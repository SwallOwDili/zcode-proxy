// L5 service — OAuth 登录管理端点逻辑（start/cookie/status/complete/callback）
#pragma once
#include <memory>
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "service/app_context.hpp"
#include "upstream/oauth.hpp"
#include "util/log.hpp"

namespace zproxy::service {

class LoginService {
public:
  explicit LoginService(AppContext& ctx)
      : ctx_(ctx), flows_(std::make_shared<upstream::oauth::FlowRegistry>()) {}

  // ---- POST /admin/login/start {name, region} ----
  nlohmann::json start(const nlohmann::json& body) {
    std::string provider = body.value("region", std::string("global")) == "cn" ? "bigmodel" : "zai";
    std::string error;
    auto f = upstream::oauth::create_flow(*flows_, ctx_.cfg.app_version, body.value("name", std::string()),
                                          provider, error);
    if (!f) return nlohmann::json{{"error", {{"message", error}}}};
    return {
      {"flowId", f->flow_id}, {"authorizeUrl", f->authorize_url},
      {"expiresAt", f->expires_at}, {"pollIntervalSec", 2},
    };
  }

  // ---- POST /admin/login/cookie {cookie, name, region} ----
  nlohmann::json cookie_login(const nlohmann::json& body) {
    std::string cookie = body.value("cookie", std::string());
    cookie = util::trim(cookie);
    if (util::starts_with(util::to_lower(cookie), "cookie:")) cookie = util::trim(cookie.substr(7));
    if (cookie.empty()) return {{"error", {{"message", "请粘贴登录站点的完整 Cookie"}}}};
    std::string provider = body.value("region", std::string("global")) == "cn" ? "bigmodel" : "zai";
    std::string error;
    auto f = upstream::oauth::create_flow(*flows_, ctx_.cfg.app_version, body.value("name", std::string()),
                                          provider, error);
    if (!f) return {{"error", {{"message", error}}}};

    // 服务端 authorize：GET authorizeUrl 带 Cookie，手动跟随 ≤8 跳直到中转页
    bool landed = false;
    std::string url = f->authorize_url;
    auto cli = upstream::make_client("https://chat.z.ai", 20, 15);
    for (int hop = 0; hop < 8 && !url.empty(); hop++) {
      httplib::Headers hh = {{"Cookie", cookie},
                             {"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"},
                             {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}};
      // authorize 页可能在 chat.z.ai 或 zcode.z.ai——按 host 重建客户端
      auto host_pos = url.find("://");
      std::string host = host_pos == std::string::npos ? "" : url.substr(host_pos + 3, url.find('/', host_pos + 3) - host_pos - 3);
      auto path_pos = url.find('/', host_pos + 3);
      std::string path = path_pos == std::string::npos ? "/" : url.substr(path_pos);
      auto res = (host.find("zcode.z.ai") != std::string::npos
                      ? upstream::make_client("https://zcode.z.ai", 20, 15)
                      : upstream::make_client("https://chat.z.ai", 20, 15))
                     .cli->Get(path, hh);
      if (!res) break;
      std::string loc = res->has_header("Location") ? res->get_header_value("Location") : "";
      util::log("cookie authorize hop " + std::to_string(hop) + ": status=" + std::to_string(res->status) +
                " loc=" + loc.substr(0, 90));
      if (res->status >= 300 && res->status < 400 && !loc.empty()) {
        if (loc.rfind("http", 0) != 0) {
          // 相对 Location
          std::string base = url.substr(0, url.find('/', url.find("://") + 3));
          url = base + (loc[0] == '/' ? loc : "/" + loc);
        } else url = loc;
        if (url.find("/app/oauth/login") != std::string::npos) { landed = true; break; }
        continue;
      }
      // 非 3xx：登录页 → Cookie 无效
      std::string text = res->body.substr(0, 4000);
      bool is_login = text.find("login") != std::string::npos || text.find("sign in") != std::string::npos ||
                      text.find("password") != std::string::npos;
      flows_->erase(f->flow_id);
      return {{"error", {{"message", is_login
                                            ? "Cookie 无效或已过期（上游返回了登录页）。请确认复制的是登录后的完整 cookie。"
                                            : "authorize 未能跳转到中转页（HTTP " + std::to_string(res->status) + "）"}}}};
    }
    if (!landed) {
      flows_->erase(f->flow_id);
      return {{"error", {{"message", "未跳转到中转页"}}}};
    }
    // 落到中转页 → 轮询确认（≤20s）
    for (int i = 0; i < 20; i++) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      auto pr = upstream::oauth::poll_flow(*f, ctx_.cfg.app_version);
      if (pr.network_error) continue;
      if (pr.upstream_code == 0 && !pr.jwt.empty() && pr.status == "ready") {
        auto user = upstream::oauth::user_info_of(pr.data);
        auto added = add_account(pr.jwt, user, f->name, f->region, f->device_mid);
        flows_->erase(f->flow_id);
        return {{"ok", true}, {"name", added["name"]}, {"profile", user}};
      }
      if (pr.upstream_code != 0 || pr.status == "failed") break;
    }
    flows_->erase(f->flow_id);
    return {{"error", {{"message", "authorize 已到中转页但 flow 未在 20s 内完成"}}}};
  }

  // ---- GET /admin/login/status?flowId= ----
  nlohmann::json status(const std::string& flow_id) {
    auto f = flows_->get(flow_id);
    if (!f) return {{"done", false}, {"error", "流程不存在或已完成"}};
    if (util::time_util::now_ms() > f->expires_at) {
      flows_->erase(flow_id);
      return {{"done", false}, {"error", "登录流程已过期，请重新发起"}};
    }
    auto pr = upstream::oauth::poll_flow(*f, ctx_.cfg.app_version);
    if (pr.network_error) return {{"done", false}, {"pending", true}};
    if (pr.http_status == 200 && pr.upstream_code == 0 && !pr.jwt.empty()) {
      auto user = upstream::oauth::user_info_of(pr.data);
      auto added = add_account(pr.jwt, user, f->name, f->region, f->device_mid);
      flows_->erase(flow_id);
      return {{"done", true}, {"name", added["name"]}, {"userId", added["userId"]}, {"profile", user}};
    }
    return {{"done", false}, {"pending", true}, {"upstreamCode", pr.upstream_code}};
  }

  // ---- POST /admin/login/complete {code | 完整 zcode:// 地址, state?, flowId?} ----
  nlohmann::json complete(const nlohmann::json& body) {
    std::string raw = util::trim(body.value("code", std::string()));
    if (raw.empty()) return {{"error", {{"message", "请粘贴完整地址或 code"}}}};
    std::string code = raw, state = util::trim(body.value("state", std::string()));
    auto extract = [&](const char* key) -> std::string {
      auto pos = raw.find(std::string(key) + "=");
      if (pos == std::string::npos) return "";
      auto rest = raw.substr(pos + strlen(key) + 1);
      auto v = rest.substr(0, rest.find('&'));
      return v;
    };
    if (auto c = extract("code"); !c.empty()) code = c;
    if (auto s = extract("state"); !s.empty() && state.empty()) state = s;
    if (code.empty()) return {{"error", {{"message", "未解析到 code"}}}};

    std::string flow_id = util::trim(body.value("flowId", std::string()));
    auto pend = flow_id.empty() ? std::nullopt : flows_->get(flow_id);

    // 没带 flowId 时做 state 归属校验（对齐 Node）
    auto all = flows_->all();
    std::vector<std::string> active_states;
    for (auto& f : all) if (!f.state.empty()) active_states.push_back(f.state);
    if (!pend && !active_states.empty()) {
      if (!state.empty() && std::find(active_states.begin(), active_states.end(), state) == active_states.end())
        return {{"error", {{"message", "这是旧登录页的回调（state 不匹配）——登录页已过期。请关闭旧标签页，重新点「打开 Z.ai 登录页」，在新页面登录后再粘贴新地址。"}}}};
      if (state.empty())
        return {{"error", {{"message", "粘贴的地址缺少 state——请复制完整地址（含 code 和 state）"}}}};
    }
    // state 依次尝试：粘贴的 → 匹配流程的 → 其余流程的 → 空
    std::vector<std::string> states;
    if (!state.empty()) states.push_back(state);
    if (pend && !pend->state.empty() && std::find(states.begin(), states.end(), pend->state) == states.end())
      states.push_back(pend->state);
    for (auto& f : all)
      if (!f.state.empty() && std::find(states.begin(), states.end(), f.state) == states.end()) states.push_back(f.state);
    if (std::find(states.begin(), states.end(), "") == states.end()) states.push_back("");

    std::string last_err = "未知错误";
    for (auto& st : states) {
      std::optional<upstream::oauth::PendingFlow> target = pend;
      if (!target) {
        for (auto& f : all)
          if (f.state == st) { target = f; break; }
      }
      std::string redirect_uri = target ? target->callback_uri : std::string(upstream::oauth::kDefaultCallback);
      auto ex = upstream::oauth::exchange_code(code, st, redirect_uri, target ? target->bearer : "",
                                               target ? target->client_id : "", target ? target->device_mid : "",
                                               ctx_.cfg.app_version);
      if (!ex.ok) {
        last_err = (ex.resp.is_object() ? ex.resp.value("msg", std::string("code ?")) : "code ?") +
                   std::string("（bearer=") + (ex.with_bearer ? "yes" : "no") + "）";
        continue;
      }
      auto user = upstream::oauth::user_info_of(ex.resp.is_object() && ex.resp.contains("data")
                                                    ? ex.resp["data"] : nlohmann::json::object());
      auto added = add_account(ex.jwt, user, target ? target->name : std::string(),
                               target ? target->region : "global", "");
      // 成功：清空所有 pending
      for (auto& f : flows_->all()) flows_->erase(f.flow_id);
      return {{"ok", true}, {"name", added["name"]}, {"profile", user}};
    }
    return {{"error", {{"message", "交换失败：" + last_err}}}};
  }

  // ---- GET /admin/oauth/callback?code=&state= ----
  std::string callback(const std::string& code, const std::string& state, bool& ok) {
    auto result = complete({{"code", code}, {"state", state}});
    ok = result.value("ok", false);
    std::string msg = ok ? ("登录成功：账号「" + result.value("name", std::string("")) + "」已加入账号池。")
                         : ("登录失败：" + result["error"]["message"].get<std::string>());
    std::string safe;
    for (char c : msg) {
      switch (c) {
        case '<': safe += "&lt;"; break;
        case '>': safe += "&gt;"; break;
        case '&': safe += "&amp;"; break;
        case '"': safe += "&quot;"; break;
        default: safe += c;
      }
    }
    return "<!doctype html><meta charset=utf-8><title>zcode-proxy oauth</title>"
           "<body style=\"font-family:-apple-system,sans-serif;padding:40px\"><h2>" +
           safe + "</h2><p>可以关闭此页面。</p></body>";
  }

  nlohmann::json debug() { return flows_->debug_json(); }

private:
  // addAccountFromToken 等价（去重：同 jwt/同 userId 原地更新）
  nlohmann::json add_account(const std::string& jwt, const nlohmann::json& user, const std::string& preferred,
                             const std::string& region, const std::string& flow_device_mid) {
    domain::Account acc;
    acc.jwt = jwt;
    acc.region = region == "cn" ? "cn" : "global";
    if (!flow_device_mid.empty()) acc.device_mid = flow_device_mid; // 新设备指纹（登录流程生成）
    if (!user.is_null() && user.is_object()) {
      acc.user_info.present = true;
      acc.user_info.name = user.value("name", "");
      acc.user_info.email = user.value("email", "");
      acc.user_info.avatar = user.value("avatar", "");
      acc.user_info.user_id = user.value("userId", "");
    }
    std::string name = preferred.empty() ? (acc.user_info.name.empty() ? std::string() : acc.user_info.name) : preferred;
    acc.name = name;
    ctx_.pool.upsert(std::move(acc), "", /*adopt_runtime=*/flow_device_mid.empty());
    auto uid = domain::account_user_id_of(jwt);
    util::log("admin: account added/refreshed -> " + (name.empty() ? "user-" + uid.substr(0, 8) : name));
    return {{"name", name}, {"userId", uid}};
  }

  AppContext& ctx_;
  std::shared_ptr<upstream::oauth::FlowRegistry> flows_;
};

} // namespace zproxy::service
