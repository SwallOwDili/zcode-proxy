// L4 upstream — OAuth 登录流：cli/init、cli/poll、code 交换、Cookie authorize
// 逆向要点（对齐 Node）：
//   - redirect_uri 用白名单中转页 https://zcode.z.ai/app/oauth/login?redirect=zcode://oauth/callback&app_version=<ver>
//   - 登录完成后 flow 服务端标记 ready，token 直接从 cli/poll 返回（多数路径无需 code 交换）
//   - 每个登录流程强制全新 deviceMid（新"设备"，防多账号关联风控）
#pragma once
#include <algorithm>
#include <cctype>
#include <map>
#include <mutex>
#include "nlohmann/json.hpp"
#include "upstream/http.hpp"
#include "util/uuid.hpp"

namespace zproxy::upstream::oauth {

static const char* kOauthBase = "https://zcode.z.ai";
static const char* kDefaultCallback = "zcode://oauth/callback";

// pending 流程（内存态）
struct PendingFlow {
  std::string flow_id;
  std::string bearer;      // 32 字节 hex，流程属主
  std::string name;
  std::string region;      // global | cn
  int64_t expires_at = 0;  // ms
  std::string authorize_url;
  std::string callback_uri;
  std::string state;
  std::string client_id;
  std::string device_mid;
};

class FlowRegistry {
public:
  void put(const PendingFlow& f) {
    std::lock_guard<std::mutex> lk(mu_);
    flows_[f.flow_id] = f;
  }
  std::optional<PendingFlow> get(const std::string& flow_id) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = flows_.find(flow_id);
    if (it == flows_.end()) return std::nullopt;
    return it->second;
  }
  void erase(const std::string& flow_id) {
    std::lock_guard<std::mutex> lk(mu_);
    flows_.erase(flow_id);
  }
  std::vector<PendingFlow> all() {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<PendingFlow> out;
    for (auto& [k, v] : flows_) out.push_back(v);
    return out;
  }
  // 兼容 Node 调试输出里的脱敏展示
  nlohmann::json debug_json() {
    std::lock_guard<std::mutex> lk(mu_);
    nlohmann::json arr = nlohmann::json::array();
    for (auto& [id, f] : flows_) {
      arr.push_back({{"flowId", id},
                     {"name", f.name},
                     {"region", f.region},
                     {"state", f.state.substr(0, 10)},
                     {"expiresIn", (int64_t)std::max((int64_t)0, (f.expires_at - util::time_util::now_ms()) / 1000)},
                     {"deviceMid", f.device_mid}});
    }
    return arr;
  }

private:
  std::mutex mu_;
  std::map<std::string, PendingFlow> flows_;
};

// withZcodeEndpointHeaders(caller, deviceMid) 等价：zcodeSourceHeaders 打底 + caller 覆盖
inline Headers with_zc_headers(const Headers& caller, const std::string& jwt, const std::string& device_mid,
                               const std::string& app_version) {
  Headers out = zcode_source_headers(jwt, device_mid, app_version); // jwt 仅用于占位，这里不注入鉴权
  // zcode_source_headers 里没有 authorization；caller 里的 authorization 直接进合并
  for (auto& [k, v] : caller) {
    bool merged = false;
    for (auto& [ok, ov] : out) {
      if (util::iequals(ok, k)) { ov = v; merged = true; break; } // caller 显式值覆盖（对齐 spread 语义）
    }
    if (!merged) out.emplace_back(k, v);
  }
  return out;
}

inline std::string url_encode(const std::string& s) {
  static const char* hex = "0123456789ABCDEF";
  std::string out;
  for (unsigned char c : s) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out += (char)c;
    else { out += '%'; out += hex[c >> 4]; out += hex[c & 15]; }
  }
  return out;
}
inline std::string join(const std::vector<std::string>& v, const std::string& sep) {
  std::string out;
  for (size_t i = 0; i < v.size(); i++) { if (i) out += sep; out += v[i]; }
  return out;
}

// 发起登录流程 → PendingFlow（失败返回 nullopt 并填 error）
inline std::optional<PendingFlow> create_flow(FlowRegistry& reg, const std::string& app_version,
                                              const std::string& name, const std::string& provider,
                                              std::string& error) {
  std::string bearer = util::random_hex(32);
  std::string flow_device_mid = util::uuid();
  Headers caller = {
    {"authorization", "Bearer " + bearer},
    {"content-type", "application/json"},
    {"X-Device-Mid", flow_device_mid},
  };
  Headers h = with_zc_headers(caller, "", flow_device_mid, app_version);
  auto res = http::post_json(kOauthBase, "/api/v1/oauth/cli/init", h, nlohmann::json{{"provider", provider}}.dump(), 30);
  nlohmann::json j;
  try { j = nlohmann::json::parse(res.body); } catch (...) { j = nullptr; }
  if (!j.is_object() || j.value("code", -1) != 0 || !j.contains("data") ||
      !j["data"].contains("flow_id") || !j["data"].contains("authorize_url")) {
    error = "登录初始化失败: " + (j.is_object() ? j.value("msg", std::string("HTTP ")) : std::string("HTTP ")) +
            std::to_string(res.status);
    return std::nullopt;
  }
  const auto& d = j["data"];
  std::string authorize_url = d.value("authorize_url", "");
  std::string callback_uri = std::string(kOauthBase) + "/app/oauth/login?redirect=" +
                             kDefaultCallback + "&app_version=" + app_version;
  // authorize_url 改写 redirect 参数（bigmodel 用 redirect，zai 用 redirect_uri）
  std::string state;
  {
    auto qpos = authorize_url.find('?');
    if (qpos != std::string::npos) {
      std::string query = authorize_url.substr(qpos + 1);
      std::vector<std::string> keep;
      bool has_state = false;
      for (auto& kv : util::split(query, '&')) {
        auto eq = kv.find('=');
        std::string k = eq == std::string::npos ? kv : kv.substr(0, eq);
        std::string v = eq == std::string::npos ? "" : kv.substr(eq + 1);
        if (k == "redirect" || k == "redirect_uri") continue;
        if (k == "state") { state = v; has_state = true; }
        keep.push_back(kv);
      }
      keep.push_back(std::string(provider == "bigmodel" ? "redirect" : "redirect_uri") + "=" +
                     url_encode(callback_uri));
      authorize_url = authorize_url.substr(0, qpos + 1) + join(keep, "&");
      if (!has_state) {
        // state 可能编码在原 query 中未取到——补一次宽松提取
        auto sm = state.empty() ? authorize_url.find("state=") : std::string::npos;
        if (sm != std::string::npos) {
          auto rest = authorize_url.substr(sm + 6);
          state = rest.substr(0, rest.find('&'));
        }
      }
    }
  }
  // client_id 从 authorize_url 提取
  std::string client_id;
  {
    auto cm = authorize_url.find("client_id=");
    if (cm != std::string::npos) {
      auto rest = authorize_url.substr(cm + 10);
      client_id = rest.substr(0, rest.find('&'));
    }
  }
  PendingFlow f;
  f.flow_id = d.value("flow_id", "");
  f.bearer = bearer;
  f.name = name;
  f.region = provider == "bigmodel" ? "cn" : "global";
  f.expires_at = (int64_t)d.value("expires_at", (double)0) * 1000;
  f.authorize_url = authorize_url;
  f.callback_uri = callback_uri;
  f.state = state;
  f.client_id = client_id;
  f.device_mid = flow_device_mid;
  reg.put(f);
  return f;
}

// poll 一次：返回 {done, jwt, user_json, upstream_code}
struct PollResult {
  bool network_error = false;
  int http_status = 0;
  int64_t upstream_code = 0;
  std::string status; // ready / pending / failed
  std::string jwt;
  nlohmann::json data; // 完整 data 对象
};
inline PollResult poll_flow(const PendingFlow& f, const std::string& app_version) {
  PollResult out;
  Headers h = with_zc_headers({{"authorization", "Bearer " + f.bearer}}, "", f.device_mid, app_version);
  auto res = http::get_json(kOauthBase, "/api/v1/oauth/cli/poll/" + f.flow_id, h, 20);
  if (!res.ok()) { out.network_error = true; return out; }
  out.http_status = res.status;
  nlohmann::json j;
  try { j = nlohmann::json::parse(res.body); } catch (...) { return out; }
  if (!j.is_object()) return out;
  out.upstream_code = j.value("code", (int64_t)-1);
  const auto& d = j.contains("data") && j["data"].is_object() ? j["data"] : nlohmann::json::object();
  out.data = d;
  out.status = d.value("status", "");
  std::string jwt;
  for (const char* key : {"token", "zcode_jwt_token", "zcodeJwtToken", "access_token"}) {
    if (d.contains(key) && d[key].is_string()) { jwt = d[key].get<std::string>(); break; }
  }
  if (jwt.empty() && d.contains("zai") && d["zai"].is_object()) jwt = d["zai"].value("access_token", "");
  if (jwt.empty() && d.contains("bigmodel") && d["bigmodel"].is_object()) jwt = d["bigmodel"].value("access_token", "");
  out.jwt = util::trim(jwt);
  return out;
}

// code 换 jwt（先带流程 bearer 再裸试；2007 换鉴权重试——对齐 exchangeOAuthCode）
struct ExchangeResult {
  bool ok = false;
  std::string jwt;
  nlohmann::json resp;
  bool with_bearer = false;
};
inline ExchangeResult exchange_code(const std::string& code, const std::string& state,
                                    const std::string& redirect_uri, const std::string& bearer,
                                    const std::string& client_id, const std::string& device_mid,
                                    const std::string& app_version) {
  ExchangeResult out;
  nlohmann::json body = {{"provider", "zai"}, {"code", code}, {"redirect_uri", redirect_uri}, {"state", state}};
  if (!client_id.empty()) body["client_id"] = client_id;
  for (int attempt = 0; attempt < 2; attempt++) {
    bool use_bearer = attempt == 0 && !bearer.empty();
    Headers caller = {{"content-type", "application/json"}};
    if (use_bearer) caller.emplace_back("authorization", "Bearer " + bearer);
    if (!device_mid.empty()) caller.emplace_back("X-Device-Mid", device_mid);
    Headers h = with_zc_headers(caller, "", device_mid, app_version);
    auto res = http::post_json(kOauthBase, "/api/v1/oauth/token", h, body.dump(), 30);
    nlohmann::json j;
    try { j = nlohmann::json::parse(res.body); } catch (...) { j = nullptr; }
    out.resp = j;
    out.with_bearer = use_bearer;
    if (!j.is_object()) continue;
    const auto& d = j.contains("data") && j["data"].is_object() ? j["data"] : nlohmann::json::object();
    std::string jwt;
    for (const char* key : {"token", "zcode_jwt_token", "access_token"}) {
      if (d.contains(key) && d[key].is_string()) { jwt = d[key].get<std::string>(); break; }
    }
    if (jwt.empty() && d.contains("zai") && d["zai"].is_object()) jwt = d["zai"].value("access_token", "");
    jwt = util::trim(jwt);
    if (j.value("code", -1) == 0 && !jwt.empty()) {
      out.ok = true;
      out.jwt = jwt;
      return out;
    }
    if (j.value("code", -1) != 2007) break;
  }
  return out;
}

// data.user → userInfo（对齐 Node 提取链）
inline nlohmann::json user_info_of(const nlohmann::json& d) {
  const auto& u = d.contains("user") && d["user"].is_object() ? d["user"] : nlohmann::json::object();
  if (u.empty()) return nullptr;
  std::string uid;
  for (const char* k : {"userId", "user_id", "sub"}) {
    if (u.contains(k) && u[k].is_string()) { uid = u[k].get<std::string>(); break; }
  }
  return {
    {"name", u.contains("name") ? u["name"] : (u.contains("nickname") ? u["nickname"] : (u.contains("displayName") ? u["displayName"] : nlohmann::json(nullptr)))},
    {"email", u.contains("email") ? u["email"] : nlohmann::json(nullptr)},
    {"avatar", u.contains("avatar") ? u["avatar"] : (u.contains("picture") ? u["picture"] : nlohmann::json(nullptr))},
    {"userId", uid},
  };
}

} // namespace zproxy::upstream::oauth
