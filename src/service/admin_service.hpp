// L5 service — /admin/* API
// Phase 1：本地状态端点（summary/routing/modelmap/pricing/usage/tps/recent/accounts CRUD/pause）
// Phase 2/3：dashboard、plan、pool-balance、claim、OAuth 登录流、audit、referral（标记 501）
#pragma once
#include <algorithm>
#include <chrono>
#include <map>
#include <set>
#include "httplib.h"
#include "transport/http_server.hpp"
#include "service/claim_service.hpp"
#include "service/login_service.hpp"
#include "upstream/billing.hpp"
#include "upstream/marketing.hpp"
#include "nlohmann/json.hpp"
#include "service/app_context.hpp"
#include "util/log.hpp"
#include "util/time_util.hpp"
#include "util/uuid.hpp"

namespace zproxy::service {

class AdminService {
public:
  explicit AdminService(AppContext& ctx) : ctx_(ctx), claim_(ctx, ctx.claim), login_(ctx) {}

  void setup(http::HttpServer& svr) {
    // 同步 handler 统一投线程池执行：admin 端点内部有大量阻塞上游调用
    // （audit 几十秒、test 最多 600s、referral curl 25s、plan/balance 秒级）——
    // 直接跑在事件循环线程上会卡死整个服务（WorkBuddy 卡死同款架构缺陷）
    auto H = [](auto fn) {
      return [fn](http::Ctx& c) -> asio::awaitable<void> {
        try { co_await http::run_blocking([&] { fn(c); }); }
        catch (const std::exception& e) {
          c.set_status(500);
          c.set_content(nlohmann::json({{"error", {{"message", e.what()}}}}).dump(), "application/json");
        }
        co_return;
      };
    };
    auto REG = [&svr](const char* m, const char* re, auto h) {
      svr.route(m, std::string("^") + re + "$", h);
    };

    // 注入提示词编辑（块边界保持：WAF 要求前两块结构）
    REG("GET", "/admin/sysprompt", H([this](http::Ctx& c) {
      auto blocks = ctx_.sys.effective_blocks();
      nlohmann::json arr = nlohmann::json::array();
      for (auto& b : blocks) arr.push_back(b);
      c.set_json({{"blocks", arr}, {"overridden", ctx_.sys.has_override()}});
    }));
    REG("PUT", "/admin/sysprompt", H([this](http::Ctx& c) {
      auto body = parse(c);
      std::vector<nlohmann::json> blocks;
      if (body.contains("blocks") && body["blocks"].is_array())
        for (auto& b : body["blocks"])
          if (b.is_object() && b.value("type", "") == "text" && b.contains("text") && b["text"].is_string())
            blocks.push_back({{"type", "text"}, {"text", b["text"]}});
      if (blocks.empty()) {
        // 空 = 清除 override，恢复自动提取
        util::fs::write_file(ctx_.cfg.state_dir + "/sysprompt-edit.json", "[]\n");
        ctx_.sys.load_override();
        c.set_json({{"ok", true}, {"overridden", false}});
        return;
      }
      if (blocks.size() < 2) {
        c.set_status(400);
        c.set_content(err("至少需要 2 个文本块（身份块 + 主段），WAF 校验块结构").dump(), "application/json");
        return;
      }
      ctx_.sys.set_override(std::move(blocks));
      c.set_json({{"ok", true}, {"overridden", true}});
    }));

    REG("GET", "/admin/summary", H([this](http::Ctx& c) { summary(c); }));
    REG("GET", "/admin/routing", H([this](http::Ctx& c) {
      c.set_content(nlohmann::json{{"mode", ctx_.routing.mode()},
                                     {"affinitySessions", ctx_.pool.affinity_size()},
                                     {"windowMs", 30000}}
                          .dump(), "application/json");
    }));
    REG("PUT", "/admin/routing", H([this](http::Ctx& c) {
      auto body = parse(c);
      std::string mode = body.value("mode", "");
      if (!ctx_.routing.set_mode(mode)) {
        c.set_status(400);
        c.set_content(err("mode must be tps or cache").dump(), "application/json");
        return;
      }
      c.set_content(nlohmann::json{{"ok", true}, {"mode", mode}}.dump(), "application/json");
    }));

    REG("GET", "/admin/modelmap", H([this](http::Ctx& c) {
      nlohmann::json mm = nlohmann::json::object();
      for (auto& [k, v] : ctx_.modelmap.effective()) mm[k] = v;
      c.set_content(nlohmann::json{{"map", mm}, {"defaultModel", ctx_.cfg.default_model}}.dump(),
                      "application/json");
    }));
    REG("PUT", "/admin/modelmap", H([this](http::Ctx& c) {
      auto body = parse(c);
      std::map<std::string, std::optional<std::string>> m;
      if (body.contains("map") && body["map"].is_object()) {
        for (auto& [k, v] : body["map"].items()) {
          if (v.is_null()) m[k] = std::nullopt;
          else if (v.is_string()) m[k] = v.get<std::string>();
        }
      }
      ctx_.modelmap.save_map(m);
      c.set_content(nlohmann::json{{"ok", true}}.dump(), "application/json");
    }));

    REG("GET", "/admin/pricing", H([this](http::Ctx& c) {
      nlohmann::json prices = nlohmann::json::object(), defaults = nlohmann::json::object();
      for (auto& [k, v] : ctx_.pricing.prices()) prices[k] = {{"in", v.in}, {"out", v.out}};
      for (auto& [k, v] : store::PricingStore::defaults()) defaults[k] = {{"in", v.in}, {"out", v.out}};
      c.set_content(nlohmann::json{{"prices", prices}, {"defaults", defaults}}.dump(), "application/json");
    }));
    REG("PUT", "/admin/pricing", H([this](http::Ctx& c) {
      auto body = parse(c);
      std::map<std::string, store::Price> m;
      if (body.contains("prices") && body["prices"].is_object()) {
        for (auto& [k, v] : body["prices"].items()) {
          if (v.is_object() && v.contains("in") && v.contains("out"))
            m[k] = store::Price{v["in"].get<double>(), v["out"].get<double>()};
        }
      }
      ctx_.pricing.save_file_prices(m);
      c.set_content(nlohmann::json{{"ok", true}}.dump(), "application/json");
    }));

    REG("GET", "/admin/usage", H([this](http::Ctx& c) {
      int want = 7;
      if (c.has_query("days")) { try { want = std::clamp(std::stoi(c.get_query("days")), 1, 30); } catch (...) {} }
      // Node 语义：days = 排序日期数组（前端 meta.days.slice），data 仅含选中的天。
      // snapshot() 返回 {日期: cells}（无 days 外壳）
      auto all = ctx_.usage.snapshot(30);
      std::vector<std::string> keys;
      for (auto& [k, v] : all.items()) keys.push_back(k);
      std::sort(keys.begin(), keys.end());
      if ((int)keys.size() > want) keys.erase(keys.begin(), keys.end() - want);
      nlohmann::json arr = nlohmann::json::array();
      nlohmann::json data = nlohmann::json::object();
      for (auto& k : keys) { arr.push_back(k); data[k] = all[k]; }
      nlohmann::json prices = nlohmann::json::object();
      for (auto& [k, v] : ctx_.pricing.prices()) prices[k] = {{"in", v.in}, {"out", v.out}};
      c.set_content(nlohmann::json{{"days", arr}, {"prices", prices}, {"data", data}}.dump(),
                      "application/json");
    }));

    REG("GET", "/admin/tps", H([this](http::Ctx& c) {
      c.set_content(ctx_.tps.stats().dump(), "application/json");
    }));
    REG("GET", "/admin/recent", H([this](http::Ctx& c) {
      c.set_content(ctx_.recent.to_json().dump(), "application/json");
    }));

    // ---- 账号 CRUD ----
    REG("GET", "/admin/accounts", H([this](http::Ctx& c) {
      auto accs = ctx_.pool.accounts();
      auto paused = ctx_.paused.paused();
      nlohmann::json list = nlohmann::json::array();
      for (auto& a : accs) {
        nlohmann::json j = {{"name", a.name}, {"jwt", a.jwt}, {"region", a.region},
                            {"status", ctx_.pool.cooldown_desc(a)},
                            {"paused", paused.count(a.name) > 0}};
        if (!a.user_info.user_id.empty()) j["userId"] = a.user_info.user_id;
        if (a.user_info.present) {
          j["profile"] = {{"name", a.user_info.name}, {"email", a.user_info.email},
                          {"avatar", a.user_info.avatar}};
        }
        list.push_back(std::move(j));
      }
      c.set_content(nlohmann::json{{"source", ctx_.pool.source()}, {"accounts", list}}.dump(),
                      "application/json");
    }));
    REG("POST", "/admin/accounts", H([this](http::Ctx& c) {
      auto body = parse(c);
      std::string jwt = body.value("jwt", "");
      if (jwt.empty()) {
        c.set_status(400);
        c.set_content(err("jwt required").dump(), "application/json");
        return;
      }
      domain::Account a;
      a.name = body.value("name", std::string());
      a.jwt = jwt;
      a.region = body.value("region", std::string("global"));
      if (body.contains("userInfo") && body["userInfo"].is_object()) {
        a.user_info.present = true;
        a.user_info.name = body["userInfo"].value("name", "");
        a.user_info.email = body["userInfo"].value("email", "");
        a.user_info.avatar = body["userInfo"].value("avatar", "");
        a.user_info.user_id = body["userInfo"].value("userId", "");
      }
      ctx_.pool.upsert(std::move(a));
      c.set_content(nlohmann::json{{"ok", true}}.dump(), "application/json");
    }));
    REG("PUT", R"(/admin/accounts/([^/]+))", H([this](http::Ctx& c) {
      std::string name = c.params[0];
      auto body = parse(c);
      auto accs = ctx_.pool.accounts();
      domain::Account* found = nullptr;
      for (auto& a : accs) if (a.name == name) found = &a;
      if (!found) {
        c.set_status(404);
        c.set_content(err("no such account").dump(), "application/json");
        return;
      }
      domain::Account next = *found;
      if (body.contains("name") && body["name"].is_string()) next.name = body["name"];
      if (body.contains("jwt") && body["jwt"].is_string()) next.jwt = body["jwt"];
      if (body.contains("region") && body["region"].is_string()) next.region = body["region"];
      if (next.name != name) {
        // 改名：先删后加
        domain::Account moved = next;
        ctx_.pool.remove(name);
        ctx_.pool.upsert(std::move(moved), name);
      } else {
        ctx_.pool.upsert(std::move(next), name);
      }
      c.set_content(nlohmann::json{{"ok", true}}.dump(), "application/json");
    }));
    REG("DELETE", R"(/admin/accounts/([^/]+))", H([this](http::Ctx& c) {
      std::string name = c.params[0];
      auto accs = ctx_.pool.accounts();
      bool last = accs.size() == 1 && accs[0].name == name;
      if (!ctx_.pool.remove(name)) {
        c.set_status(404);
        c.set_content(err("no such account").dump(), "application/json");
        return;
      }
      nlohmann::json out = {{"ok", true}};
      if (last) out["note"] = "last account removed";
      c.set_content(out.dump(), "application/json");
    }));
    REG("PUT", R"(/admin/accounts/([^/]+)/pause)", H([this](http::Ctx& c) {
      std::string name = c.params[0];
      auto body = parse(c);
      bool paused = body.value("paused", false);
      auto cur = ctx_.paused.paused();
      if (paused) cur.insert(name); else cur.erase(name);
      ctx_.paused.set_paused(cur);
      c.set_content(nlohmann::json{{"ok", true}, {"paused", paused}}.dump(), "application/json");
    }));

    // ---- dashboard：今日用量 + tps + 24h 直方图 ----
    REG("GET", "/admin/dashboard", H([this](http::Ctx& c) { dashboard(c); }));

    // ---- pool-balance：全池额度（5min 缓存）----
    REG("GET", "/admin/pool-balance", H([this](http::Ctx& c) {
      bool force = c.has_query("refresh") && c.get_query("refresh") == "1";
      c.set_content(pool_balance(force).dump(), "application/json");
    }));

    // ---- 账号级 plan / test ----
    REG("GET", R"(/admin/accounts/([^/]+)/plan)", H([this](http::Ctx& c) {
      std::string name = c.params[0];
      bool force = c.has_query("refresh") && c.get_query("refresh") == "1";
      auto acc = ctx_.pool.get(name);
      if (!acc) {
        c.set_status(404);
        c.set_content(err("no such account").dump(), "application/json");
        return;
      }
      std::string jwt = acc->jwt;
      std::string device_mid = acc->device_mid.empty() ? util::uuid() : acc->device_mid;
      nlohmann::json out;
      int64_t now = util::time_util::now_ms();
      auto& entry = plan_cache_[name];
      if (!force && !entry.data.is_null() && now - entry.at < 60'000) {
        out = entry.data;
        out["cached"] = true;
        out["cacheAgeMs"] = now - entry.at;
      } else {
        auto raw = upstream::fetch_balance_raw(jwt, device_mid, ctx_.cfg.app_version);
        nlohmann::json plans = nlohmann::json::array(), balances = nlohmann::json::array();
        if (raw.ok() && upstream::parse_balance(raw.body, plans, balances)) {
          // 回写模型剩余额度到池（pick 用它跳过已耗尽的模型）
          for (auto& b : balances)
            ctx_.pool.set_model_remaining(name, b.value("name", ""), b.value("remaining", (int64_t)0));
          out = {{"plans", plans}, {"balances", balances}, {"fetchedAt", now}, {"cached", false}};
          entry = {out, now};
        } else {
          c.set_status(502);
          c.set_content(err("balance fetch failed: " + (raw.error.empty() ? raw.body.substr(0, 200) : raw.error)).dump(),
                          "application/json");
          return;
        }
      }
      c.set_content(out.dump(), "application/json");
    }));
    REG("POST", R"(/admin/accounts/([^/]+)/test)", H([this](http::Ctx& c) {
      std::string name = c.params[0];
      auto lease = ctx_.pool.lease(name);
      if (!lease.valid) {
        c.set_status(404);
        c.set_content(err("no such account").dump(), "application/json");
        return;
      }
      // lease 已挂在途计数；test 结束统一 release
      nlohmann::json body = {
        {"model", ctx_.cfg.default_model},
        {"max_tokens", 16},
        {"messages", nlohmann::json::array({{{"role", "user"}, {"content", "hi"}}})},
      };
      auto t0 = std::chrono::steady_clock::now();
      auto call = ctx_.client.call(body, "", "", nullptr);
      int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
      ctx_.pool.release(name);
      bool ok = call.status >= 200 && call.status < 300;
      if (call.status == 401) ctx_.pool.mark_cooldown(name, ctx_.cfg.cooldown_401_ms);
      if (call.status == 429) ctx_.pool.mark_cooldown(name, ctx_.cfg.cooldown_429_ms, ctx_.cfg.default_model);
      domain::RecentEntry e; e.kind = "test"; e.model = ctx_.cfg.default_model; e.account = name;
      e.status = call.status; e.ms = ms;
      ctx_.record(e);
      nlohmann::json out = {{"ok", ok}, {"status", call.status}, {"ms", ms}};
      if (!call.body.empty()) out["body"] = call.body.substr(0, 300);
      c.set_content(out.dump(), "application/json");
    }));

    // ---- claim / audit / complete-login ----
    REG("GET", "/admin/claim/status", H([this](http::Ctx& c) {
      c.set_content(claim_.status_json().dump(), "application/json");
    }));
    REG("POST", "/admin/claim/run", H([this](http::Ctx& c) {
      auto body = parse(c);
      bool force = body.value("force", false);
      if (!claim_.try_start_cycle(force)) {
        c.set_content(nlohmann::json{{"started", false}, {"message", "领取周期已在运行中"}}.dump(),
                        "application/json");
        return;
      }
      c.set_content(nlohmann::json{{"started", true}}.dump(), "application/json");
    }));
    REG("POST", "/admin/claim/retry-blocked", H([this](http::Ctx& c) {
      c.set_content(claim_.retry_blocked().dump(), "application/json");
    }));
    REG("GET", "/admin/audit", H([this](http::Ctx& c) {
      auto rows = claim_.audit();
      c.set_content(rows.dump(), "application/json");
    }));
    REG("POST", R"(/admin/accounts/([^/]+)/complete-login)", H([this](http::Ctx& c) {
      std::string name = c.params[0];
      auto acc = ctx_.pool.get(name);
      if (!acc) {
        c.set_status(404);
        c.set_content(err("no such account").dump(), "application/json");
        return;
      }
      std::string jwt = acc->jwt;
      std::string dm = acc->device_mid.empty() ? util::uuid() : acc->device_mid;
      auto results = claim_.complete_login_device(jwt, dm, ctx_.cfg.app_version, acc->region);
      c.set_content(nlohmann::json{{"name", name}, {"results", results}}.dump(), "application/json");
    }));

    // ---- referral ----
    REG("GET", R"(/admin/accounts/([^/]+)/referral)", H([this](http::Ctx& c) {
      std::string name = c.params[0];
      auto acc = ctx_.pool.get(name);
      if (!acc) {
        c.set_status(404);
        c.set_content(err("no such account").dump(), "application/json");
        return;
      }
      // Node 语义：referralCache 命中立即返回，过期后台静默刷新（页面永不阻塞上游）
      constexpr int64_t kRefTtlMs = 5 * 60'000;
      int64_t now = util::time_util::now_ms();
      nlohmann::json cached;
      {
        std::lock_guard<std::mutex> lk(ref_mu_);
        auto it = ref_cache_.find(acc->jwt);
        if (it != ref_cache_.end()) {
          cached = it->second.data;
          if (now - it->second.at <= kRefTtlMs) {
            c.set_content(cached.dump(), "application/json");
            return;
          }
        }
      }
      // 无缓存：同步拉一次并入缓存；有旧缓存：后台刷新
      auto fetch_and_store = [this, jwt = acc->jwt, dm = (acc->device_mid.empty() ? util::uuid() : acc->device_mid)] {
        bool ok = false;
        std::string error;
        auto data = upstream::fetch_referral(jwt, dm, ctx_.cfg.app_version, ok, error);
        if (ok) {
          std::lock_guard<std::mutex> lk(ref_mu_);
          ref_cache_[jwt] = {data, util::time_util::now_ms()};
        }
      };
      if (!cached.is_null()) {
        std::thread([fetch_and_store] { fetch_and_store(); }).detach();
        c.set_content(cached.dump(), "application/json");
        return;
      }
      fetch_and_store();
      std::lock_guard<std::mutex> lk(ref_mu_);
      auto it = ref_cache_.find(acc->jwt);
      if (it == ref_cache_.end()) {
        c.set_status(502);
        c.set_content(err("referral fetch failed").dump(), "application/json");
        return;
      }
      c.set_content(it->second.data.dump(), "application/json");
    }));
    REG("POST", R"(/admin/accounts/([^/]+)/bind-referral)", H([this](http::Ctx& c) {
      std::string name = c.params[0];
      auto body = parse(c);
      auto acc = ctx_.pool.get(name);
      if (!acc) {
        c.set_status(404);
        c.set_content(err("no such account").dump(), "application/json");
        return;
      }
      std::string jwt = acc->jwt;
      std::string dm = acc->device_mid.empty() ? util::uuid() : acc->device_mid;
      std::string code = util::trim(body.value("invite_code", body.value("code", std::string())));
      if (code.empty()) {
        c.set_status(400);
        c.set_content(err("缺少邀请码").dump(), "application/json");
        return;
      }
      // 同账号绑定限速：SDK 重触发/重复提交不许连环打上游（每次都是真上游调用）
      {
        std::lock_guard<std::mutex> lk(bind_rate_mu_);
        int64_t now = util::time_util::now_ms();
        auto& last = bind_last_attempt_[name];
        if (now - last < 10'000) {
          c.set_status(429);
          c.set_content(err("绑定请求过于频繁，请 10 秒后再试").dump(), "application/json");
          return;
        }
        last = now;
      }
      std::string cap = util::trim(body.value("captchaVerifyParam", std::string()));
      std::string cap_region = util::trim(body.value("captcha_region", std::string("sgp")));
      // 头集合对齐 fetch_referral/claim（同一上游风控域实测可过的组合），再叠加 captcha 两头
      upstream::Headers h = upstream::claim_headers(jwt, dm, ctx_.cfg.app_version);
      h.emplace_back("Accept", "application/json");
      h.emplace_back("X-Aliyun-Captcha-Verify-Region", cap_region);
      if (!cap.empty()) h.emplace_back("X-Aliyun-Captcha-Verify-Param", cap);
      auto raw = upstream::curl_post_raw("https://zcode.z.ai/api/v1/incentive/referral/bind-code", h,
                                         {{"invite_code", code}});
      nlohmann::json out = nullptr;
      try { out = nlohmann::json::parse(raw.body); } catch (...) {}
      int64_t bcode = out.is_object() ? out.value("code", (int64_t)-1) : -1;
      if (bcode == 0) {
        c.set_content(nlohmann::json{{"ok", true}, {"name", name}, {"code", code}}.dump(), "application/json");
        return;
      }
      // 失败必须留痕：超时/非 JSON/上游 msg 原文都进日志（此前只剩泛化「绑定失败」无从排查）
      std::string raw_snip = raw.body.substr(0, 500);
      util::log("bind-referral " + name + " invite=" + code + " bcode=" + std::to_string(bcode) +
                (raw.timed_out ? " timed_out" : "") + (raw.spawn_failed ? " spawn_failed" : "") +
                " curl_exit=" + std::to_string(raw.exit_code) + " body=" + raw_snip);
      // 错误文案对齐官网 invite 页（3006 旧映射是错的：官方「资格窗口」是 3507，3007=验证未通过）
      static const std::map<int64_t, std::string> kBindMsgs = {
          {401, "登录已失效，请重新登录该账号"}, {1006, "登录已失效，请重新登录该账号"},
          {3007, "安全验证未通过，请刷新页面重试"},
          {3501, "邀请活动暂未开放"}, {3502, "当前账号不符合参与条件"},
          {3503, "邀请链接无效，请向好友获取新的链接"}, {3504, "不能接受自己的邀请"},
          {3505, "已绑定过邀请，无法重复接受"}, {3506, "邀请人暂未获得邀请资格"},
          {3507, "已超过新用户参与时限，无法接受邀请"},
      };
      auto it_msg = kBindMsgs.find(bcode);
      std::string msg = it_msg != kBindMsgs.end() ? it_msg->second
                      : raw.timed_out ? "上游超时（20s 无响应）"
                      : raw.spawn_failed ? "curl 启动失败"
                      : out.is_object()
                          ? "上游拒绝 code=" + std::to_string(bcode) + ": " + out.value("msg", std::string())
                      : !raw.body.empty() ? "上游非 JSON 响应: " + raw_snip
                                          : "上游无响应（curl exit " + std::to_string(raw.exit_code) + "）";
      c.set_content(nlohmann::json{{"ok", false}, {"code", bcode}, {"message", msg}, {"captcha", bcode == 3007}}.dump(),
                      "application/json");
    }));

    // 官方 captcha 配置实时代理（region 会变：cn→sgp 曾导致绑定全部 3007）；失败兜底最近已知值
    REG("GET", "/admin/captcha-config", H([this](http::Ctx& c) {
      nlohmann::json fallback = {{"enabled", true}, {"prefix", "no8xfe"}, {"region", "sgp"},
                                 {"sceneId", "11xygtvd"}, {"skip_model_request", true}};
      auto res = upstream::http::get_json("https://zcode.z.ai", "/api/v1/client/configs",
                                {{"User-Agent", "ZCode/" + ctx_.cfg.app_version}}, 10);
      nlohmann::json j;
      try { j = nlohmann::json::parse(res.body); } catch (...) { j = nullptr; }
      nlohmann::json cap = j.is_object() && j.contains("data") && j["data"].contains("configs") &&
                                   j["data"]["configs"].contains("captcha")
                               ? j["data"]["configs"]["captcha"]
                               : nlohmann::json(nullptr);
      if (!cap.is_object() || cap.value("region", std::string()).empty() ||
          cap.value("prefix", std::string()).empty() || cap.value("sceneId", std::string()).empty()) {
        util::log("captcha-config: upstream missing/incomplete, using fallback (status=" +
                  std::to_string(res.status) + ")");
        cap = fallback;
      }
      c.set_content(cap.dump(), "application/json");
    }));

    // 各账号当前可领取的活动（touch 投放里有 claim_zcode_plan 按钮的）
    REG("GET", "/admin/claim/opportunities", H([this](http::Ctx& c) {
      nlohmann::json items = nlohmann::json::array();
      for (auto& a : ctx_.pool.accounts()) {
        if (a.jwt.empty()) continue;
        std::string dm = a.device_mid.empty() ? util::uuid() : a.device_mid;
        auto tp = upstream::extract_touch_plan_id(a.jwt, dm, ctx_.cfg.app_version);
        if (!tp) continue;
        items.push_back({{"name", a.name},
                         {"campaign_id", tp->campaign_id},
                         {"plan_id", tp->plan_id},
                         {"plan_name", tp->plan_name},
                         {"show_name", tp->show_name},
                         {"grant_units", tp->grant_units}});
      }
      c.set_content(nlohmann::json{{"ok", true}, {"items", items}}.dump(), "application/json");
    }));

    // 手动领取（浏览器生成验证参数后提交，对齐客户端 claimManualPlan：
    // POST billing/claim + X-Aliyun-Captcha-Verify-Param/Region 头）
    REG("POST", R"(/admin/accounts/([^/]+)/claim-plan)", H([this](http::Ctx& c) {
      std::string name = c.params[0];
      auto body = parse(c);
      auto acc = ctx_.pool.get(name);
      if (!acc) {
        c.set_status(404);
        c.set_content(err("no such account").dump(), "application/json");
        return;
      }
      std::string plan_id = util::trim(body.value("plan_id", std::string()));
      std::string cap = util::trim(body.value("captchaVerifyParam", std::string()));
      std::string cap_region = util::trim(body.value("captcha_region", std::string("sgp")));
      if (plan_id.empty()) {
        c.set_status(400);
        c.set_content(err("缺少 plan_id").dump(), "application/json");
        return;
      }
      {
        std::lock_guard<std::mutex> lk(bind_rate_mu_);
        int64_t now = util::time_util::now_ms();
        auto& last = bind_last_attempt_["claim:" + name];
        if (now - last < 8'000) {
          c.set_status(429);
          c.set_content(err("领取请求过于频繁，请 8 秒后再试").dump(), "application/json");
          return;
        }
        last = now;
      }
      std::string dm = acc->device_mid.empty() ? util::uuid() : acc->device_mid;
      upstream::Headers h = upstream::claim_headers(acc->jwt, dm, ctx_.cfg.app_version);
      h.emplace_back("Accept", "application/json");
      if (!cap.empty()) {
        h.emplace_back("X-Aliyun-Captcha-Verify-Param", cap);
        h.emplace_back("X-Aliyun-Captcha-Verify-Region", cap_region);
      }
      auto raw = upstream::curl_post_raw(std::string(upstream::kClaimBase) + "/api/v1/zcode-plan/billing/claim", h,
                                         {{"plan_id", plan_id}});
      nlohmann::json out = nullptr;
      try { out = nlohmann::json::parse(raw.body); } catch (...) {}
      int64_t bcode = out.is_object() ? out.value("code", (int64_t)-1) : -1;
      bool granted = bcode == 0 && out.contains("data") && out["data"].is_object() &&
                     out["data"].contains("plan");
      if (granted) {
        util::log("[claim-manual] " + name + " ✅ " + plan_id + " 已领取");
        c.set_content(nlohmann::json{{"ok", true}, {"name", name}, {"plan_id", plan_id}}.dump(),
                        "application/json");
        return;
      }
      std::string raw_snip = raw.body.substr(0, 500);
      util::log("[claim-manual] " + name + " " + plan_id + " bcode=" + std::to_string(bcode) +
                (raw.timed_out ? " timed_out" : "") + " curl_exit=" + std::to_string(raw.exit_code) +
                " body=" + raw_snip);
      static const std::map<int64_t, std::string> kClaimMsgs = {
          {1003, "上游返回已领取"}, {3007, "安全验证未通过，请重试"}, {401, "登录已失效"},
      };
      auto it_msg = kClaimMsgs.find(bcode);
      std::string msg = it_msg != kClaimMsgs.end() ? it_msg->second
                      : raw.timed_out ? "上游超时（20s 无响应）"
                      : out.is_object() && out.contains("msg") && out["msg"].is_string()
                          ? "上游拒绝 code=" + std::to_string(bcode) + ": " + out["msg"].get<std::string>()
                      : out.is_object()
                          ? "上游拒绝 code=" + std::to_string(bcode)
                      : !raw.body.empty() ? "上游非 JSON 响应: " + raw_snip
                                          : "上游无响应（curl exit " + std::to_string(raw.exit_code) + "）";
      c.set_content(nlohmann::json{{"ok", false}, {"code", bcode}, {"message", msg}}.dump(),
                      "application/json");
    }));

    // ---- OAuth 登录流 ----
    REG("POST", "/admin/login/start", H([this](http::Ctx& c) {
      auto out = login_.start(parse(c));
      if (out.contains("error")) c.set_status(502);
      c.set_content(out.dump(), "application/json");
    }));
    REG("POST", "/admin/login/cookie", H([this](http::Ctx& c) {
      auto out = login_.cookie_login(parse(c));
      if (out.contains("error")) c.set_status(502);
      c.set_content(out.dump(), "application/json");
    }));
    REG("GET", "/admin/login/status", H([this](http::Ctx& c) {
      c.set_content(login_.status(c.get_query("flowId")).dump(), "application/json");
    }));
    REG("POST", "/admin/login/complete", H([this](http::Ctx& c) {
      auto out = login_.complete(parse(c));
      if (out.contains("error")) c.set_status(502);
      c.set_content(out.dump(), "application/json");
    }));
    REG("GET", "/admin/login/debug", H([this](http::Ctx& c) {
      c.set_content(login_.debug().dump(), "application/json");
    }));
    REG("GET", "/admin/oauth/callback", H([this](http::Ctx& c) {
      bool ok = false;
      std::string html = login_.callback(c.get_query("code"), c.get_query("state"), ok);
      c.set_status(200);
      c.set_content(html, "text/html; charset=utf-8");
    }));

    // ---- import-local ----
    REG("POST", "/admin/import-local", H([this](http::Ctx& c) {
      auto creds = store::load_local_creds(ctx_.cfg);
      if (creds && !creds->jwt.empty()) {
        // Node 语义：用本机凭据替换全部账号为单个 local-zcode
        std::set<std::string> none;
        ctx_.paused.set_paused(none);
        domain::Account acc;
        acc.name = "local-zcode";
        acc.jwt = creds->jwt;
        if (!creds->user_info_raw.empty()) {
          try {
            auto u = nlohmann::json::parse(creds->user_info_raw);
            if (u.is_object()) {
              acc.user_info.present = true;
              acc.user_info.name = u.value("name", u.value("nickname", ""));
              acc.user_info.email = u.value("email", "");
              acc.user_info.avatar = u.value("avatar", u.value("picture", ""));
            }
          } catch (...) {}
        }
        // Node 语义：本机凭据替换全部账号；内存权威 + enable_persist 后由 sync 落盘
        domain::Account single = std::move(acc);
        for (auto& a : ctx_.pool.accounts()) ctx_.pool.remove(a.name);
        ctx_.pool.upsert(std::move(single));
        ctx_.pool.enable_persist();
        ctx_.pool.flush_now();
        c.set_content(nlohmann::json{{"imported", true}}.dump(), "application/json");
        util::log("admin: imported local credential account");
      } else {
        c.set_content(nlohmann::json{{"imported", false},
                                       {"message", "本地凭据不可用（未登录 ZCode）"}}.dump(),
                        "application/json");
      }
    }));
  }

private:
  struct PlanCacheEntry { nlohmann::json data; int64_t at = 0; };
  struct RefCacheEntry { nlohmann::json data; int64_t at = 0; };
  std::mutex ref_mu_;
  std::map<std::string, RefCacheEntry> ref_cache_; // jwt → 缓存
  std::mutex bind_rate_mu_;
  std::map<std::string, int64_t> bind_last_attempt_; // 账号 → 上次绑定请求时刻（限速防连环提交）
  std::map<std::string, PlanCacheEntry> plan_cache_;
  std::mutex pb_mu_;
  nlohmann::json pool_balance_cache_;
  int64_t pool_balance_at_ = 0;

  nlohmann::json pool_balance(bool force) {
    int64_t now = util::time_util::now_ms();
    std::lock_guard<std::mutex> lk(pb_mu_);
    if (!force && !pool_balance_cache_.is_null() && now - pool_balance_at_ < 5 * 60'000) {
      nlohmann::json out = pool_balance_cache_;
      out["cached"] = true;
      return out;
    }
    auto accs = ctx_.pool.accounts();
    auto paused = ctx_.paused.paused();
    nlohmann::json by_model = nlohmann::json::object();
    nlohmann::json acc_list = nlohmann::json::array();
    for (auto& a : accs) {
      nlohmann::json entry = {{"name", a.name}};
      if (paused.count(a.name)) entry["paused"] = true;
      std::string dm = a.device_mid.empty() ? util::uuid() : a.device_mid;
      auto raw = upstream::fetch_balance_raw(a.jwt, dm, ctx_.cfg.app_version);
      nlohmann::json plans, balances;
      if (raw.ok() && upstream::parse_balance(raw.body, plans, balances)) {
        nlohmann::json models = nlohmann::json::object();
        for (auto& b : balances) {
          std::string show = b.value("name", "");
          int64_t rem = b.value("remaining", (int64_t)0), tot = b.value("total", (int64_t)0);
          models[show] = {{"remaining", rem}, {"total", tot}, {"expiresAt", b.value("expiresAt", (int64_t)0)}};
          auto& agg = by_model[show];
          if (!agg.is_object()) agg = nlohmann::json::object();
          agg["total"] = agg.value("total", (int64_t)0) + tot;
          agg["remaining"] = agg.value("remaining", (int64_t)0) + rem;
        }
        entry["models"] = models;
      } else {
        entry["err"] = raw.error.empty() ? "upstream " + std::to_string(raw.status) : raw.error;
      }
      acc_list.push_back(std::move(entry));
    }
    nlohmann::json out = {{"byModel", by_model}, {"accounts", acc_list}, {"fetchedAt", now}, {"cached", false}};
    pool_balance_cache_ = out;
    pool_balance_at_ = now;
    return out;
  }

  void dashboard(http::Ctx& c) {
    auto snap = ctx_.usage.snapshot(30); // 全量近期天数，按 day 精确取（snapshot(1) 字母序会拿到昨天）
    std::string day = util::time_util::beijing_date();
    nlohmann::json by_model = nlohmann::json::object();
    nlohmann::json total = {{"req", 0}, {"in", 0}, {"out", 0}, {"cache", 0}, {"tokens", 0}};
    if (snap.contains(day) && snap[day].is_object()) {
      for (auto& [key, cell] : snap[day].items()) {
        std::string model = key;
        auto pos = key.find('\x01');
        if (pos != std::string::npos) model = key.substr(pos + 1);
        auto& m = by_model[model];
        if (!m.is_object()) m = nlohmann::json::object();
        for (auto k : {"req", "in", "out", "cache"}) m[k] = m.value(k, (int64_t)0) + cell.value(k, (int64_t)0);
        m["total"] = m.value("in", (int64_t)0) + m.value("out", (int64_t)0);
        for (auto k : {"req", "in", "out", "cache"}) total[k] = total.value(k, (int64_t)0) + cell.value(k, (int64_t)0);
      }
    }
    total["tokens"] = total.value("in", (int64_t)0) + total.value("out", (int64_t)0);
    // hourly：24 小时分布（来自 recent 内存日志，对齐 Node dashboardStats）
    nlohmann::json hourly = nlohmann::json::array();
    for (int h = 0; h < 24; h++) hourly.push_back({{"hour", h}, {"req", 0}, {"in", 0}, {"out", 0}, {"cache", 0}});
    {
      auto rec = ctx_.recent.to_json()["recent"];
      for (auto& r : rec) {
        int hour = r.value("hour", -1);
        if (hour < 0 || hour > 23) continue;
        auto& h = hourly[hour];
        h["req"] = h.value("req", (int64_t)0) + 1;
        h["in"] = h.value("in", (int64_t)0) + r.value("in", (int64_t)0);
        h["out"] = h.value("out", (int64_t)0) + r.value("out", (int64_t)0);
        h["cache"] = h.value("cache", (int64_t)0) + r.value("cache", (int64_t)0);
      }
    }
    nlohmann::json rt = ctx_.live_rate_getter ? ctx_.live_rate_getter() : nlohmann::json(nullptr);
    c.set_content(nlohmann::json{{"day", day},
                                   {"byModel", by_model},
                                   {"total", total},
                                   {"tps", ctx_.tps.stats()},
                                   {"realtime", rt},
                                   {"hourly", hourly}}
                        .dump(), "application/json");
  }

  static nlohmann::json parse(const http::Ctx& c) {
    try { return nlohmann::json::parse(c.body); } catch (...) { return nlohmann::json::object(); }
  }
  static nlohmann::json err(const std::string& msg) { return {{"error", {{"message", msg}}}}; }
  static void not_implemented(http::Ctx& c) {
    c.set_status(501);
    c.set_content(err("not implemented yet (Phase 2/3)").dump(), "application/json");
  }

  void summary(http::Ctx& c) {
    auto accs = ctx_.pool.accounts();
    auto paused = ctx_.paused.paused();
    int healthy = 0;
    for (auto& a : accs) {
      if (!paused.count(a.name) && !ctx_.pool.cooled_for(a, "")) healthy++;
    }
    nlohmann::json mm = nlohmann::json::object();
    for (auto& [k, v] : ctx_.modelmap.effective()) mm[k] = v;
    c.set_content(nlohmann::json{
      {"ok", healthy > 0 && ctx_.sys.size() > 0},
      {"listen", ctx_.cfg.host + ":" + std::to_string(ctx_.cfg.port)},
      {"accounts", accs.size()},
      {"routingMode", ctx_.routing.mode()},
      {"affinitySessions", ctx_.pool.affinity_size()},
      {"pausedCount", paused.size()},
      {"tps", ctx_.tps.stats()},
      {"modelMap", mm},
      {"defaultModel", ctx_.cfg.default_model},
      {"healthyNow", healthy},
      {"systemPromptBlocks", ctx_.sys.size()},
      {"accountSource", ctx_.pool.source()},
      {"void", util::time_util::now_ms()},
    }.dump(), "application/json");
  }

  AppContext& ctx_;
  ClaimService claim_;
  LoginService login_;
};

} // namespace zproxy::service
