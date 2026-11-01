// L5 service — 每日领取（claim 周期）、入池体检、风控重试、补完登录任务
// 策略要点（对齐 Node 逆向结论）：
//   上游只允许领取「账号套餐列表里已存在」的活动：老号+列表内 → 1003 已领；
//   老号+列表外 → 1001；新号+列表外 → 3012 风控。只领 touch 投递/已学到的 plan，绝不盲猜。
#pragma once
#include <atomic>
#include <thread>
#include "domain/account_pool.hpp"
#include "nlohmann/json.hpp"
#include "service/app_context.hpp"
#include "store/claim_store.hpp"
#include "upstream/marketing.hpp"
#include "util/time_util.hpp"

namespace zproxy::service {

class ClaimService {
public:
  ClaimService(AppContext& ctx, store::ClaimStore& store)
      : ctx_(ctx), store_(store) {
    if (ctx_.cfg.blocked_retry) {
      retry_thread_ = std::thread([this] {
        while (!stop_.load()) {
          for (int i = 0; i < 120 && !stop_.load(); i++) // 2h 粒度切片（60s×120）
            std::this_thread::sleep_for(std::chrono::seconds(60));
          if (stop_.load()) break;
          retry_blocked();
        }
      });
    }
  }
  ~ClaimService() {
    stop_ = true;
    if (retry_thread_.joinable()) retry_thread_.join();
  }

  // ---------- 单账号领取 ----------
  struct ClaimOutcome { std::string status, detail; };

  ClaimOutcome claim_one(const domain::Account& acc) {
    std::string dm = acc.device_mid.empty() ? util::uuid() : acc.device_mid;
    std::string jwt = acc.jwt;
    std::string ver = ctx_.cfg.app_version;
    std::string uid = acc.jwt_user_id().empty() ? acc.name : acc.jwt_user_id();

    // 1) balance：今日套餐已在列 → already
    upstream::Headers h = upstream::claim_headers(jwt, dm, ver);
    auto bal_res = upstream::http::get_json(upstream::kClaimBase,
        "/api/v1/zcode-plan/billing/balance?app_version=" + ver, h, 20);
    nlohmann::json bal;
    try { bal = nlohmann::json::parse(bal_res.body); } catch (...) { bal = nullptr; }
    if (bal.is_object() && bal.contains("data") && already_has_today(bal["data"])) {
      return {"already", "今日套餐已在列"};
    }

    // 2) 领取前自愈：login_device 未完成 → 补发 app_login_success（结果缓存 10 分钟）
    {
      std::lock_guard<std::mutex> lk(lc_mu_);
      auto it = login_checked_.find(jwt);
      if (it == login_checked_.end() || util::time_util::now_ms() - it->second > 10 * 60'000) {
        bool ok = false;
        std::string err;
        auto rf = upstream::fetch_referral(jwt, dm, ver, ok, err);
        if (ok) {
          for (auto& t : rf.value("newcomerTasks", nlohmann::json::array())) {
            if (t.value("key", "") == "login_device" && !t.value("completed", true)) {
              util::log("[claim] " + acc.name + " login_device 未完成，自动补发 app_login_success");
              complete_login_device(jwt, dm, ver, acc.region);
              std::this_thread::sleep_for(std::chrono::milliseconds(1500));
            }
          }
        }
        login_checked_[jwt] = util::time_util::now_ms();
      }
    }

    // 3) 候选 plan：touch 投递 → 已学到（含今日日期）→ 套餐列表里今日生成的 start-plan
    auto touch = upstream::extract_touch_plan_id(jwt, dm, ver);
    std::string tag = store_.today();
    std::vector<std::string> candidates;
    if (touch) candidates.push_back(touch->plan_id);
    std::string remembered = store_.learned_plan_id();
    if (!remembered.empty() && remembered.find(tag) != std::string::npos &&
        std::find(candidates.begin(), candidates.end(), remembered) == candidates.end())
      candidates.push_back(remembered);
    if (bal.is_object() && bal.contains("data") && bal["data"].contains("plans") && bal["data"]["plans"].is_array()) {
      for (auto& p : bal["data"]["plans"]) {
        std::string pid = p.value("plan_id", "");
        if (pid.find("start-plan-" + tag) != std::string::npos &&
            std::find(candidates.begin(), candidates.end(), pid) == candidates.end())
          candidates.push_back(pid);
      }
    }
    if (candidates.empty()) {
      return {"no-campaign", !touch ? "无活动投放且套餐列表无今日活动（跳过，避免风控）" : "今日无 claim 类型投放（跳过）"};
    }

    // 4) touch confirm
    if (touch) {
      upstream::curl_post_json(std::string(upstream::kClaimBase) + "/api/v1/marketing/touch/action", h,
                               {{"campaign_id", touch->campaign_id}, {"action_type", "confirm"}});
    }

    // 5) 逐个 claim（curl POST 绕 TLS 指纹）
    std::string last;
    for (auto& pid : candidates) {
      auto j = upstream::curl_post_json(std::string(upstream::kClaimBase) + "/api/v1/zcode-plan/billing/claim", h,
                                        {{"plan_id", pid}});
      int64_t code = j.is_object() ? j.value("code", (int64_t)-1) : -1;
      if (code == 0) {
        store_.set_learned_plan_id(pid);
        std::string grants;
        if (j.contains("data") && j["data"].is_object() && j["data"].contains("plan") &&
            j["data"]["plan"].is_object() && j["data"]["plan"].contains("entitlements") &&
            j["data"]["plan"]["entitlements"].is_array()) {
          for (auto& e : j["data"]["plan"]["entitlements"]) {
            if (!grants.empty()) grants += ", ";
            grants += e.value("show_name", e.value("entitlement_id", "")) + " " +
                      std::to_string(e.value("grant_units", (int64_t)0));
          }
        }
        return {"claimed", pid + (grants.empty() ? "" : "（" + grants + "）")};
      }
      last = "claim " + pid + " -> code=" + std::to_string(code) + " " +
             (j.is_object() ? j.value("msg", std::string()) : std::string());
      util::log("[claim] " + acc.name + " " + last);
      if (code == 1003) return {"already", "上游返回已领取"};
      if (code == 3012) return {"blocked", "3012 风控：该活动未投放到此账号（不重试无投放的 plan）"};
      if (code == 1001) return {"no-campaign", "套餐不存在或未投放（" + pid + "）"};
      std::this_thread::sleep_for(std::chrono::milliseconds(code == 3012 ? 15'000 : 3'000)); // 风控时才长等
    }
    return {"failed", last.empty() ? "无可候选 plan_id" : last};
  }

  // ---------- 完整周期（并发 4、跳过已处理、写 claim-state）----------
  nlohmann::json run_cycle(bool force) {
    std::string tag = store_.today();
    auto prev = store_.day_results(tag);
    auto accs = ctx_.pool.accounts();
    nlohmann::json results = nlohmann::json::array();
    struct Job { std::string name, jwt, region, device_mid, uid; };
    std::vector<Job> queue;
    for (auto& a : accs) {
      std::string uid = a.jwt_user_id().empty() ? a.name : a.jwt_user_id();
      auto it = prev.find(uid);
      if (!force && it != prev.end() &&
          (it->second.status == "claimed" || it->second.status == "already")) {
        results.push_back({{"account", a.name}, {"uid", uid}, {"status", it->second.status},
                           {"detail", "今日已处理（" + it->second.detail + "）"}});
        continue;
      }
      results.push_back({{"account", a.name}, {"uid", uid}, {"status", "pending"}, {"detail", ""}});
      queue.push_back({a.name, a.jwt, a.region, a.device_mid, uid});
    }
    {
      std::lock_guard<std::mutex> lk(live_mu_);
      live_ = {{"running", true}, {"startedAt", util::time_util::now_ms()}, {"results", results}};
    }
    int concurrency = std::max(1, std::min<int>(ctx_.cfg.claim_concurrency, (int)queue.size()));
    std::atomic<size_t> cursor{0};
    auto worker = [&]() {
      for (;;) {
        size_t i = cursor++;
        if (i >= queue.size()) break;
        auto& job = queue[i];
        ClaimOutcome out{"failed", "unknown"};
        try {
          domain::Account acc;
          acc.name = job.name; acc.jwt = job.jwt; acc.region = job.region; acc.device_mid = job.device_mid;
          out = claim_one(acc);
        } catch (const std::exception& e) { out = {"failed", e.what()}; }
        store_.record_result(job.uid, {out.status, util::time_util::now_ms(), out.detail});
        {
          std::lock_guard<std::mutex> lk(live_mu_);
          for (auto& r : live_["results"]) {
            if (r.value("uid", "") == job.uid && r.value("status", "") == "pending") {
              r["status"] = out.status;
              r["detail"] = out.detail;
              break;
            }
          }
        }
        util::log("[claim] " + job.name + " -> " + out.status + " " + out.detail);
        std::this_thread::sleep_for(std::chrono::milliseconds(800)); // 同 worker 内错峰
      }
    };
    std::vector<std::thread> workers;
    for (int i = 0; i < concurrency; i++) workers.emplace_back(worker);
    for (auto& w : workers) w.join();
    {
      std::lock_guard<std::mutex> lk(live_mu_);
      live_["running"] = false;
      last_run_ = {{"at", util::time_util::now_ms()}, {"dayTag", tag}, {"results", live_["results"]}};
      return last_run_;
    }
  }

  // 风控 blocked 账号重试
  nlohmann::json retry_blocked() {
    std::string tag = store_.today();
    auto day = store_.day_results(tag);
    std::vector<domain::Account> blocked;
    for (auto& a : ctx_.pool.accounts()) {
      std::string uid = a.jwt_user_id().empty() ? a.name : a.jwt_user_id();
      auto it = day.find(uid);
      if (it != day.end() && it->second.status == "blocked") blocked.push_back(a);
    }
    nlohmann::json out = {{"retried", blocked.size()}, {"ok", 0}};
    if (blocked.empty()) return out;
    int ok = 0;
    for (auto& a : blocked) {
      std::string uid = a.jwt_user_id().empty() ? a.name : a.jwt_user_id();
      auto out2 = claim_one(a);
      if (out2.status == "claimed" || out2.status == "already") {
        ok++;
        store_.record_result(uid, {out2.status, util::time_util::now_ms(), out2.detail});
        util::log("[claim-retry] ✅ " + a.name + " " + out2.status + " " + out2.detail);
      } else {
        util::log("[claim-retry] " + a.name + " 仍被拦: " + out2.detail);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    }
    out["ok"] = ok;
    return out;
  }

  // 入池体检
  nlohmann::json audit() {
    nlohmann::json rows = nlohmann::json::array();
    nlohmann::json need = nlohmann::json::array();
    for (auto& a : ctx_.pool.accounts()) {
      std::string dm = a.device_mid.empty() ? util::uuid() : a.device_mid;
      std::string uid = a.jwt_user_id().empty() ? a.name : a.jwt_user_id();
      bool ok = false;
      std::string err;
      auto rf = upstream::fetch_referral(a.jwt, dm, ctx_.cfg.app_version, ok, err);
      bool need_app_login = false;
      nlohmann::json login_task = nullptr;
      if (ok) {
        for (auto& t : rf.value("newcomerTasks", nlohmann::json::array())) {
          if (t.value("key", "") == "login_device") login_task = t;
        }
        need_app_login = !login_task.is_null() && !login_task.value("completed", true);
      }
      bool jwt_ok = true;
      nlohmann::json plans = nlohmann::json::array();
      auto bal_res = upstream::http::get_json(upstream::kClaimBase,
          "/api/v1/zcode-plan/billing/balance?app_version=" + ctx_.cfg.app_version,
          upstream::claim_headers(a.jwt, dm, ctx_.cfg.app_version), 20);
      if (bal_res.status == 401) jwt_ok = false;
      try {
        auto jb = nlohmann::json::parse(bal_res.body);
        if (jb.is_object() && jb.contains("data") && jb["data"].contains("plans")) {
          for (auto& p : jb["data"]["plans"]) plans.push_back(p.value("plan_id", ""));
        }
      } catch (...) {}
      bool has_campaign = false;
      for (auto& p : plans) {
        std::string s = p.get<std::string>();
        if (s.find("start-plan-") != std::string::npos && s.find("0817") == std::string::npos &&
            s.find("referral") == std::string::npos)
          has_campaign = true;
      }
      if (need_app_login) need.push_back(a.name);
      rows.push_back({
        {"name", a.name}, {"uid", uid},
        {"inviteBound", ok && rf.value("bindDone", false)},
        {"loginDevice", login_task.is_null() ? nlohmann::json(nullptr) : nlohmann::json(login_task.value("completed", false))},
        {"needAppLogin", need_app_login}, {"jwtOk", jwt_ok},
        {"plans", plans}, {"hasCampaign", has_campaign},
        {"action", !jwt_ok ? "重新导入 token" : (need_app_login ? "需在 ZCode App 登录一次" : "正常")},
      });
      std::this_thread::sleep_for(std::chrono::milliseconds(800));
    }
    return {{"accounts", rows}, {"needAppLogin", need}};
  }

  // 补完「登录客户端」任务（app_login_ck → 1.2s → app_login_success）
  nlohmann::json complete_login_device(const std::string& jwt, const std::string& device_mid,
                                       const std::string& ver, const std::string& region) {
    std::string uid = domain::account_user_id_of(jwt);
    std::string family = region == "cn" ? "bigmodel" : "zai";
    nlohmann::json results = nlohmann::json::array();
    auto r1 = upstream::report_event(jwt, device_mid, ver, "app_login_ck", "app", "ck",
                                     {{"login_url", "https://chat.z.ai/auth"}}, uid);
    results.push_back({{"step", "app_login_ck"}, {"ok", r1}});
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    auto r2 = upstream::report_event(jwt, device_mid, ver, "app_login_success", "app_profile", "view",
                                     {{"login_provider", family}}, uid);
    results.push_back({{"step", "app_login_success"}, {"ok", r2}});
    return results;
  }

  nlohmann::json status_json() {
    std::lock_guard<std::mutex> lk(live_mu_);
    // 契约（claim.html）：live = [{account, status, detail}] 数组（前端 .map 渲染进行中的账号）
    // 注意：nlohmann value(key, nullptr) 遇到 number 值会抛 302——claim 跑过一次后
    // startedAt 是 number，绝不能用 value(nullptr) 读它。
    nlohmann::json out = {
      {"dayTag", store_.today()},
      {"running", live_.value("running", false)},
      {"live", live_.value("results", nlohmann::json::array())},
      {"perAccount", store_.state().contains(store_.today()) ? store_.state()[store_.today()] : nlohmann::json::object()},
      {"lastRun", last_run_.is_null() ? nlohmann::json(nullptr) : last_run_},
    };
    out["startedAt"] = (live_.contains("startedAt") && !live_["startedAt"].is_null())
                           ? live_["startedAt"] : nlohmann::json(nullptr);
    return out;
  }

  bool try_start_cycle(bool force) {
    bool expect = false;
    if (!running_.compare_exchange_strong(expect, true)) return false;
    std::thread([this, force] {
      try { run_cycle(force); } catch (const std::exception& e) { util::log("[claim] cycle error: " + std::string(e.what())); }
      running_ = false;
    }).detach();
    return true;
  }

private:
  static bool already_has_today(const nlohmann::json& balance_data) {
    std::string tag = util::time_util::beijing_mmdd();
    if (!balance_data.contains("plans") || !balance_data["plans"].is_array()) return false;
    for (auto& p : balance_data["plans"]) {
      std::string pid = p.value("plan_id", "");
      if (p.value("status", "") == "active" && pid.find("start-plan-" + tag) != std::string::npos) return true;
    }
    return false;
  }

  AppContext& ctx_;
  store::ClaimStore& store_;
  std::mutex lc_mu_;
  std::map<std::string, int64_t> login_checked_; // jwt → 体检时间
  std::mutex live_mu_;
  nlohmann::json live_ = {{"running", false}, {"results", nlohmann::json::array()}};
  nlohmann::json last_run_ = nullptr;
  std::atomic<bool> running_{false};
  std::atomic<bool> stop_{false};
  std::thread retry_thread_;
};

} // namespace zproxy::service
