// L4 upstream — marketing/claim/referral 端点（billing/claim、touch 走 curl 子进程绕 TLS 指纹风控）
#pragma once
#include "domain/jwt.hpp"
#include "nlohmann/json.hpp"
#include "upstream/http.hpp"
#include "upstream/zcode_client.hpp" // zcode_source_headers
#include "util/exec.hpp"
#include "util/time_util.hpp"

namespace zproxy::upstream {

static const char* kClaimBase = "https://zcode.z.ai"; // cn 账号的 zcode-plan API 同样只在 zcode.z.ai（bigmodel.cn 上 404）

// claimHeaders 等价：全套 ZC 头 + Bearer + Content-Type
inline Headers claim_headers(const std::string& jwt, const std::string& device_mid,
                             const std::string& app_version) {
  Headers h = zcode_source_headers(jwt, device_mid, app_version);
  h.emplace_back("Authorization", "Bearer " + jwt);
  h.emplace_back("Content-Type", "application/json");
  return h;
}

// curl POST（-H... --data JSON --max-time 20；不经 shell）
inline nlohmann::json curl_post_json(const std::string& url, const Headers& headers, const nlohmann::json& body) {
  std::vector<std::string> argv{"curl", "-s", "-X", "POST", url};
  for (auto& [k, v] : headers) { argv.push_back("-H"); argv.push_back(k + ": " + v); }
  argv.push_back("--data");
  argv.push_back(body.dump());
  argv.push_back("--max-time");
  argv.push_back("20");
  auto r = util::exec::run(argv, 25'000);
  if (r.timed_out || r.spawn_failed) return nullptr;
  try { return nlohmann::json::parse(r.stdout_data); } catch (...) { return nullptr; }
}

// marketing/touch 扫描 claim 按钮（6s 硬超时；拿不到靠日期规律兜底）
struct TouchPlan {
  std::string campaign_id;
  std::string plan_id;
};
inline std::optional<TouchPlan> extract_touch_plan_id(const std::string& jwt, const std::string& device_mid,
                                                      const std::string& app_version) {
  Headers h = claim_headers(jwt, device_mid, app_version);
  // touch 用 GET + fetch（Node 用 fetch；6s 超时）
  auto res = http::get_json(kClaimBase, "/api/v1/marketing/touch?seq=0", h, 6);
  nlohmann::json j;
  try { j = nlohmann::json::parse(res.body); } catch (...) { return std::nullopt; }
  if (!j.is_object() || !j.contains("data") || !j["data"].contains("deliveries")) return std::nullopt;
  for (auto& dd : j["data"]["deliveries"]) {
    if (!dd.is_object()) continue;
    for (const char* kind : {"popup", "banner"}) {
      if (!dd.contains(kind) || !dd[kind].is_object() || !dd[kind].contains("buttons") ||
          !dd[kind]["buttons"].is_array())
        continue;
      for (auto& b : dd[kind]["buttons"]) {
        if (!b.is_object() || !b.contains("action") || !b["action"].is_object()) continue;
        const auto& act = b["action"];
        if (act.value("type", "") == "claim_zcode_plan" && act.contains("args") &&
            act["args"].is_object() && act["args"].contains("plan_id")) {
          return TouchPlan{dd.value("campaign_id", ""), act["args"].value("plan_id", "")};
        }
      }
    }
  }
  return std::nullopt;
}

// 遥测事件上报（补完「登录客户端」任务）
inline bool report_event(const std::string& jwt, const std::string& device_mid, const std::string& app_version,
                         const std::string& element, const std::string& region, const std::string& type,
                         const nlohmann::json& detail, const std::string& user_id) {
  nlohmann::json body = {
    {"event_id", util::uuid()}, {"client_timezone", "Asia/Shanghai"}, {"client_language", "zh-CN"},
    {"element_name", element}, {"event_region", region}, {"event_type", type}, {"event_text", ""},
    {"event_extra_detail", detail}, {"user_id", user_id}, {"screen_resolution", "2056x1329"},
    {"app_version", app_version}, {"device_os_category", "macos"},
    {"device_os_version", sysinfo::kernel_version()}, {"device_mid", device_mid},
    {"mac_id", ""}, {"marketing_params", "{}"},
  };
  Headers h = claim_headers(jwt, device_mid, app_version);
  auto res = http::post_json(kClaimBase, "/api/v1/event/report", h, body.dump(), 20);
  return res.ok();
}

// referral/summary → referralOf 映射（对齐 Node 形状）
inline nlohmann::json fetch_referral(const std::string& jwt, const std::string& device_mid,
                                     const std::string& app_version, bool& ok, std::string& error) {
  Headers h = claim_headers(jwt, device_mid, app_version);
  h.emplace_back("Accept", "application/json");
  auto res = http::get_json(kClaimBase, "/api/v1/incentive/referral/summary", h, 20);
  nlohmann::json j;
  try { j = nlohmann::json::parse(res.body); } catch (...) { j = nullptr; }
  if (!j.is_object() || j.value("code", -1) != 0 || !j.contains("data")) {
    error = "referral " + std::to_string(res.status) + ": " + (j.is_object() ? j.value("msg", std::string()) : std::string());
    ok = false;
    return nullptr;
  }
  const auto& data = j["data"];
  const auto& inviter = data.contains("inviter") && data["inviter"].is_object() ? data["inviter"] : nlohmann::json::object();
  const auto& invitee = data.contains("invitee") && data["invitee"].is_object() ? data["invitee"] : nlohmann::json::object();
  std::string code = inviter.value("invite_code", "");
  nlohmann::json bind_task = nullptr;
  if (invitee.contains("tasks") && invitee["tasks"].is_array()) {
    for (auto& t : invitee["tasks"]) {
      if (t.is_object() && t.value("key", "") == "referral_bind_code") { bind_task = t; break; }
    }
  }
  nlohmann::json invitees = nlohmann::json::array();
  if (inviter.contains("invitees") && inviter["invitees"].is_array()) {
    for (auto& x : inviter["invitees"]) {
      invitees.push_back({{"name", x.contains("name_masked") && x["name_masked"].is_string() ? x["name_masked"] : nlohmann::json("新用户")},
                          {"avatar", x.contains("avatar") ? x["avatar"] : nlohmann::json(nullptr)},
                          {"boundAt", x.contains("bound_at") && x["bound_at"].is_number() ? x["bound_at"] : nlohmann::json(nullptr)}});
    }
  }
  nlohmann::json newcomer_tasks = nlohmann::json::array();
  if (invitee.contains("tasks") && invitee["tasks"].is_array()) {
    for (auto& t : invitee["tasks"]) {
      if (t.is_object()) newcomer_tasks.push_back({{"key", t.value("key", "")}, {"completed", t.value("completed", false)}});
    }
  }
  bool bind_done = false;
  if (!bind_task.is_null() && bind_task.value("completed", false)) bind_done = true;
  if (invitee.contains("inviter") && invitee.contains("state") && invitee.value("state", "") == "done") bind_done = true;
  bool can_bind = invitee.value("state", "") == "active" && !bind_task.is_null() && !bind_task.value("completed", true);
  ok = true;
  return {
    {"inviteCode", code.empty() ? nlohmann::json(nullptr) : nlohmann::json(code)},
    {"inviteLink", code.empty() ? nlohmann::json(nullptr) : nlohmann::json("https://zcode.z.ai/invite/" + code)},
    {"inviterState", inviter.contains("state") ? inviter["state"] : nlohmann::json(nullptr)},
    {"inviterUnlockedAt", inviter.contains("unlock_at") && inviter["unlock_at"].is_number() ? inviter["unlock_at"] : nlohmann::json(nullptr)},
    {"invitedTotal", inviter.contains("invited") && inviter["invited"].is_object() ? inviter["invited"].value("total", 0) : 0},
    {"invitedWeekly", inviter.contains("invited") && inviter["invited"].is_object() ? inviter["invited"].value("weekly", 0) : 0},
    {"invitees", invitees},
    {"inviteeState", invitee.contains("state") ? invitee["state"] : nlohmann::json(nullptr)},
    {"bindDone", bind_done},
    {"canBind", can_bind},
    {"newcomerTasks", newcomer_tasks},
  };
}

} // namespace zproxy::upstream
