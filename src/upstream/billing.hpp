// L4 upstream — billing/balance 端点（额度池 / 账号套餐）
#pragma once
#include <map>
#include "nlohmann/json.hpp"
#include "upstream/http.hpp"
#include "upstream/zcode_client.hpp" // zcode_source_headers / combine
#include "util/time_util.hpp"

namespace zproxy::upstream {

static const char* kBillingBase = "https://zcode.z.ai";

// 单账号 balance 原始拉取（对齐 Node：完整 zcodeSourceHeaders + Bearer）
inline HttpResponse fetch_balance_raw(const std::string& jwt, const std::string& device_mid,
                                      const std::string& app_version) {
  Headers h = zcode_source_headers(jwt, device_mid, app_version);
  h.emplace_back("Authorization", "Bearer " + jwt);
  return http::get_json(kBillingBase, "/api/v1/zcode-plan/billing/balance?app_version=" + app_version, h, 20);
}

// 解析为 plan/balances 列表（对齐 Node /admin/accounts/{name}/plan 输出形状）
inline bool parse_balance(const std::string& body, nlohmann::json& plans, nlohmann::json& balances) {
  nlohmann::json j;
  try { j = nlohmann::json::parse(body); } catch (...) { return false; }
  if (!j.is_object() || j.value("code", -1) != 0 || !j.contains("data")) return false;
  const auto& d = j["data"];
  plans = nlohmann::json::array();
  if (d.contains("plans") && d["plans"].is_array()) {
    for (auto& p : d["plans"]) {
      plans.push_back({
        {"name", p.value("name", "")},
        {"planId", p.value("plan_id", "")},
        {"userPlanId", p.value("user_plan_id", "")},
        {"status", p.value("status", "")},
        {"startsAt", p.value("starts_at", (int64_t)0) * 1000},
        {"endsAt", p.value("ends_at", (int64_t)0) * 1000},
      });
    }
  }
  balances = nlohmann::json::array();
  if (d.contains("balances") && d["balances"].is_array()) {
    for (auto& b : d["balances"]) {
      balances.push_back({
        {"name", b.value("show_name", "")},
        {"total", b.value("total_units", (int64_t)0)},
        {"used", b.value("used_units", (int64_t)0)},
        {"remaining", b.value("remaining_units", (int64_t)0)},
        {"userPlanId", b.value("user_plan_id", "")},
        {"expiresAt", b.value("expires_at", (int64_t)0)},
      });
    }
  }
  return true;
}

} // namespace zproxy::upstream
