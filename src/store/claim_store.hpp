// L2 store — claim-state.json：每日领取状态
// {"_today":"MMDD","planId":"...","MMDD":{"<user-uuid>":{"status":..,"at":ms,"detail":..}}}
#pragma once
#include <map>
#include <string>
#include "nlohmann/json.hpp"
#include "store/json_store.hpp"
#include "util/time_util.hpp"

namespace zproxy::store {

struct ClaimResult {
  std::string status; // claimed | already | blocked | no-campaign | failed
  int64_t at = 0;
  std::string detail;
};

class ClaimStore : public JsonFile {
public:
  explicit ClaimStore(std::string path) : JsonFile(std::move(path)) {}

  std::string today() const { return util::time_util::beijing_mmdd(); }

  nlohmann::json state() {
    if (changed_on_disk() || !loaded_) { loaded_ = true; auto j = read(); data_ = (j && j->is_object()) ? *j : nlohmann::json::object(); }
    return data_;
  }

  std::string learned_plan_id() {
    auto s = state();
    return s.value("planId", std::string());
  }
  void set_learned_plan_id(const std::string& id) {
    state();
    data_["planId"] = id;
    persist();
  }

  std::map<std::string, ClaimResult> day_results(const std::string& day) {
    std::map<std::string, ClaimResult> out;
    auto s = state();
    if (s.contains(day) && s[day].is_object()) {
      for (auto& [uid, v] : s[day].items()) {
        if (v.is_object()) out[uid] = ClaimResult{v.value("status", ""), v.value("at", (int64_t)0), v.value("detail", "")};
      }
    }
    return out;
  }

  void record_result(const std::string& uid, const ClaimResult& r) {
    state();
    std::string day = today();
    if (data_["_today"].is_string() && data_["_today"].get<std::string>() != day) {
      // 跨天：丢弃旧 day 键，仅保留今天/昨天由 persist 清理
      std::string old = data_["_today"];
      if (data_.contains(old)) data_.erase(old);
    }
    data_["_today"] = day;
    data_[day][uid] = {{"status", r.status}, {"at", r.at}, {"detail", r.detail}};
    persist();
  }

private:
  // 只保留 _today、planId 与 4 位数字 day 键
  void persist() {
    nlohmann::json out = nlohmann::json::object();
    if (data_.contains("_today")) out["_today"] = data_["_today"];
    if (data_.contains("planId")) out["planId"] = data_["planId"];
    std::string tag_now = this->today();
    std::string yesterday_tag = yesterday();
    const std::string& today = tag_now;
    for (auto& [k, v] : data_.items()) {
      if (k.size() == 4 && k.find_first_not_of("0123456789") == std::string::npos) {
        if (k == today || k == yesterday_tag) out[k] = v;
      }
    }
    data_ = out;
    write(out, 1);
  }
  static std::string yesterday() {
    return util::time_util::beijing_mmdd(util::time_util::now_ms() - 24 * 3600 * 1000);
  }

  nlohmann::json data_ = nlohmann::json::object();
  bool loaded_ = false;
};

} // namespace zproxy::store
