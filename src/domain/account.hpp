// L3 domain — 账号实体（持久化字段 + 运行时状态）
#pragma once
#include <map>
#include <optional>
#include <string>
#include "nlohmann/json.hpp"
#include "domain/jwt.hpp"
#include "util/config.hpp"
#include "util/uuid.hpp"

namespace zproxy::domain {

struct UserInfo {
  std::string name, email, avatar, user_id;
  bool present = false;
};

struct Account {
  // 持久化（tokens.json）
  std::string name;
  std::string jwt;
  std::string region = "global"; // global | cn
  std::string device_mid;        // 懒生成
  std::string session_id;        // 懒生成
  UserInfo user_info;
  bool has_fingerprint = false;
  std::string fp_platform = "darwin-arm64";
  std::string fp_language = "zh-CN";

  // 运行时（不落盘）
  int64_t cooldown_until = 0;                      // 账号级冷却（401 等）
  std::map<std::string, int64_t> model_cooldowns;  // 模型级冷却（429 配额）
  std::map<std::string, int64_t> model_remaining;  // 模型剩余额度（billing 刷新；0 = 不选）
  int inflight = 0; // 在途计数（池锁保护）

  nlohmann::json to_json() const {
    nlohmann::json j;
    j["name"] = name;
    j["jwt"] = jwt;
    j["region"] = region;
    if (!device_mid.empty()) j["deviceMid"] = device_mid;
    if (!session_id.empty()) j["sessionId"] = session_id;
    if (user_info.present) {
      nlohmann::json u = nlohmann::json::object();
      if (!user_info.name.empty()) u["name"] = user_info.name;
      if (!user_info.email.empty()) u["email"] = user_info.email;
      if (!user_info.avatar.empty()) u["avatar"] = user_info.avatar;
      if (!user_info.user_id.empty()) u["userId"] = user_info.user_id;
      j["userInfo"] = u;
    }
    if (has_fingerprint) {
      j["fingerprint"] = {{"platform", fp_platform}, {"language", fp_language}};
    }
    return j;
  }

  static Account from_json(const nlohmann::json& j, const std::string& fallback_name) {
    Account a;
    a.name = j.value("name", fallback_name);
    a.jwt = j.value("jwt", "");
    a.region = j.value("region", "global");
    a.device_mid = j.value("deviceMid", "");
    a.session_id = j.value("sessionId", "");
    if (j.contains("userInfo") && j["userInfo"].is_object()) {
      a.user_info.present = true;
      const auto& u = j["userInfo"];
      a.user_info.name = u.value("name", "");
      a.user_info.email = u.value("email", "");
      a.user_info.avatar = u.value("avatar", "");
      a.user_info.user_id = u.value("userId", "");
    }
    if (j.contains("fingerprint") && j["fingerprint"].is_object()) {
      a.has_fingerprint = true;
      a.fp_platform = j["fingerprint"].value("platform", "darwin-arm64");
      a.fp_language = j["fingerprint"].value("language", "zh-CN");
    }
    return a;
  }

  // JWT payload 里的 user_id（去重判据；无则空）
  std::string jwt_user_id() const { return account_user_id_of(jwt); }
};

} // namespace zproxy::domain
