// L3 domain — JWT 解码（不验签，仅取 payload）
#pragma once
#include <optional>
#include <string>
#include "nlohmann/json.hpp"
#include "util/b64.hpp"
#include "util/string_util.hpp"

namespace zproxy::domain {

inline std::optional<nlohmann::json> jwt_payload(const std::string& jwt) {
  auto parts = util::split(jwt, '.');
  if (parts.size() < 2) return std::nullopt;
  std::string payload = util::b64::decode(parts[1]);
  try { return nlohmann::json::parse(payload); } catch (...) { return std::nullopt; }
}

inline std::string account_user_id_of(const std::string& jwt) {
  auto p = jwt_payload(jwt);
  if (!p || !p->is_object()) return "";
  if (p->contains("user_id") && (*p)["user_id"].is_string()) return (*p)["user_id"].get<std::string>();
  if (p->contains("sub") && (*p)["sub"].is_string()) return (*p)["sub"].get<std::string>();
  return "";
}

} // namespace zproxy::domain
