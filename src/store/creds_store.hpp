// L2 store — 本机 ZCode credentials.json（AES-256-GCM 解密）
#pragma once
#include <optional>
#include <string>
#include "crypto/aes_gcm.hpp"
#include "nlohmann/json.hpp"
#include "util/config.hpp"
#include "util/fs.hpp"
#include "util/log.hpp"

namespace zproxy::store {

struct LocalCreds {
  std::string jwt;           // zcodejwttoken（解密后）
  std::string user_info_raw; // oauth:zai:user_info（解密后的 JSON 字符串，可能为空）
  double mtime_ms = -1;
};

inline std::optional<LocalCreds> load_local_creds(const Config& cfg) {
  auto raw = util::fs::read_file(cfg.creds_path);
  if (!raw) return std::nullopt;
  nlohmann::json j;
  try { j = nlohmann::json::parse(*raw); } catch (...) { return std::nullopt; }
  if (!j.is_object()) return std::nullopt;

  LocalCreds out;
  out.mtime_ms = util::fs::mtime_ms(cfg.creds_path);
  std::vector<uint8_t> key = cfg.local_key();

  if (j.contains("zcodejwttoken") && j["zcodejwttoken"].is_string()) {
    auto dec = crypto::decrypt_cred(j["zcodejwttoken"].get<std::string>(), key);
    if (dec) out.jwt = *dec;
  }
  if (j.contains("oauth:zai:user_info") && j["oauth:zai:user_info"].is_string()) {
    auto dec = crypto::decrypt_cred(j["oauth:zai:user_info"].get<std::string>(), key);
    if (dec) out.user_info_raw = *dec;
  }
  if (out.jwt.empty()) return std::nullopt;
  return out;
}

} // namespace zproxy::store
