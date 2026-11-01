// L1 crypto — AES-256-GCM 解密 ZCode credentials（enc:v1:iv.tag.ct，base64url）
#pragma once
#include <openssl/evp.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "util/b64.hpp"
#include "util/string_util.hpp"

namespace zproxy::crypto {

// 与 Node 版 decryptCred 逐位对齐：
//   值不以 "enc:v1:" 开头 → 原样返回（明文回退）
//   否则切 "." 得 [iv, tag, ct]（base64url），AES-256-GCM 解密，失败返回 nullopt
inline std::optional<std::string> decrypt_cred(const std::string& value, const std::vector<uint8_t>& key) {
  static const std::string kPrefix = "enc:v1:";
  if (!zproxy::util::starts_with(value, kPrefix)) return value;

  std::string rest = value.substr(kPrefix.size());
  auto parts = zproxy::util::split(rest, '.');
  if (parts.size() != 3) return std::nullopt;

  std::string iv = zproxy::util::b64::decode(parts[0]);
  std::string tag = zproxy::util::b64::decode(parts[1]);
  std::string ct = zproxy::util::b64::decode(parts[2]);
  if (iv.empty() || tag.size() != 16 || ct.empty() || key.size() != 32) return std::nullopt;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return std::nullopt;
  std::string out;
  out.resize(ct.size() + 16);
  int len = 0, total = 0;
  bool ok = true;
  do {
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { ok = false; break; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) != 1) { ok = false; break; }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(),
                           reinterpret_cast<const unsigned char*>(iv.data())) != 1) { ok = false; break; }
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(out.data()), &len,
                          reinterpret_cast<const unsigned char*>(ct.data()), (int)ct.size()) != 1) { ok = false; break; }
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(tag.data()))) != 1) { ok = false; break; }
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(out.data()) + total, &len) != 1) { ok = false; break; }
    total += len;
  } while (false);
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) return std::nullopt;
  out.resize(total);
  return out;
}

} // namespace zproxy::crypto
