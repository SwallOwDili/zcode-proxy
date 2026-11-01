// L1 crypto — SHA256（hex / 原始摘要）
#pragma once
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstdint>
#include <string>
#include <vector>

namespace zproxy::crypto {

inline std::vector<uint8_t> sha256_raw(const std::string& data) {
  std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), out.data());
  return out;
}

inline std::string sha256_hex(const std::string& data) {
  static const char* hexd = "0123456789abcdef";
  auto d = sha256_raw(data);
  std::string out;
  out.reserve(d.size() * 2);
  for (uint8_t b : d) { out += hexd[b >> 4]; out += hexd[b & 0xf]; }
  return out;
}

// 多段流式摘要：免 a+b 拼接临时（亲和键 system ~9KB 场景）
inline std::string sha256_hex_multi(std::initializer_list<std::string_view> parts) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  std::string out;
  if (ctx) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1;
    for (auto& sv : parts)
      if (ok && !sv.empty()) ok = EVP_DigestUpdate(ctx, sv.data(), sv.size()) == 1;
    if (ok && EVP_DigestFinal_ex(ctx, md, &len) == 1) {
      static const char* hexd = "0123456789abcdef";
      out.reserve(len * 2);
      for (unsigned int i = 0; i < len; i++) { out += hexd[md[i] >> 4]; out += hexd[md[i] & 0xf]; }
    }
    EVP_MD_CTX_free(ctx);
  }
  return out;
}

} // namespace zproxy::crypto
