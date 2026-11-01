// L0 util — 随机数 / UUID v4（OpenSSL CSPRNG，禁止用 rand()）
#pragma once
#include <openssl/rand.h>
#include <cstdint>
#include <cstdio>
#include <string>

namespace zproxy::util {

// n 字节随机数的 hex 表示（用于 OAuth bearer 等）
inline std::string random_hex(size_t bytes) {
  std::string buf(bytes, '\0');
  if (RAND_bytes(reinterpret_cast<unsigned char*>(buf.data()), (int)bytes) != 1) return "";
  char out[3];
  std::string hex;
  hex.reserve(bytes * 2);
  for (size_t i = 0; i < bytes; i++) {
    std::snprintf(out, sizeof(out), "%02x", (unsigned char)buf[i]);
    hex += out;
  }
  return hex;
}

inline std::string uuid() {
  unsigned char b[16];
  if (RAND_bytes(b, 16) != 1) return "00000000-0000-4000-8000-000000000000";
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant 10
  char out[37];
  std::snprintf(out, sizeof(out),
    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
  return out;
}

} // namespace zproxy::util
