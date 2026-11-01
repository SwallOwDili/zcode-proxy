// L0 util — base64 / base64url 编解码（无外部依赖，自实现以同时支持 url 变体与容错）
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace zproxy::util::b64 {

inline const char* kStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
inline const char* kUrl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

namespace detail {
inline void encode_into(const std::vector<uint8_t>& in, const char* tbl, bool pad, std::string& out) {
  out.clear();
  out.reserve((in.size() + 2) / 3 * 4);
  size_t i = 0;
  while (i + 2 < in.size()) {
    uint32_t v = (uint32_t(in[i]) << 16) | (uint32_t(in[i + 1]) << 8) | in[i + 2];
    out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63]; out += tbl[(v >> 6) & 63]; out += tbl[v & 63];
    i += 3;
  }
  if (i + 1 == in.size()) {
    uint32_t v = uint32_t(in[i]) << 16;
    out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63];
    if (pad) out += "==";
  } else if (i + 2 == in.size()) {
    uint32_t v = (uint32_t(in[i]) << 16) | (uint32_t(in[i + 1]) << 8);
    out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63]; out += tbl[(v >> 6) & 63];
    if (pad) out += '=';
  }
}
inline int8_t dec(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+' || c == '-') return 62;
  if (c == '/' || c == '_') return 63;
  return -1;
}
} // namespace detail

inline std::string encode(const std::string& raw) {
  std::string out;
  detail::encode_into(std::vector<uint8_t>(raw.begin(), raw.end()), kStd, true, out);
  return out;
}
inline std::string encode_url(const std::string& raw) {
  std::string out;
  detail::encode_into(std::vector<uint8_t>(raw.begin(), raw.end()), kUrl, false, out);
  return out;
}
inline std::string decode(const std::string& in) {
  std::string out;
  uint32_t acc = 0; int bits = 0;
  for (char c : in) {
    int8_t v = detail::dec(c);
    if (v < 0) continue; // 忽略 '='、空白、非法字符（Node Buffer 宽容行为）
    acc = (acc << 6) | uint32_t(v); bits += 6;
    if (bits >= 8) { bits -= 8; out += char((acc >> bits) & 0xff); }
  }
  return out;
}

} // namespace zproxy::util::b64
