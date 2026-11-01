// tests — util/crypto/store 用例
#include <cassert>
#include <cstdio>
#include "crypto/aes_gcm.hpp"
#include "crypto/sha256.hpp"
#include "store/usage_store.hpp"
#include "util/b64.hpp"
#include "util/time_util.hpp"
#include "util/uuid.hpp"

using namespace zproxy;
static int g_pass = 0, g_fail = 0;
#define CHECK(cond)                                                                                                    \
  do {                                                                                                                 \
    if (cond) { g_pass++; } else { g_fail++; std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); }              \
  } while (0)

static void test_b64() {
  CHECK(util::b64::encode("hello") == "aGVsbG8=");
  CHECK(util::b64::decode("aGVsbG8=") == "hello");
  CHECK(util::b64::decode("aGVs bG8=") == "hello");   // 宽容空白
  CHECK(util::b64::encode_url("\xfb\xff") == "-_8");  // url 变体无填充
}

static void test_sha256() {
  CHECK(crypto::sha256_hex("abc") ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void test_uuid() {
  auto u = util::uuid();
  CHECK(u.size() == 36 && u[14] == '4' && (u[19] == '8' || u[19] == '9' || u[19] == 'a' || u[19] == 'b'));
  auto h = util::random_hex(32);
  CHECK(h.size() == 64);
}

static void test_aes_roundtrip() {
  // 自加密向量（Node 无依赖可复算：openssl enc -aes-256-gcm 等价语义）
  std::vector<uint8_t> key(32, 0x42);
  std::string iv_s = util::random_hex(12);
  std::string plain = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig";
  // 用 OpenSSL 加密构造 enc:v1: 格式再解密
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  std::vector<uint8_t> iv;
  for (size_t i = 0; i < iv_s.size(); i += 2) iv.push_back(std::stoi(iv_s.substr(i, 2), nullptr, 16));
  std::string ct(plain.size() + 16, '\0');
  int len = 0, total = 0;
  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data());
  EVP_EncryptUpdate(ctx, (uint8_t*)ct.data(), &len, (const uint8_t*)plain.data(), (int)plain.size());
  total = len;
  EVP_EncryptFinal_ex(ctx, (uint8_t*)ct.data() + total, &len);
  total += len;
  uint8_t tag[16];
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
  EVP_CIPHER_CTX_free(ctx);
  std::string enc = "enc:v1:" + util::b64::encode_url(std::string(iv.begin(), iv.end())) + "." +
                    util::b64::encode_url(std::string((char*)tag, 16)) + "." +
                    util::b64::encode_url(ct.substr(0, total));
  auto dec = crypto::decrypt_cred(enc, key);
  CHECK(dec.has_value() && *dec == plain);
  // 明文回退
  auto dec2 = crypto::decrypt_cred("plain-jwt", key);
  CHECK(dec2.has_value() && *dec2 == "plain-jwt");
  // 篡改失败
  auto dec3 = crypto::decrypt_cred(enc.substr(0, enc.size() - 2) + "AA", key);
  CHECK(!dec3.has_value());
}

static void test_usage_store() {
  std::string path = "/tmp/zproxy-test-usage.json";
  ::unlink(path.c_str());
  {
    store::UsageStore u(path);
    u.record("acc-a", "GLM-5.3", 100, 50, 10);
    u.record("acc-a", "GLM-5.3", 10, 5, 1);
    u.record("acc-b", "GLM-5.3-Flash", 7, 3, 0);
    u.flush_now();
  }
  auto raw = util::fs::read_file(path);
  CHECK(raw.has_value());
  auto j = nlohmann::json::parse(*raw);
  CHECK(j["days"].is_object());
  std::string day = util::time_util::beijing_date();
  auto key = "acc-a\x01GLM-5.3";
  CHECK(j["days"][day][key]["req"] == 2);
  CHECK(j["days"][day][key]["in"] == 110);
  CHECK(j["days"][day][key]["out"] == 55);
  CHECK(j["days"][day][key]["cache"] == 11);
  // 1 空格缩进（磁盘格式兼容）
  CHECK(raw->rfind("{\n \"days\"", 0) == 0);
  ::unlink(path.c_str());
}

static void test_time() {
  CHECK(util::time_util::beijing_date().size() == 10);
  CHECK(util::time_util::beijing_mmdd().size() == 4);
}

int main() {
  test_b64();
  test_sha256();
  test_uuid();
  test_aes_roundtrip();
  test_usage_store();
  test_time();
  std::printf("pass=%d fail=%d\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
