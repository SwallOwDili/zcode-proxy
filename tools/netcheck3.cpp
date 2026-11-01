// netcheck3 — 用 zproxy 真实头集逐项二分定位连接失败
#include <cstdio>
#include "upstream/zcode_client.hpp"
using namespace zproxy;
using namespace zproxy::upstream;

int main() {
  domain::AccountPool::Lease l;
  l.valid = true;
  l.name = "t"; l.jwt = std::string(255, 'e'); // 假 JWT，尺寸对齐真实
  l.device_mid = util::uuid(); l.session_id = "session_" + util::uuid();
  l.region = "global"; l.fp_platform = "darwin-arm64"; l.fp_language = "zh-CN";
  l.app_version = "3.16.3";

  auto step = [&](const char* name, const Headers& h, const std::string& body) {
    auto r = upstream::http::post_json("https://zcode.z.ai", "/api/v1/zcode-plan/anthropic/v1/messages", h, body);
    std::printf("%-24s status=%d err=%s\n", name, r.status, r.error.c_str());
    return r.ok();
  };
  std::string small_body = R"({"model":"GLM-5.3-Flash","max_tokens":1,"messages":[{"role":"user","content":"hi"}]})";

  // 1) 仅 caller 头（buildUpstreamHeaders + auth）
  auto caller = build_upstream_caller(l);
  step("caller-only", caller, small_body);
  // 2) 合并后全头（zproxy 实际发送集）
  auto combined = combine_zcode_endpoint(caller, l.jwt, l.device_mid, l.app_version);
  step("combined-full", combined, small_body);
  // 3) 合并头 + 真实大小 body（注入 system 后 ~16KB）
  std::string big_body = R"({"model":"GLM-5.3-Flash","max_tokens":1,"system":[{"type":"text","text":")" +
                         std::string(9000, 'z') + R"("}],"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]})";
  step("combined-bigbody", combined, big_body);
  return 0;
}
