// netcheck4 — 完全复刻 zcode_client.call 的 post_stream 用法
#include <cstdio>
#include "upstream/zcode_client.hpp"
using namespace zproxy;
using namespace zproxy::upstream;
namespace zhttp = ::zproxy::http;

int main() {
  domain::AccountPool::Lease l;
  l.valid = true;
  l.name = "t"; l.jwt = std::string(255, 'e');
  l.device_mid = util::uuid(); l.session_id = "session_" + util::uuid();
  l.fp_platform = "darwin-arm64"; l.fp_language = "zh-CN"; l.app_version = "3.16.3";

  auto caller = build_upstream_caller(l);
  auto combined = combine_zcode_endpoint(caller, l.jwt, l.device_mid, l.app_version);
  std::string body = R"({"model":"GLM-5.3-Flash","max_tokens":1,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]})";

  int chunks = 0;
  auto on_chunk = [&](std::string_view sv) -> bool { chunks++; return true; };
  auto r = upstream::http::post_stream("https://zcode.z.ai", "/api/v1/zcode-plan/anthropic/v1/messages", combined, body, on_chunk);
  std::printf("post_stream: status=%d err=%s chunks=%d body=%.120s\n", r.status, r.error.c_str(), chunks,
              r.body.c_str());
  return 0;
}
