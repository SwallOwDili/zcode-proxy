#include <cstdio>
#include "upstream/http.hpp"
using namespace zproxy;
int main() {
  using namespace zproxy::upstream;
  // 1) 小 body POST
  auto r1 = http::post_json("https://zcode.z.ai", "/api/v1/zcode-plan/anthropic/v1/messages",
                            {{"content-type","application/json"},{"anthropic-version","2023-06-01"}},
                            "{\"model\":\"x\",\"max_tokens\":1,\"messages\":[]}");
  std::printf("small POST: status=%d err=%s\n", r1.status, r1.error.c_str());
  // 2) 大 body (16KB) POST
  std::string big(16384, 'a');
  auto r2 = http::post_json("https://zcode.z.ai", "/api/v1/zcode-plan/anthropic/v1/messages",
                            {{"content-type","application/json"}},
                            "{\"pad\":\"" + big + "\"}");
  std::printf("big POST: status=%d err=%s\n", r2.status, r2.error.c_str());
  return 0;
}
