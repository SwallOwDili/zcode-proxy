#include <cstdio>
#include "protocol/openai_to_anthropic.hpp"
using namespace zproxy;
int main() {
  nlohmann::json in = {
    {"model","dc"},{"stream",true},
    {"messages", nlohmann::json::array({
      {{"role","system"},{"content","be nice"}},
      {{"role","user"},{"content","hi"}},
    })},
  };
  auto out = protocol::translate_request(in, "M");
  std::printf("keys: [");
  for (auto& k : out.items()) std::printf("%s ", k.key().c_str());
  std::printf("]\n");
  if (out.contains("system")) std::printf("system=%s\n", out["system"].dump().c_str());
  std::printf("msgs=%zu\n", out["messages"].size());
  return 0;
}
