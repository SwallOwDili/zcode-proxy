#include <chrono>
#include <cstdio>
#include <set>
#include "domain/account_pool.hpp"
using namespace zproxy;
int main() {
  std::string dir = "/tmp/zproxy-bench";
  ::system(("rm -rf " + dir + " && mkdir -p " + dir).c_str());
  Config cfg; cfg.state_dir = dir; cfg.creds_path = dir + "/none.json";
  { std::ofstream f(dir + "/tokens.json");
    f << "[";
    for (int i = 0; i < 100000; i++) { if (i) f << ","; f << "{\"name\":\"acc" << i << "\",\"jwt\":\"jwt" << i << "\"}"; }
    f << "]"; }
  store::TokensStore t(cfg.path("tokens.json"));
  store::PausedStore p(cfg.path("paused.json"));
  domain::AccountPool pool(cfg, t, p);
  std::printf("pool size=%zu\n", pool.size());
  // 预热
  for (int i = 0; i < 1000; i++) (void)pool.pick("", "", "GLM-5.3");
  constexpr int N = 1000000;
  auto t0 = std::chrono::steady_clock::now();
  uint64_t sink = 0;
  for (int i = 0; i < N; i++) { auto r = pool.pick("", "", "GLM-5.3"); sink += r->size(); }
  double ns = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count() / N;
  std::printf("10万账号 pick 平均: %.1f ns/op (sink=%llu)\n", ns, (unsigned long long)sink);
  return 0;
}
