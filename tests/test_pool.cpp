// tests — AccountPool 内存权威架构：启动恢复 / 索引 / 定时刷盘 / creds 回退
#include <cstdio>
#include <chrono>
#include <fstream>
#include <set>
#include <thread>
#include "domain/account_pool.hpp"
#include "store/paused_store.hpp"
#include "store/tokens_store.hpp"

using namespace zproxy;
static int g_pass = 0, g_fail = 0;
#define CHECK(cond)                                                                                                    \
  do {                                                                                                                 \
    if (cond) { g_pass++; } else { g_fail++; std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); }              \
  } while (0)

static void write_tokens(const std::string& path, const std::string& content) {
  std::ofstream f(path);
  f << content;
}

int main() {
  std::string dir = "/tmp/zproxy-test-pool";
  ::system(("rm -rf " + dir + " && mkdir -p " + dir).c_str());
  Config cfg;
  cfg.state_dir = dir;
  cfg.creds_path = dir + "/nonexistent-creds.json";
  cfg.sync_ms = 1000; // 测试用短间隔

  // ---- 1. 启动恢复：tokens.json → 内存 ----
  write_tokens(dir + "/tokens.json", R"([{"name":"a","jwt":"jwt-a"},{"name":"b","jwt":"jwt-b"}])");
  {
    store::TokensStore tokens(cfg.path("tokens.json"));
    store::PausedStore paused(cfg.path("paused.json"));
    domain::AccountPool pool(cfg, tokens, paused);
    CHECK(pool.size() == 2);
    CHECK(pool.source() == "tokens");

    // 2. lease/release（O(1) 索引路径）
    for (int i = 0; i < 3; i++) {
      auto lease = pool.lease("a");
      CHECK(lease.valid);
      CHECK(lease.jwt == "jwt-a");
      CHECK(!lease.device_mid.empty() && !lease.session_id.empty());
      pool.release("a");
    }
    CHECK(pool.get("a").has_value());
    CHECK(!pool.get("zzz").has_value());

    // 3. upsert 新账号 → 内存即生效；flush 落盘
    domain::Account c;
    c.name = "c"; c.jwt = "jwt-c";
    CHECK(pool.upsert(std::move(c)));
    CHECK(pool.size() == 3);
    pool.flush_now();
    auto raw = util::fs::read_file(cfg.path("tokens.json"));
    CHECK(raw.has_value() && raw->find("\"c\"") != std::string::npos && raw->find("jwt-c") != std::string::npos);

    // 4. remove（swap-with-last 索引一致性）
    CHECK(pool.remove("b"));
    CHECK(pool.size() == 2);
    CHECK(pool.get("b") == std::nullopt);
    CHECK(pool.get("c").has_value());   // swap 后索引仍正确
    CHECK(pool.get("a").has_value());
    auto lease2 = pool.lease("c");
    CHECK(lease2.valid);
    pool.release("c");
    pool.flush_now();
    auto raw2 = util::fs::read_file(cfg.path("tokens.json"));
    CHECK(raw2.has_value() && raw2->find("jwt-b") == std::string::npos);

    // 5. 改名（upsert old_name）
    domain::Account renamed;
    renamed.name = "alpha"; renamed.jwt = "jwt-a";
    CHECK(pool.upsert(std::move(renamed), "a"));
    CHECK(pool.get("a") == std::nullopt);
    CHECK(pool.get("alpha").has_value());
    pool.flush_now();
    auto raw3 = util::fs::read_file(cfg.path("tokens.json"));
    CHECK(raw3.has_value() && raw3->find("\"alpha\"") != std::string::npos);

    // 6. 内存权威：外部删文件不影响运行中的池
    ::unlink((dir + "/tokens.json").c_str());
    CHECK(pool.size() == 2);
    CHECK(pool.source() == "tokens");
  }

  // ---- 7. 无 tokens.json → creds 回退 ----
  {
    store::TokensStore tokens(cfg.path("tokens.json"));
    store::PausedStore paused(cfg.path("paused.json"));
    domain::AccountPool pool(cfg, tokens, paused);
    CHECK(pool.size() == 0); // creds 路径不存在 → 空池
    CHECK(pool.source().empty());
  }

  // ---- 8. 同 JWT 去重 upsert（原地更新）----
  {
    write_tokens(dir + "/tokens.json", R"([{"name":"a","jwt":"jwt-a"}])");
    store::TokensStore tokens(cfg.path("tokens.json"));
    store::PausedStore paused(cfg.path("paused.json"));
    domain::AccountPool pool(cfg, tokens, paused);
    domain::Account dup;
    dup.name = "a2"; dup.jwt = "jwt-a"; // 同 jwt → 原地更新，不追加
    CHECK(pool.upsert(std::move(dup)));
    CHECK(pool.size() == 1);
    pool.flush_now();
    auto raw = util::fs::read_file(cfg.path("tokens.json"));
    CHECK(raw.has_value() && raw->find("a2") != std::string::npos);
  }

  // ---- 9. 就绪表：冷却摘除 / 到期回收 / 轮转 / avoid ----
  {
    write_tokens(dir + "/tokens.json",
                 R"([{"name":"a","jwt":"jwt-a"},{"name":"b","jwt":"jwt-b"},{"name":"c","jwt":"jwt-c"}])");
    store::TokensStore tokens(cfg.path("tokens.json"));
    store::PausedStore paused(cfg.path("paused.json"));
    domain::AccountPool pool(cfg, tokens, paused);
    // 轮转分布：多次 pick 覆盖全部健康账号
    std::set<std::string> picked;
    for (int i = 0; i < 9; i++) {
      auto n = pool.pick("", "", "GLM-5.3");
      CHECK(n.has_value());
      picked.insert(*n);
    }
    CHECK(picked.size() == 3);

    // 冷却摘除：a 进入模型冷却 → pick("GLM-5.3") 不再返回 a
    pool.mark_cooldown("a", 60'000, "GLM-5.3");
    for (int i = 0; i < 6; i++) {
      auto n = pool.pick("", "", "GLM-5.3");
      CHECK(n.has_value() && *n != "a");
    }
    // 其他模型（无模型冷却桶）a 仍可用
    auto n2 = pool.pick("", "", "GLM-4.5-Air");
    CHECK(n2.has_value());

    // 账号级冷却 → 全模型摘除
    pool.mark_cooldown("b", 60'000);
    for (int i = 0; i < 6; i++) {
      auto n3 = pool.pick("", "", "GLM-5.3");
      CHECK(n3.has_value() && *n3 != "b");
    }

    // 全冷却 → fallback「照样试」语义（仍返回账号）
    pool.mark_cooldown("c", 60'000);
    auto n4 = pool.pick("", "", "GLM-5.3");
    CHECK(n4.has_value());

    // avoid：单账号场景下 avoid 自己 → null
    // （构造单账号池验证）
    std::string dir2 = dir + "-2";
    ::system(("rm -rf " + dir2 + " && mkdir -p " + dir2).c_str());
    Config cfg2 = cfg;
    cfg2.state_dir = dir2;
    write_tokens(dir2 + "/tokens.json", R"([{"name":"solo","jwt":"jwt-s"}])");
    store::TokensStore t2(cfg2.path("tokens.json"));
    store::PausedStore p2(cfg2.path("paused.json"));
    domain::AccountPool pool2(cfg2, t2, p2);
    auto n5 = pool2.pick("", "solo", "GLM-5.3");
    CHECK(n5.has_value() && *n5 == "solo"); // avoid 唯一账号时仍返回（对齐 Node：pool 只有一个时 tied 轮转仍可能选中）

    // 到期回收：短冷却 → sync 线程 1s 内重建 → 账号回归
    pool2.mark_cooldown("solo", 1500);
    auto n6 = pool2.pick("", "", "GLM-5.3"); // 立即 pick：就绪表已摘除 → fallback 返回
    CHECK(n6.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(2600)); // 冷却 1.5s 过期 + sync 1s 重建
    auto n7 = pool2.pick("", "", "GLM-5.3");
    CHECK(n7.has_value() && *n7 == "solo"); // 回收后正常轮转命中
  }

  std::printf("pass=%d fail=%d\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
