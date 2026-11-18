// L7 main — asio 协程 server（8787 正式口）+ 信号安全停机 + --extract-token
#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <thread>
#include "server/router.hpp"
#include "service/api_service.hpp"
#include "service/app_context.hpp"
#include "store/creds_store.hpp"
#include "transport/http_server.hpp"
#include "util/log.hpp"

namespace {
std::atomic<bool> g_shutdown{false};
std::function<void()> g_flush;
// 信号 handler 只置标志——handler 上下文做锁+磁盘 IO 不安全
void on_signal(int) { g_shutdown = true; }
} // namespace

int main(int argc, char** argv) {
  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "--extract-token") {
      auto cfg = zproxy::Config::from_env(0, nullptr);
      auto creds = zproxy::store::load_local_creds(cfg);
      if (!creds) {
        std::cerr << "无法读取或解密 " << cfg.creds_path << "（ZCode 未登录？）" << std::endl;
        return 1;
      }
      std::cout << creds->jwt << std::endl;
      std::cerr << "user_id: " << zproxy::domain::account_user_id_of(creds->jwt) << std::endl;
      return 0;
    }
  }

  auto ctx = std::make_unique<zproxy::service::AppContext>(zproxy::Config::from_env(argc, argv));
  auto& cfg = ctx->cfg;

  zproxy::util::log("zcode-proxy-cpp (asio) starting: http://" + cfg.host + ":" + std::to_string(cfg.port) +
                    " state_dir=" + cfg.state_dir + " web_dir=" + cfg.web_dir);
  zproxy::util::log("accounts source=" + ctx->pool.source() + " systemPromptBlocks=" +
                    std::to_string(ctx->sys.size()));

  ctx->usage.start_saver();
  g_flush = [&ctx] {
    if (!ctx) return;
    ctx->pool.flush_now(); // 内存账号表 → tokens.json
    ctx->usage.flush_now();
  };
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  std::signal(SIGHUP, on_signal);

  asio::io_context io;
  zproxy::http::HttpServer server(io);
  zproxy::server::Router router(*ctx);
  router.setup(server);

  // 停机监视：信号只置标志，收尾由本线程完成（不在信号上下文做 IO/锁）。
  // 先排空在途请求（此前立即 exit 掐断上传/SSE 流——客户端大量 EPIPE 的直接来源），再落盘退出
  std::thread([&] {
    while (!g_shutdown) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    int drain_s = zproxy::util::env::i64("ZPROXY_DRAIN_TIMEOUT_S", 30);
    int inflight = server.initiate_shutdown();
    if (inflight > 0) {
      zproxy::util::log("shutdown: draining " + std::to_string(inflight) +
                        " in-flight request(s), up to " + std::to_string(drain_s) + "s...");
      bool done = server.drain_wait(drain_s);
      zproxy::util::log(std::string("shutdown: drain ") + (done ? "complete" : "timeout, cutting remaining"));
    }
    zproxy::util::log("shutdown signal received, flushing...");
    if (g_flush) g_flush();
    std::exit(0); // flush 已同步完成；asio acceptor 随进程终止
  }).detach();

  zproxy::util::log("listening on " + cfg.host + ":" + std::to_string(cfg.port));
  asio::co_spawn(io, server.listen(cfg.host, cfg.port), asio::detached);
  io.run(); // 事件循环（阻塞至进程退出）
  return 0;
}
