// L5 service — GET /admin/live：SSE 实时推送（替代 Node /ws/live WebSocket；消息形状一致）
//   {type:"req", ts, model, account, status, in, out, cache, ms}
//   {type:"rate", active, inPerSec, outPerSec, reqsPerMin, clients}   每 2s
#pragma once
#include <atomic>
#include <chrono>
#include <cmath>
#include <deque>
#include <mutex>
#include <set>
#include <thread>
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "service/app_context.hpp"
#include "util/time_util.hpp"

namespace zproxy::service {

class LiveService {
public:
  explicit LiveService(AppContext& ctx) : ctx_(ctx) {
    ctx.live_rate_getter = [this] { return rate_json(); };
    // recordRecent → 广播到所有 SSE 客户端
    ctx_.recent.set_broadcast([this](const nlohmann::json& msg) { broadcast(msg); });
    // 2s 定时 rate 推送（libc++ 无 jthread，用 atomic 停止位）
    rate_thread_ = std::thread([this] {
      while (!stop_.load()) {
        for (int i = 0; i < 20 && !stop_.load(); i++) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (stop_.load()) break;
        if (client_count() == 0) continue;
        broadcast(rate_msg());
      }
    });
  }

  void handle(httplib::Response& res) {
    res.set_chunked_content_provider(
        "text/event-stream; charset=utf-8",
        [this](size_t offset, httplib::DataSink& sink) -> bool {
          if (offset > 0) return false;
          {
            std::lock_guard<std::mutex> lk(mu_);
            sinks_.insert(&sink);
          }
          // 连接即推 rate
          std::string r = "data: " + rate_msg().dump() + "\n\n";
          sink.write(r.data(), r.size());
          // 阻塞至断开（广播与 janitor 负责 done）
          while (sink.is_writable()) std::this_thread::sleep_for(std::chrono::milliseconds(200));
          std::lock_guard<std::mutex> lk(mu_);
          sinks_.erase(&sink);
          return false;
        });
  }

  ~LiveService() {
    stop_ = true;
    if (rate_thread_.joinable()) rate_thread_.join();
  }

  // 轮询端点用：当前速率快照（与 SSE rate 消息同源同形）
  nlohmann::json rate_json() { return rate_msg(); }

private:
  int client_count() {
    std::lock_guard<std::mutex> lk(mu_);
    return (int)sinks_.size();
  }
  void broadcast(const nlohmann::json& msg) {
    std::string data = "data: " + msg.dump() + "\n\n";
    // req 消息入速率窗口（Node：所有广播都采样，req 携带 in/out）
    if (msg.value("type", "") == "req") {
      std::lock_guard<std::mutex> lk(wmu_);
      window_.push_back(Sample{util::time_util::now_ms(), msg.value("in", (int64_t)0), msg.value("out", (int64_t)0)});
    }
    std::lock_guard<std::mutex> lk(mu_);
    for (auto* s : sinks_) s->write(data.data(), data.size());
  }
  nlohmann::json rate_msg() {
    // 60s 窗口：req 消息贡献 in/out；rate 消息计数但不贡献流量
    int64_t now = util::time_util::now_ms();
    int reqs = 0;
    int64_t in = 0, out = 0;
    {
      std::lock_guard<std::mutex> lk(wmu_);
      for (auto it = window_.begin(); it != window_.end();) {
        if (now - it->ts > 60'000) it = window_.erase(it);
        else { reqs++; in += it->in; out += it->out; ++it; }
      }
      window_.push_back(Sample{now, 0, 0});
    }
    // active = 60s 窗口有请求（与数据窗口同口径；颜色语义，数值不归零）
    bool active = reqs > 0;
    return {
      {"type", "rate"}, {"active", active},
      {"totalPerSec", round1((double)(in + out) / 60.0)}, // 消耗速率 = 输入+输出
      {"inPerSec", round1((double)in / 60.0)},
      {"outPerSec", round1((double)out / 60.0)},
      {"reqsPerMin", reqs},
      {"clients", client_count()},
    };
  }
  static double round1(double v) { return std::round(v * 10.0) / 10.0; }

  struct Sample { int64_t ts, in, out; };
  AppContext& ctx_;
  std::mutex mu_;
  std::set<httplib::DataSink*> sinks_;
  std::mutex wmu_;
  std::deque<Sample> window_;
  std::atomic<bool> stop_{false};
  std::thread rate_thread_;
};

} // namespace zproxy::service
