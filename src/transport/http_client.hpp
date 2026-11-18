// L6 transport — asio TLS 协程客户端：连接池 + chunked 解码 + SSE 流式
// + run_blocking：阻塞调用桥接（低频路径走线程池，不卡事件循环）
#pragma once
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>
#include <chrono>
#include <deque>
#include <mutex>
#include <thread>
#include <variant>
#include "nlohmann/json.hpp"
#include "util/log.hpp"

namespace zproxy::http {

using asio::ip::tcp;
using asio::awaitable;
using asio::use_awaitable;
using namespace asio::experimental::awaitable_operators;
using Headers = std::vector<std::pair<std::string, std::string>>;

struct HttpResponse {
  int status = 0;
  std::string content_type;
  std::string body;
  std::string error;
  bool delivered_any = false;      // 流式：至少一个 chunk 已递交给调用方（最终已写到客户端）
  bool stream_interrupted = false; // 流式：on_chunk 返回 false（客户端写失败/上游错误事件）主动断流
  bool ok() const { return error.empty() && status > 0; }
};

// ---------- TLS 上下文（verify_none 与 httplib 版一致） ----------
inline asio::ssl::context& tls_ctx() {
  static asio::ssl::context ctx(asio::ssl::context::tls_client);
  ctx.set_verify_mode(asio::ssl::verify_none);
  return ctx;
}

// ---------- per-host 空闲连接池（协程取-还，单连接串行使用） ----------
struct TlsConn {
  std::unique_ptr<asio::ssl::stream<tcp::socket>> stream;
  std::string host_port;
  bool broken_reuse = false;          // 流式中断：连接状态未知，不归还池
  int64_t idle_since = 0;             // 归还时间戳：空闲超过阈值的连接取出时直接弃用
};

class ConnPool {
public:
  static ConnPool& get() { static ConnPool p; return p; }
  // 上游网关对闲置 keep-alive 连接会静默丢弃（无 FIN/RST，实测 30s 阈值内也有死连接：
  // 写请求进黑洞 40-120s 后才以 EPIPE 暴露）——取出时空闲超过 max_idle 的连接直接弃用重建。
  // 另有兜底：池化连接在收到响应字节前失败时，调用方换全新连接透明重试一次（见 co_post_*）。
  std::shared_ptr<TlsConn> take(const std::string& key, int64_t max_idle_ms = 15'000) {
    std::lock_guard<std::mutex> lk(mu_);
    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
    for (auto it = idle_.begin(); it != idle_.end(); ++it) {
      if ((*it)->host_port != key) continue;
      auto c = std::move(*it);
      idle_.erase(it);
      if (now - c->idle_since > max_idle_ms) return nullptr; // 太旧：弃用，调用方新建
      return c;
    }
    return nullptr;
  }
  void give_back(std::shared_ptr<TlsConn> c) {
    std::lock_guard<std::mutex> lk(mu_);
    if (idle_.size() < 64) {
      c->idle_since = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
      idle_.push_back(std::move(c));
    }
  }

private:
  std::mutex mu_;
  std::deque<std::shared_ptr<TlsConn>> idle_;
};

// 连接+握手（30s race 超时；SNI 必须——WAF 指纹依赖）
inline asio::awaitable<std::shared_ptr<TlsConn>> dial(const std::string& host, const std::string& port) {
  using namespace asio::experimental::awaitable_operators;
  auto conn = std::make_shared<TlsConn>();
  conn->stream = std::make_unique<asio::ssl::stream<tcp::socket>>(
      co_await asio::this_coro::executor, tls_ctx());
  conn->host_port = host + ":" + port;
  auto& stream = *conn->stream;
  if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()))
    throw std::runtime_error("failed to set SNI hostname");
  tcp::resolver res(co_await asio::this_coro::executor);
  auto eps = co_await res.async_resolve(host, port, use_awaitable);
  asio::steady_timer timer(co_await asio::this_coro::executor);
  auto to_void = [](auto op) -> asio::awaitable<void> { co_await std::move(op); };
  timer.expires_after(std::chrono::seconds(30));
  co_await (to_void(asio::async_connect(stream.next_layer(), eps, use_awaitable)) ||
            timer.async_wait(use_awaitable));
  timer.expires_after(std::chrono::seconds(30));
  co_await (to_void(stream.async_handshake(asio::ssl::stream_base::client, use_awaitable)) ||
            timer.async_wait(use_awaitable));
  asio::error_code nec;
  stream.next_layer().set_option(asio::ip::tcp::no_delay(true), nec); // SSE 小帧免 Nagle 延迟
  co_return conn;
}

// base_url 携带的路径前缀（如 .../zcode-plan/anthropic）——拼接进每个请求路径
inline std::string prefix_of(const std::string& base_url) {
  auto pos = base_url.find("://");
  if (pos == std::string::npos) return "";
  auto slash = base_url.find('/', pos + 3);
  return slash == std::string::npos ? "" : base_url.substr(slash);
}
inline std::string full_path(const std::string& base_url, const std::string& path) {
  return prefix_of(base_url) + path;
}

inline std::string host_of(const std::string& base_url) {
  std::string rest = base_url;
  auto pos = rest.find("://");
  if (pos != std::string::npos) rest = rest.substr(pos + 3);
  auto slash = rest.find('/');
  return slash == std::string::npos ? rest : rest.substr(0, slash);
}
inline std::string host_only(const std::string& hp) {
  auto c = hp.rfind(':');
  return c == std::string::npos || hp.find(']') != std::string::npos ? hp : hp.substr(0, c);
}
inline std::string port_of(const std::string& hp, bool tls) {
  auto c = hp.rfind(':');
  if (c == std::string::npos || hp.find(']') != std::string::npos) return tls ? "443" : "80";
  return hp.substr(c + 1);
}

// 单次读 + 无数据超时（上游网关会静默挂起 keep-alive 连接——曾致协程永久挂、客户端无限等）
constexpr int kReadTimeoutSec = 300;

inline asio::awaitable<size_t> async_read_race(asio::ssl::stream<tcp::socket>& s, char* buf) {
  size_t n = co_await s.async_read_some(asio::buffer(buf, 16384), use_awaitable);
  co_return n;
}
inline asio::awaitable<size_t> async_read_exact_race(asio::ssl::stream<tcp::socket>& s, char* buf, size_t sz) {
  size_t n = co_await asio::async_read(s, asio::buffer(buf, sz), use_awaitable);
  co_return n;
}

// 响应头解析结果
struct RespHead {
  int status = 0;
  std::string content_type;
  bool chunked = false;
  size_t content_length = 0;
  std::vector<std::string> raw; // 原始头行（debug）
};

inline asio::awaitable<RespHead> read_resp_head(asio::ssl::stream<tcp::socket>& s) {
  std::string buf;
  char ch;
  while (buf.find("\r\n\r\n") == std::string::npos) {
    // 无数据超时：此前此处无超时，池化连接被静默丢弃时协程永久挂死、客户端无限等
    asio::steady_timer timer(s.get_executor());
    timer.expires_after(std::chrono::seconds(kReadTimeoutSec));
    std::variant<size_t, std::monostate> v =
        co_await (async_read_exact_race(s, &ch, 1) || timer.async_wait(use_awaitable));
    if (v.index() == 1) throw std::runtime_error("upstream read timeout (head)");
    buf += ch;
    if (buf.size() > 256 * 1024) throw std::runtime_error("resp headers too large");
  }
  RespHead out;
  auto first_eol = buf.find("\r\n");
  // "HTTP/1.1 200 OK"
  {
    std::string line = buf.substr(0, first_eol);
    auto sp = line.find(' ');
    out.status = std::atoi(line.c_str() + (sp == std::string::npos ? 0 : sp + 1));
  }
  size_t pos = first_eol + 2;
  while (pos < buf.size()) {
    auto eol = buf.find("\r\n", pos);
    std::string line = buf.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
    if (line.empty()) break;
    auto colon = line.find(':');
    if (colon != std::string::npos) {
      std::string k = line.substr(0, colon), v = line.substr(colon + 1);
      while (!v.empty() && (v[0] == ' ' || v[0] == '\t')) v.erase(0, 1);
      if (strcasecmp(k.c_str(), "content-type") == 0) out.content_type = v;
      if (strcasecmp(k.c_str(), "transfer-encoding") == 0 && v.find("chunked") != std::string::npos) out.chunked = true;
      if (strcasecmp(k.c_str(), "content-length") == 0) out.content_length = (size_t)std::stoull(v);
    }
    pos = eol + 2;
  }
  co_return out;
}

// 单次读 + 无数据超时（上游网关会静默挂起 keep-alive 连接——曾致协程永久挂、客户端无限等）
// （kReadTimeoutSec 与 race 读辅助已上移至 read_resp_head 之前）

inline asio::awaitable<std::string> read_some(asio::ssl::stream<tcp::socket>& s) {
  char buf[16384];
  asio::steady_timer timer(s.get_executor());
  timer.expires_after(std::chrono::seconds(kReadTimeoutSec));
  using namespace asio::experimental::awaitable_operators;
  auto v = co_await (async_read_race(s, buf) || timer.async_wait(use_awaitable));
  if (v.index() == 1) throw std::runtime_error("upstream read timeout (no data " + std::to_string(kReadTimeoutSec) + "s)");
  size_t n = std::get<0>(v);
  co_return std::string(buf, n);
}

inline asio::awaitable<std::string> read_line(asio::ssl::stream<tcp::socket>& s) {
  std::string line;
  char ch;
  while (true) {
    asio::steady_timer timer(s.get_executor());
    timer.expires_after(std::chrono::seconds(kReadTimeoutSec));
    std::variant<size_t, std::monostate> v =
        co_await (async_read_exact_race(s, &ch, 1) || timer.async_wait(use_awaitable));
    if (v.index() == 1) throw std::runtime_error("upstream read timeout (line)");
    if (ch == '\n') break;
    if (ch != '\r') line += ch;
    if (line.size() > 32) break;
  }
  co_return line;
}

// 带无数据超时的精确读：此前 chunk body / content-length body 多处裸 async_read 无超时，
// 上游静默挂起时协程永久卡死（客户端表现为无限等待后断开）
inline asio::awaitable<void> read_exact_timed(asio::ssl::stream<tcp::socket>& s, void* buf, size_t sz,
                                              const char* what) {
  if (sz == 0) co_return;
  asio::steady_timer timer(s.get_executor());
  timer.expires_after(std::chrono::seconds(kReadTimeoutSec));
  std::variant<size_t, std::monostate> v =
      co_await (async_read_exact_race(s, (char*)buf, sz) || timer.async_wait(use_awaitable));
  if (v.index() == 1)
    throw std::runtime_error(std::string("upstream read timeout (") + what + ")");
}

// ---------- 池化连接策略 ----------
// 实测日志：池内空闲 <15s 的连接也会被上游静默丢弃，写 33MB 请求进黑洞 40-120s 后才 EPIPE。
//  - 大 body（>1MB，主链路 33MB 级）不复用池：直接新建连接（握手 ~100ms 相对上传时间可忽略）
//  - 池化连接在收到任何响应字节之前失败 → 换全新连接透明重试一次（尚未发出任何响应，重试无副作用）
//  - 已收到响应头后的失败是真实中断，如实报错（交由上层 premature/重试语义处理）
constexpr size_t kMaxPooledBodyBytes = 1 * 1024 * 1024;

// POST JSON：全量缓冲（chunked 或 content-length 均处理）
inline asio::awaitable<HttpResponse> co_post_json(const std::string& base_url, const std::string& path,
                                                  const Headers& headers, const std::string& body) {
  HttpResponse out;
  std::string hp = host_of(base_url);
  for (int attempt = 0; attempt < 2; attempt++) {
    bool pooled = false;
    std::shared_ptr<TlsConn> conn;
    if (attempt == 0 && body.size() <= kMaxPooledBodyBytes) {
      conn = ConnPool::get().take(hp);
      pooled = (bool)conn;
    }
    if (!conn) {
      try {
        conn = co_await dial(host_only(hp), port_of(hp, true));
      } catch (const std::exception& e) {
        out.error = e.what();
        co_return out;
      }
    }
    auto& s = *conn->stream;
    std::string req = "POST " + path + " HTTP/1.1\r\nHost: " + host_only(hp) + "\r\n";
    for (auto& [k, v] : headers) req += k + ": " + v + "\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\nConnection: keep-alive\r\n\r\n" + body;
    bool head_done = false;
    try {
      co_await asio::async_write(s, asio::buffer(req), use_awaitable);
      auto head = co_await read_resp_head(s);
      head_done = true;
      out.status = head.status;
      out.content_type = head.content_type;
      if (head.chunked) {
        for (;;) {
          std::string szline = co_await read_line(s);
          size_t sz = std::stoull(szline, nullptr, 16);
          if (sz == 0) { co_await read_line(s); break; }
          std::string chunk(sz, '\0');
          co_await read_exact_timed(s, chunk.data(), sz, "chunk");
          out.body += chunk;
          co_await read_line(s); // 尾 \r\n
          if (out.body.size() > 64 * 1024 * 1024) throw std::runtime_error("body too large");
        }
      } else if (head.content_length) {
        out.body.resize(head.content_length);
        co_await read_exact_timed(s, out.body.data(), out.body.size(), "body");
      } else {
        out.body = co_await read_some(s); // close-delimited
      }
      ConnPool::get().give_back(conn);
      co_return out;
    } catch (const std::exception& e) {
      out.error = e.what(); // 连接破损：不归还
      if (head_done) co_return out;              // 上游已开始响应：真实中断，不重试
      if (!pooled || attempt == 1) co_return out; // 新建连接也失败：如实报错
      util::log("pooled upstream conn dead before response (" + out.error + "), redial fresh");
      out = HttpResponse{}; // 透明重试：尚未发出任何字节
    }
  }
  co_return out;
}

inline asio::awaitable<HttpResponse> co_get_json(const std::string& base_url, const std::string& path,
                                                 const Headers& headers) {
  HttpResponse out;
  std::string hp = host_of(base_url);
  for (int attempt = 0; attempt < 2; attempt++) {
    bool pooled = false;
    std::shared_ptr<TlsConn> conn;
    if (attempt == 0) {
      conn = ConnPool::get().take(hp);
      pooled = (bool)conn;
    }
    if (!conn) {
      try {
        conn = co_await dial(host_only(hp), port_of(hp, true));
      } catch (const std::exception& e) {
        out.error = e.what();
        co_return out;
      }
    }
    auto& s = *conn->stream;
    std::string req = "GET " + path + " HTTP/1.1\r\nHost: " + host_only(hp) + "\r\n";
    for (auto& [k, v] : headers) req += k + ": " + v + "\r\n";
    req += "Connection: keep-alive\r\n\r\n";
    bool head_done = false;
    try {
      co_await asio::async_write(s, asio::buffer(req), use_awaitable);
      auto head = co_await read_resp_head(s);
      head_done = true;
      out.status = head.status;
      out.content_type = head.content_type;
      if (head.content_length) {
        out.body.resize(head.content_length);
        co_await read_exact_timed(s, out.body.data(), out.body.size(), "body");
      } else {
        out.body = co_await read_some(s);
      }
      ConnPool::get().give_back(conn);
      co_return out;
    } catch (const std::exception& e) {
      out.error = e.what();
      if (head_done) co_return out;
      if (!pooled || attempt == 1) co_return out;
      util::log("pooled upstream conn dead before response (" + out.error + "), redial fresh");
      out = HttpResponse{};
    }
  }
  co_return out;
}

// POST 流式（SSE）：2xx 且 SSE 的 chunk 经 on_chunk 逐块回调；其余全量缓冲到 out.body
inline asio::awaitable<HttpResponse> co_post_stream(const std::string& base_url, const std::string& path,
                                                    const Headers& headers, const std::string& body,
                                                    const std::function<asio::awaitable<bool>(std::string_view)>& on_chunk) {
  HttpResponse out;
  std::string hp = host_of(base_url);
  for (int attempt = 0; attempt < 2; attempt++) {
    bool pooled = false;
    std::shared_ptr<TlsConn> conn;
    if (attempt == 0 && body.size() <= kMaxPooledBodyBytes) {
      conn = ConnPool::get().take(hp);
      pooled = (bool)conn;
    }
    if (!conn) {
      try {
        conn = co_await dial(host_only(hp), port_of(hp, true));
      } catch (const std::exception& e) {
        out.error = e.what();
        co_return out;
      }
    }
    auto& s = *conn->stream;
    std::string req = "POST " + path + " HTTP/1.1\r\nHost: " + host_only(hp) + "\r\n";
    for (auto& [k, v] : headers) req += k + ": " + v + "\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\nConnection: keep-alive\r\n\r\n" + body;
    bool head_done = false;
    try {
      co_await asio::async_write(s, asio::buffer(req), use_awaitable);
      auto head = co_await read_resp_head(s);
      head_done = true;
      out.status = head.status;
      out.content_type = head.content_type;
      bool streaming = out.status >= 200 && out.status < 300 &&
                       out.content_type.find("text/event-stream") != std::string::npos;
      if (streaming) {
        // 流式：chunked 解码逐块回调（on_chunk false = 中断）
        if (head.chunked) {
          for (;;) {
            std::string szline = co_await read_line(s);
            size_t sz = std::stoull(szline, nullptr, 16);
            if (sz == 0) { co_await read_line(s); break; }
            std::string chunk(sz, '\0');
            co_await read_exact_timed(s, chunk.data(), sz, "chunk");
            co_await read_line(s);
            if (on_chunk) {
              out.delivered_any = true;
              if (!co_await on_chunk(chunk)) { out.stream_interrupted = true; co_return out; } // 中断：丢弃连接
            }
          }
        } else if (head.content_length) {
          std::string rest;
          rest.resize(head.content_length);
          co_await read_exact_timed(s, rest.data(), rest.size(), "body");
          if (on_chunk) {
            out.delivered_any = true;
            if (!co_await on_chunk(rest)) { out.stream_interrupted = true; co_return out; }
          }
        }
        ConnPool::get().give_back(conn);
      } else {
        // 非 SSE：全量缓冲
        if (head.chunked) {
          for (;;) {
            std::string szline = co_await read_line(s);
            size_t sz = std::stoull(szline, nullptr, 16);
            if (sz == 0) { co_await read_line(s); break; }
            std::string chunk(sz, '\0');
            co_await read_exact_timed(s, chunk.data(), sz, "chunk");
            out.body += chunk;
            co_await read_line(s);
          }
        } else if (head.content_length) {
          out.body.resize(head.content_length);
          co_await read_exact_timed(s, out.body.data(), out.body.size(), "body");
        } else {
          out.body = co_await read_some(s);
        }
        ConnPool::get().give_back(conn);
      }
      co_return out;
    } catch (const std::exception& e) {
      out.error = e.what(); // 连接破损：不归还
      if (head_done) co_return out;              // 上游已开始响应：真实中断，不重试
      if (!pooled || attempt == 1) co_return out; // 新建连接也失败：如实报错
      util::log("pooled upstream conn dead before response (" + out.error + "), redial fresh");
      out = HttpResponse{}; // 透明重试：尚未发出任何字节
    }
  }
  co_return out;
}

// ---------- 阻塞调用桥接：admin/oauth/claim 等低频阻塞 HTTP 调用投线程池 ----------

// ---------- 阻塞调用桥接：admin 同步 handler（含阻塞上游调用）投线程执行 ----------
inline asio::awaitable<void> run_blocking(std::function<void()> f) {
  struct State {
    std::mutex mu;
    std::condition_variable cv;
    bool done = false;
    std::exception_ptr ep;
  };
  auto state = std::make_shared<State>();
  std::thread([f = std::move(f), state] {
    try { f(); }
    catch (...) { state->ep = std::current_exception(); }
    { std::lock_guard<std::mutex> lk(state->mu); state->done = true; }
    state->cv.notify_all();
  }).detach();
  asio::steady_timer timer(co_await asio::this_coro::executor);
  for (;;) {
    {
      std::lock_guard<std::mutex> lk(state->mu);
      if (state->done) break;
    }
    timer.expires_after(std::chrono::milliseconds(25));
    co_await timer.async_wait(asio::use_awaitable);
  }
  if (state->ep) std::rethrow_exception(state->ep);
}

} // namespace zproxy::http
