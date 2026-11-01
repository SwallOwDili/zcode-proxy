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
  // 上游网关对闲置超阈值的 keep-alive 连接会静默丢弃（无 FIN/RST）——
  // 取出时空闲超过 max_idle 的连接直接弃用重建（多付一次 TLS 握手 ~100ms，
  // 换取永不把半死连接交给读操作去挂死）。阈值 < 网关空闲超时即安全。
  std::shared_ptr<TlsConn> take(const std::string& key, int64_t max_idle_ms = 30'000) {
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
    co_await asio::async_read(s, asio::buffer(&ch, 1), use_awaitable);
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
constexpr int kReadTimeoutSec = 300;

inline asio::awaitable<size_t> async_read_race(asio::ssl::stream<tcp::socket>& s, char* buf) {
  size_t n = co_await s.async_read_some(asio::buffer(buf, 16384), use_awaitable);
  co_return n;
}
inline asio::awaitable<size_t> async_read_exact_race(asio::ssl::stream<tcp::socket>& s, char* buf, size_t sz) {
  size_t n = co_await asio::async_read(s, asio::buffer(buf, sz), use_awaitable);
  co_return n;
}

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

// POST JSON：全量缓冲（chunked 或 content-length 均处理）
inline asio::awaitable<HttpResponse> co_post_json(const std::string& base_url, const std::string& path,
                                                  const Headers& headers, const std::string& body) {
  HttpResponse out;
  std::string hp = host_of(base_url);
  auto conn = ConnPool::get().take(hp);
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
  try {
    co_await asio::async_write(s, asio::buffer(req), use_awaitable);
    auto head = co_await read_resp_head(s);
    out.status = head.status;
    out.content_type = head.content_type;
    if (head.chunked) {
      for (;;) {
        std::string szline = co_await read_line(s);
        size_t sz = std::stoull(szline, nullptr, 16);
        if (sz == 0) { co_await read_line(s); break; }
        std::string chunk(sz, '\0');
        co_await asio::async_read(s, asio::buffer(chunk), use_awaitable);
        out.body += chunk;
        co_await read_line(s); // 尾 \r\n
        if (out.body.size() > 64 * 1024 * 1024) throw std::runtime_error("body too large");
      }
    } else if (head.content_length) {
      out.body.resize(head.content_length);
      co_await asio::async_read(s, asio::buffer(out.body), use_awaitable);
    } else {
      out.body = co_await read_some(s); // close-delimited
    }
    ConnPool::get().give_back(conn);
  } catch (const std::exception& e) {
    out.error = e.what(); // 连接破损：不归还
  }
  co_return out;
}

inline asio::awaitable<HttpResponse> co_get_json(const std::string& base_url, const std::string& path,
                                                 const Headers& headers) {
  HttpResponse out;
  std::string hp = host_of(base_url);
  auto conn = ConnPool::get().take(hp);
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
  try {
    co_await asio::async_write(s, asio::buffer(req), use_awaitable);
    auto head = co_await read_resp_head(s);
    out.status = head.status;
    out.content_type = head.content_type;
    if (head.content_length) {
      out.body.resize(head.content_length);
      {
        asio::steady_timer timer(s.get_executor());
        timer.expires_after(std::chrono::seconds(kReadTimeoutSec));
        std::variant<size_t, std::monostate> v = co_await (
            async_read_exact_race(s, out.body.data(), out.body.size()) || timer.async_wait(use_awaitable));
        if (v.index() == 1) throw std::runtime_error("upstream read timeout (body)");
      }
    } else {
      out.body = co_await read_some(s);
    }
    ConnPool::get().give_back(conn);
  } catch (const std::exception& e) {
    out.error = e.what();
  }
  co_return out;
}

// POST 流式（SSE）：2xx 且 SSE 的 chunk 经 on_chunk 逐块回调；其余全量缓冲到 out.body
inline asio::awaitable<HttpResponse> co_post_stream(const std::string& base_url, const std::string& path,
                                                    const Headers& headers, const std::string& body,
                                                    const std::function<asio::awaitable<bool>(std::string_view)>& on_chunk) {
  HttpResponse out;
  std::string hp = host_of(base_url);
  auto conn = ConnPool::get().take(hp);
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
  bool streaming = false;
  try {
    co_await asio::async_write(s, asio::buffer(req), use_awaitable);
    auto head = co_await read_resp_head(s);
    out.status = head.status;
    out.content_type = head.content_type;
    streaming = out.status >= 200 && out.status < 300 &&
                out.content_type.find("text/event-stream") != std::string::npos;
    if (streaming) {
      // 流式：chunked 解码逐块回调（on_chunk false = 中断）
      if (head.chunked) {
        for (;;) {
          std::string szline = co_await read_line(s);
          size_t sz = std::stoull(szline, nullptr, 16);
          if (sz == 0) { co_await read_line(s); break; }
          std::string chunk(sz, '\0');
          co_await asio::async_read(s, asio::buffer(chunk), use_awaitable);
          co_await read_line(s);
          if (on_chunk && !co_await on_chunk(chunk)) co_return out; // 中断：直接丢弃连接
        }
      } else if (head.content_length) {
        std::string rest;
        rest.resize(head.content_length);
        {
          asio::steady_timer timer(s.get_executor());
          timer.expires_after(std::chrono::seconds(kReadTimeoutSec));
          std::variant<size_t, std::monostate> v = co_await (
              async_read_exact_race(s, rest.data(), rest.size()) || timer.async_wait(use_awaitable));
          if (v.index() == 1) throw std::runtime_error("upstream read timeout (body)");
        }
        if (on_chunk) co_await on_chunk(rest);
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
          {
            asio::steady_timer timer(s.get_executor());
            timer.expires_after(std::chrono::seconds(kReadTimeoutSec));
            std::variant<size_t, std::monostate> v =
                co_await (async_read_exact_race(s, chunk.data(), sz) || timer.async_wait(use_awaitable));
            if (v.index() == 1) throw std::runtime_error("upstream read timeout (chunk)");
          }
          out.body += chunk;
          co_await read_line(s);
        }
      } else if (head.content_length) {
        out.body.resize(head.content_length);
        co_await asio::async_read(s, asio::buffer(out.body), use_awaitable);
      } else {
        out.body = co_await read_some(s);
      }
      ConnPool::get().give_back(conn);
    }
  } catch (const std::exception& e) {
    out.error = e.what();
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
