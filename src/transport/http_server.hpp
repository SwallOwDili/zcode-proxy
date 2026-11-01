// L6 transport — asio 协程化 HTTP/1.1 server（极简：parse / keep-alive / SSE close-delimited）
#pragma once
#include <asio.hpp>
#include <asio/use_awaitable.hpp>
#include <atomic>
#include <functional>
#include <regex>
#include "http_ctx.hpp"
#include "util/log.hpp"

namespace zproxy::http {

using asio::ip::tcp;
using asio::awaitable;

struct Route {
  std::string method; // GET/POST/... 空=任意
  std::regex path_re;
  std::function<asio::awaitable<void>(Ctx&)> handler;
};

class HttpServer {
public:
  explicit HttpServer(asio::io_context& io) : io_(io) {}

  void route(const std::string& method, const std::string& path_re,
             std::function<asio::awaitable<void>(Ctx&)> h) {
    routes_.push_back({method, std::regex(path_re), std::move(h)});
  }
  // 同步便捷路由（非协程 handler 直接填 ctx）
  void route_sync(const std::string& method, const std::string& path_re,
                  std::function<void(Ctx&)> h) {
    route(method, path_re, [h](Ctx& c) -> awaitable<void> {
      h(c);
      co_return;
    });
  }

  asio::awaitable<void> listen(const std::string& host, int port) {
    tcp::acceptor acc(io_);
    tcp::endpoint ep(asio::ip::make_address(host), (unsigned short)port);
    acc.open(ep.protocol());
    acc.set_option(asio::socket_base::reuse_address(true));
    acc.bind(ep);
    acc.listen(asio::socket_base::max_listen_connections);
    util::log("asio listening on " + host + ":" + std::to_string(port));
    for (;;) {
      auto socket = std::make_shared<tcp::socket>(co_await acc.async_accept(asio::use_awaitable));
      asio::co_spawn(io_, session(socket), asio::detached);
    }
  }

private:
  static asio::awaitable<std::string> read_until_headers(tcp::socket& s, asio::streambuf& buf) {
    std::string headers;
    char c;
    while (headers.find("\r\n\r\n") == std::string::npos) {
      co_await asio::async_read(s, asio::buffer(&c, 1), asio::use_awaitable);
      headers += c;
      if (headers.size() > 64 * 1024) throw std::runtime_error("headers too large");
    }
    co_return headers;
  }

  asio::awaitable<void> session(std::shared_ptr<tcp::socket> sock) {
    asio::streambuf buf;
    try {
      util::log("session opened fd=" + std::to_string(sock->native_handle()));
      for (;;) { // keep-alive 循环
        // ---- 请求头 ----
        std::string raw = co_await read_until_headers(*sock, buf);
        auto line_end = raw.find("\r\n");
        std::string reqline = raw.substr(0, line_end);
        auto sp1 = reqline.find(' ');
        auto sp2 = reqline.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos) break;
        std::string version = sp2 == std::string::npos ? "HTTP/1.0" : reqline.substr(sp2 + 1);
        bool http10 = version.find("1.0") != std::string::npos;
        Ctx ctx;
        ctx.method = reqline.substr(0, sp1);
        std::string target = reqline.substr(sp1 + 1, sp2 - sp1 - 1);
        auto qpos = target.find('?');
        ctx.path = url_decode(qpos == std::string::npos ? target : target.substr(0, qpos)); // 路径解码（%20 等）
        if (qpos != std::string::npos) {
          for (auto& kv : util_split(target.substr(qpos + 1), '&')) {
            auto eq = kv.find('=');
            if (eq == std::string::npos) continue;
            ctx.query[url_decode(kv.substr(0, eq))] = url_decode(kv.substr(eq + 1));
          }
        }
        size_t content_length = 0;
        {
          size_t pos = line_end + 2;
          while (pos < raw.size()) {
            auto eol = raw.find("\r\n", pos);
            std::string line = raw.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
            if (line.empty()) break;
            auto colon = line.find(':');
            if (colon != std::string::npos) {
              std::string k = line.substr(0, colon), v = line.substr(colon + 1);
              while (!v.empty() && v[0] == ' ') v.erase(0, 1);
              ctx.headers.emplace_back(k, v);
              if (strcasecmp(k.c_str(), "content-length") == 0) content_length = (size_t)std::stoull(v);
            }
            pos = eol + 2;
          }
        }
        if (content_length > 8 * 1024 * 1024) {
          Ctx err;
          err.set_status(413);
          err.set_content(R"({"error":{"message":"payload too large (8MB limit) - reduce conversation history"}})", "application/json");
          co_await write_simple(*sock, err, false);
          break;
        }
        // Expect: 100-continue：客户端等 interim 响应再发 body（undici 对大 body 会用）
        for (auto& [hk, hv] : ctx.headers)
          if (strcasecmp(hk.c_str(), "expect") == 0 && strcasecmp(hv.c_str(), "100-continue") == 0) {
            std::string cont = "HTTP/1.1 100 Continue\r\n\r\n";
            co_await asio::async_write(*sock, asio::buffer(cont), asio::use_awaitable);
            break;
          }
        // ---- body ----
        ctx.body.resize(content_length);
        if (content_length) co_await asio::async_read(*sock, asio::buffer(ctx.body), asio::use_awaitable);

        util::log("request " + ctx.method + " " + ctx.path + " bodylen=" + std::to_string(ctx.body.size()));
        // ---- 路由 ----
        Route* matched = nullptr;
        for (auto& r : routes_) {
          if (!r.method.empty() && r.method != ctx.method) continue;
          std::smatch m;
          if (std::regex_search(ctx.path, m, r.path_re)) {
            for (size_t i = 1; i < m.size(); i++) ctx.params.push_back(m[i].str());
            matched = &r;
            break;
          }
        }
        // keep-alive 语义按版本：1.1 默认 keep-alive（除非 close）；1.0 默认 close（除非 keep-alive）
        std::string conn_hdr = header_of(ctx.headers, "connection");
        bool keep_alive = http10 ? ieq(conn_hdr, "keep-alive") : !ieq(conn_hdr, "close");
        // SSE writer 装配：首次写时惰性发响应头（close-delimited）
        bool sse_headers_sent = false;
        ctx.sse_writer = [sock, &sse_headers_sent, &ctx](std::string_view data) -> asio::awaitable<bool> {
          ctx.sse_used = true;
          if (!sse_headers_sent) {
            std::string head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\n"
                               "Cache-Control: no-cache\r\nConnection: close\r\n\r\n";
            asio::error_code ec;
            co_await asio::async_write(*sock, asio::buffer(head), asio::redirect_error(asio::use_awaitable, ec));
            if (ec) co_return false;
            sse_headers_sent = true;
          }
          asio::error_code ec;
          co_await asio::async_write(*sock, asio::buffer(data), asio::redirect_error(asio::use_awaitable, ec));
          co_return !ec;
        };
        std::string handler_err;
        try {
          if (!matched) {
            ctx.set_status(404);
            ctx.set_content(R"({"error":{"message":"no route"}})", "application/json");
          } else {
            ctx.set_header("Connection", keep_alive ? "keep-alive" : "close");
            co_await matched->handler(ctx);
          }
        } catch (const std::exception& e) {
          handler_err = e.what();
          util::log(std::string("handler error: ") + handler_err);
          if (!ctx.responded) {
            ctx.set_status(500);
            ctx.set_content(nlohmann::json({{"error", {{"message", handler_err}}}}).dump(), "application/json");
          }
        }
        util::log("handler done " + ctx.path + " status=" + std::to_string(ctx.status) + " sse=" + std::to_string((bool)ctx.sse_writer));
        // 协程体内写响应（错误/兜底统一在此）
        if (!ctx.sse_used) co_await write_simple(*sock, ctx, keep_alive && handler_err.empty());
        else {
          if (ctx.sse_final) co_await ctx.sse_final(); // chunked 终止块
          asio::error_code ec;
          sock->shutdown(tcp::socket::shutdown_send, ec);
        }
        if (!keep_alive || !handler_err.empty() || ctx.sse_used) break;
      }
    } catch (const std::exception&) {
      // 客户端断开/解析失败：结束连接
    }
    asio::error_code ec;
    sock->shutdown(tcp::socket::shutdown_both, ec);
    sock->close(ec);
  }

  // SSE：handler 通过 ctx.sse_writer 写流（writer 内部直接写 socket），此处仅收尾
  static asio::awaitable<void> write_sse(tcp::socket& s, Ctx& ctx) {
    asio::error_code ec;
    s.shutdown(tcp::socket::shutdown_send, ec);
    co_return;
  }

  static asio::awaitable<void> write_simple(tcp::socket& s, Ctx& c, bool keep_alive) {
    std::string out = "HTTP/1.1 " + std::to_string(c.status) + " " + reason(c.status) + "\r\n";
    out += "Content-Length: " + std::to_string(c.res_body.size()) + "\r\n";
    bool has_conn = false;
    for (auto& [k, v] : c.res_headers) if (strcasecmp(k.c_str(), "connection") == 0) has_conn = true;
    if (!has_conn) out += "Connection: " + std::string(keep_alive ? "keep-alive" : "close") + "\r\n";
    for (auto& [k, v] : c.res_headers) out += k + ": " + v + "\r\n";
    if (c.res_headers.empty() || !has_ct(c)) out += "Content-Type: " + c.res_content_type + "\r\n";
    out += "\r\n";
    out += c.res_body;
    co_await asio::async_write(s, asio::buffer(out), asio::use_awaitable);
  }

  static bool has_ct(const Ctx& c) {
    for (auto& [k, v] : c.res_headers) if (strcasecmp(k.c_str(), "content-type") == 0) return true;
    return false;
  }
  static std::string reason(int s) {
    switch (s) {
      case 200: return "OK"; case 302: return "Found"; case 400: return "Bad Request";
      case 401: return "Unauthorized"; case 404: return "Not Found";
      case 429: return "Too Many Requests"; case 500: return "Internal Server Error";
      case 502: return "Bad Gateway"; case 503: return "Service Unavailable";
      default: return "OK";
    }
  }
  static std::string header_of(const std::vector<std::pair<std::string, std::string>>& h, const char* k) {
    for (auto& [hk, hv] : h) if (strcasecmp(hk.c_str(), k) == 0) return hv;
    return "";
  }
  static bool ieq(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) return false;
    return true;
  }
  static std::vector<std::string> util_split(const std::string& s, char d) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) { if (c == d) { out.push_back(cur); cur.clear(); } else cur += c; }
    out.push_back(cur);
    return out;
  }
  static std::string url_decode(const std::string& in) {
    std::string out;
    for (size_t i = 0; i < in.size(); i++) {
      if (in[i] == '%' && i + 2 < in.size()) {
        out += (char)std::stoi(in.substr(i + 1, 2), nullptr, 16);
        i += 2;
      } else if (in[i] == '+') out += ' ';
      else out += in[i];
    }
    return out;
  }

  asio::io_context& io_;
  std::vector<Route> routes_;
};

} // namespace zproxy::http
