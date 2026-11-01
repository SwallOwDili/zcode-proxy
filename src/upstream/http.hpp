// L4 upstream — HTTP 客户端封装（cpp-httplib + OpenSSL；每请求独立连接，SSE 流式回调）
//
// 注意（httplib 0.64 语义）：Client(host, port) 构造是明文 HTTP-only；
// SSL 必须用 Client("scheme://host[:port]") 通用构造。这里统一走 scheme_host_port 形式，
// 并保留 base_url 的路径前缀（如 .../zcode-plan/anthropic）拼接到每个请求路径前。
#pragma once
#include <httplib.h> // CPPHTTPLIB_OPENSSL_SUPPORT 由 CMake 全局定义
#include <functional>
#include <map>
#include <optional>
#include <string>
#include "nlohmann/json.hpp"
#include "util/log.hpp"

namespace zproxy::upstream {

using Headers = std::vector<std::pair<std::string, std::string>>; // 保序（WAF 可能关心头序）

struct HttpResponse {
  int status = 0;
  std::string content_type;
  std::string body; // 全量缓冲（JSON / 小响应；流式走 stream 回调不落这里）
  std::string error; // 网络层错误
  bool ok() const { return error.empty() && status > 0; }
};

struct ClientHandle {
  std::unique_ptr<httplib::Client> cli;
  std::string prefix; // base_url 携带的路径前缀
};

// 解析 scheme://host[:port][/prefix] 并构造 SSL 感知客户端
inline ClientHandle make_client(const std::string& base_url, int64_t read_timeout_sec = 600,
                                int64_t connect_timeout_sec = 30) {
  std::string scheme = "https", rest = base_url;
  auto pos = base_url.find("://");
  if (pos != std::string::npos) {
    scheme = base_url.substr(0, pos);
    rest = base_url.substr(pos + 3);
  }
  std::string hostport = rest, prefix;
  auto slash = rest.find('/');
  if (slash != std::string::npos) {
    hostport = rest.substr(0, slash);
    prefix = rest.substr(slash);
    if (prefix.size() > 1 && prefix.back() == '/') prefix.pop_back();
  }
  ClientHandle h;
  h.cli = std::make_unique<httplib::Client>(scheme + "://" + hostport);
  h.prefix = prefix;
  h.cli->enable_server_certificate_verification(false); // 本地代理场景；上游 WAF 校验与证书无关
  h.cli->set_connection_timeout(connect_timeout_sec, 0);
  h.cli->set_read_timeout(read_timeout_sec, 0);
  h.cli->set_write_timeout(60, 0);
  h.cli->set_keep_alive(true);
  return h;
}

inline std::string full_path(const ClientHandle& h, const std::string& path) {
  return h.prefix + path;
}

inline httplib::Headers to_httplib_headers(const Headers& in) {
  httplib::Headers out;
  for (auto& [k, v] : in) out.emplace(k, v);
  return out;
}

namespace http {

inline std::map<std::string, ClientHandle>& client_for_cache() {
  thread_local std::map<std::string, ClientHandle> cache;
  return cache;
}
// 连接复用：每 worker 线程每 base_url 持有一条 keep-alive 连接（httplib Client 非线程安全，
// thread_local 保证单线程访问）。省掉每请求完整 TLS 握手。
inline ClientHandle& client_for(const std::string& base_url) {
  auto& cache = client_for_cache();
  auto it = cache.find(base_url);
  if (it == cache.end()) it = cache.emplace(base_url, make_client(base_url)).first;
  return it->second;
}
inline void invalidate_client(const std::string& base_url) {
  thread_local std::map<std::string, ClientHandle>& cache = client_for_cache();
  cache.erase(base_url);
}

// POST JSON（全量缓冲响应）
inline HttpResponse post_json(const std::string& base_url, const std::string& path, const Headers& headers,
                              const std::string& body, int64_t read_timeout_sec = 600) {
  HttpResponse out;
  auto& h = client_for(base_url);
  auto res = h.cli->Post(full_path(h, path), to_httplib_headers(headers), body, "application/json");
  if (!res) { // 连接可能失效：重建一次再试（此时请求未发出任何数据，安全）
    invalidate_client(base_url);
    auto& h2 = client_for(base_url);
    res = h2.cli->Post(full_path(h2, path), to_httplib_headers(headers), body, "application/json");
    if (!res) { out.error = httplib::to_string(res.error()); return out; }
  }
  out.status = res->status;
  if (res->has_header("Content-Type")) out.content_type = res->get_header_value("Content-Type");
  out.body = std::move(res->body);
  return out;
}

inline HttpResponse get_json(const std::string& base_url, const std::string& path, const Headers& headers,
                             int64_t read_timeout_sec = 30) {
  HttpResponse out;
  auto& h = client_for(base_url);
  auto res = h.cli->Get(full_path(h, path), to_httplib_headers(headers));
  if (!res) {
    invalidate_client(base_url);
    auto& h2 = client_for(base_url);
    res = h2.cli->Get(full_path(h2, path), to_httplib_headers(headers));
    if (!res) { out.error = httplib::to_string(res.error()); return out; }
  }
  out.status = res->status;
  if (res->has_header("Content-Type")) out.content_type = res->get_header_value("Content-Type");
  out.body = std::move(res->body);
  return out;
}

// POST 流式：on_chunk 逐块接收 SSE；JSON 体（错误/业务错误/非流式响应）全量缓冲到 out.body。
// 通用 Client 的 Post 无 ResponseHandler+Receiver 组合重载（0.64），ContentReceiver 阶段拿不到
// status/content-type —— 因此按内容嗅探分发：首块以 '{' 开头 = JSON → 缓冲；否则 = SSE → on_chunk。
inline HttpResponse post_stream(const std::string& base_url, const std::string& path, const Headers& headers,
                                const std::string& body,
                                const std::function<bool(std::string_view)>& on_chunk) {
  HttpResponse out;
  auto& h = client_for(base_url);
  bool sse_mode = false;
  bool decided = false;
  std::string sniff;
  auto handler = [&](const char* data, size_t len) -> bool {
    if (!decided) {
      sniff.append(data, len);
      // 等到可判定：出现 '{'（JSON）或 '\n'（SSE 帧分隔）或攒够 64B
      if (sniff.size() < 64 && sniff.find('{') == std::string::npos && sniff.find('\n') == std::string::npos)
        return true;
      decided = true;
      sse_mode = !sniff.empty() && sniff[0] != '{';
      if (on_chunk && sse_mode) return on_chunk(std::string_view(sniff));
      out.body.append(sniff);
      return true;
    }
    if (sse_mode) return on_chunk ? on_chunk(std::string_view(data, len)) : true;
    out.body.append(data, len);
    return true;
  };
  auto res = h.cli->Post(full_path(h, path), to_httplib_headers(headers), body, "application/json", handler);
  if (!res && !decided && sniff.empty() && out.body.empty()) { // 尚无任何响应数据：连接失效，重建重试一次
    invalidate_client(base_url);
    auto& h2 = client_for(base_url);
    res = h2.cli->Post(full_path(h2, path), to_httplib_headers(headers), body, "application/json", handler);
  }
  if (!res) { out.error = httplib::to_string(res.error()); return out; }
  out.status = res->status;
  if (res->has_header("Content-Type")) out.content_type = res->get_header_value("Content-Type");
  return out;
}

} // namespace http
} // namespace zproxy::upstream
