// L6 transport — HTTP 上下文抽象：Service 层唯一接触面（与 httplib 解耦）
#pragma once
#include <functional>
#include <map>
#include <string>
#include <vector>
#include <asio.hpp>
#include <asio/use_awaitable.hpp>
#include "nlohmann/json.hpp"

namespace zproxy::http {

using asio::awaitable;

struct Ctx {
  // 请求
  std::string method, path, body;
  std::vector<std::pair<std::string, std::string>> headers;
  std::vector<std::string> params; // 路由捕获组
  std::map<std::string, std::string> query;

  std::string header(const std::string& k) const {
    for (auto& [hk, hv] : headers)
      if (strcasecmp(hk.c_str(), k.c_str()) == 0) return hv;
    return "";
  }
  bool has_query(const std::string& k) const { return query.count(k) > 0; }
  std::string get_query(const std::string& k, const std::string& dflt = "") const {
    auto it = query.find(k);
    return it != query.end() ? it->second : dflt;
  }

  // 响应（同步端点直接填；SSE 端点走 sse_write）
  int status = 200;
  bool responded = false;
  std::string res_body, res_content_type = "application/json";
  std::vector<std::pair<std::string, std::string>> res_headers;

  void set_content(std::string b, std::string ct) {
    responded = true;
    res_body = std::move(b);
    res_content_type = ct;
  }
  void set_json(nlohmann::json j) { set_content(j.dump(), "application/json"); }
  void set_status(int s) {
    status = s;
    responded = true;
  }
  void set_header(const std::string& k, const std::string& v) { res_headers.emplace_back(k, v); }

  // SSE 模式：handler 调用 writer 写流；server 收尾看 sse_used（writer 被真正用过才算 SSE）。
  std::function<awaitable<bool>(std::string_view)> sse_writer;
  std::function<awaitable<void>()> sse_final; // chunked 终止块
  bool sse_used = false;
};

} // namespace zproxy::http
