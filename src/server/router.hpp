// L6 server — 路由（asio http::Ctx 版全量；httplib 已退役）
#pragma once
#include "service/admin_service.hpp"
#include "service/api_service.hpp"
#include "service/app_context.hpp"
#include "service/chat_service.hpp"
#include "service/live_service.hpp"
#include "service/messages_service.hpp"
#include "transport/http_server.hpp"
#include "util/log.hpp"
#include "util/string_util.hpp"

namespace zproxy::server {

class Router {
public:
  explicit Router(service::AppContext& ctx) : ctx_(ctx), chat_(ctx), messages_(ctx), api_(ctx), admin_(ctx), live_(ctx) {}

  void setup(http::HttpServer& svr) {
    auto CO = [](auto fn) -> asio::awaitable<void> { co_await fn(); };
    // 鉴权
    if (!ctx_.cfg.client_token.empty()) {
      svr.route("", R"(.*))", [this](http::Ctx& c) -> asio::awaitable<void> {
        if (c.header("Authorization") != "Bearer " + ctx_.cfg.client_token) {
          c.set_status(401);
          c.set_content(R"({"error":{"message":"unauthorized"}})", "application/json");
          co_return;
        }
        co_return;
      });
    }
    auto wrap_sync = [](std::function<void(http::Ctx&)> h) {
      return [h](http::Ctx& c) -> asio::awaitable<void> {
        h(c);
        co_return;
      };
    };

    svr.route_sync("GET", R"(^/$)", [](http::Ctx& c) { redirect(c); });
    svr.route_sync("GET", R"(^/admin/?$)", [](http::Ctx& c) { redirect(c); });
    svr.route_sync("GET", R"(^/admin/(assets/.+)$)", [this](http::Ctx& c) { serve_web(c); }); // 捕获含 assets/ 前缀
    svr.route_sync("GET", R"(^/admin/([\w-]+\.html)$)", [this](http::Ctx& c) { serve_web(c); });
    svr.route_sync("GET", R"(^/favicon\.ico$)", [](http::Ctx& c) { c.set_status(404); });

    svr.route("POST", R"(^/v1/chat/completions$)", [this](http::Ctx& c) -> asio::awaitable<void> { co_await chat_.handle(c); });
    svr.route("POST", R"(^/chat/completions$)", [this](http::Ctx& c) -> asio::awaitable<void> { co_await chat_.handle(c); });
    svr.route("POST", R"(^/v1/messages$)", [this](http::Ctx& c) -> asio::awaitable<void> { co_await messages_.handle(c); });
    svr.route("POST", R"(^/messages$)", [this](http::Ctx& c) -> asio::awaitable<void> { co_await messages_.handle(c); });
    svr.route_sync("GET", R"(^/v1/models$)", [this](http::Ctx& c) { c.set_json(api_.models_json()); });
    svr.route_sync("GET", R"(^/health$)", [this](http::Ctx& c) { c.set_json(api_.health_json()); });
    svr.route_sync("GET", R"(^/admin/rate$)", [this](http::Ctx& c) { c.set_json(live_.rate_json()); });

    admin_.setup(svr);
    live_setup(svr);
  }

private:
  static void redirect(http::Ctx& c) {
    c.set_status(302);
    c.set_header("Location", "/admin/index.html");
  }
  void serve_web(http::Ctx& c) {
    std::string rel = c.params.empty() ? "" : c.params.back();
    std::string abs_root = absolutize(ctx_.cfg.web_dir);
    std::string target = absolutize(util::fs::join(abs_root, rel));
    if (abs_root.empty() || target.rfind(abs_root, 0) != 0 || !util::fs::is_file(target)) {
      c.set_status(404);
      c.set_content("not found", "text/plain; charset=utf-8");
      return;
    }
    auto data = util::fs::read_file(target);
    if (!data) {
      c.set_status(404);
      c.set_content("not found", "text/plain; charset=utf-8");
      return;
    }
    c.set_content(*data, mime_for(target));
    c.set_header("Cache-Control", "no-store");
  }
  static std::string absolutize(std::string p) {
    if (p.empty()) return p;
    if (p[0] != '/') p = util::fs::join(util::fs::cwd(), p);
    std::vector<std::string> st;
    for (auto& s : util::split(p, '/')) {
      if (s.empty() || s == ".") continue;
      if (s == "..") { if (!st.empty()) st.pop_back(); continue; }
      st.push_back(s);
    }
    std::string out;
    for (auto& s : st) out += "/" + s;
    return out;
  }
  static std::string mime_for(const std::string& p) {
    if (util::ends_with(p, ".html")) return "text/html; charset=utf-8";
    if (util::ends_with(p, ".css")) return "text/css; charset=utf-8";
    if (util::ends_with(p, ".js")) return "text/javascript; charset=utf-8";
    if (util::ends_with(p, ".svg")) return "image/svg+xml";
    if (util::ends_with(p, ".png")) return "image/png";
    if (util::ends_with(p, ".ico")) return "image/x-icon";
    return "application/octet-stream";
  }
  void live_setup(http::HttpServer& svr) {
    // SSE live（保留兼容端点；前端已用轮询）
    svr.route("GET", R"(^/admin/live$)", [this](http::Ctx& c) -> asio::awaitable<void> {
      c.set_json(live_.rate_json());
      co_return;
    });
  }

  service::AppContext& ctx_;
  service::ChatService chat_;
  service::MessagesService messages_;
  service::ApiService api_;
  service::AdminService admin_;
  service::LiveService live_;
};

} // namespace zproxy::server
