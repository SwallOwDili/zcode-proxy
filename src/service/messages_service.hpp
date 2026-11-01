// L5 service — /v1/messages：Anthropic 协议透传（asio 协程直通：原始字节转发 + 用量旁路统计）
#pragma once
#include <asio.hpp>
#include <asio/use_awaitable.hpp>
#include "protocol/sse_parser.hpp"
#include "service/app_context.hpp"
#include "transport/http_ctx.hpp"
#include "service/chat_service.hpp" // detail::biz_* 复用
#include "util/log.hpp"

namespace zproxy::service {

class MessagesService {
public:
  explicit MessagesService(AppContext& ctx) : ctx_(ctx) {}

  asio::awaitable<void> handle(http::Ctx& ctx) {
    nlohmann::json body;
    try { body = nlohmann::json::parse(ctx.body); } catch (...) {
      ctx.set_status(400);
      ctx.set_content(anthropic_error("invalid JSON body").dump(), "application/json");
      co_return;
    }
    std::string().swap(ctx.body); // 原始 body 已解析进 DOM：立即释放（1M 上下文时省一整份）
    std::string session_key;
    if (ctx_.routing.mode() == "cache") session_key = domain::affinity_key(body);
    auto t0 = std::chrono::steady_clock::now();

    protocol::SseParser tap;
    int64_t in_tok = 0, out_tok = 0;
    bool got_out = false;
    std::string model = body.value("model", std::string());
    int64_t tps_id = ctx_.tps.run_start("");

    auto on_chunk = [&](std::string_view sv) -> asio::awaitable<bool> {
      // 旁路统计 + 原始字节直写
      for (auto& ev : tap.feed(sv)) {
        if (ev.data == "[DONE]") continue;
        nlohmann::json d;
        try { d = nlohmann::json::parse(ev.data); } catch (...) { continue; }
        if (!d.is_object()) continue;
        std::string type = !ev.event.empty() ? ev.event : d.value("type", "");
        if (type == "message_start") {
          const nlohmann::json* u = nullptr;
          if (d.contains("message") && d["message"].is_object() && d["message"].contains("usage"))
            u = &d["message"]["usage"];
          else if (d.contains("usage")) u = &d["usage"];
          if (u) in_tok = u->value("input_tokens", (int64_t)0);
        } else if (type == "content_block_delta") {
          const auto& dd = d.value("delta", nlohmann::json::object());
          std::string dtype = dd.value("type", "");
          int64_t n = 1;
          if (dtype == "text_delta") n = (int64_t)dd.value("text", std::string()).size();
          else if (dtype == "thinking_delta") n = (int64_t)dd.value("thinking", std::string()).size();
          else if (dtype == "input_json_delta") n = (int64_t)dd.value("partial_json", std::string()).size();
          ctx_.tps.run_delta(tps_id, (n + 3) / 4);
        } else if (type == "message_delta") {
          if (d.contains("usage") && d["usage"].is_object()) {
            int64_t o = d["usage"].value("output_tokens", (int64_t)0);
            if (o > 0) { out_tok = o; got_out = true; }
          }
        }
      }
      co_return co_await ctx.sse_writer(sv); // 原始字节直通
    };

    auto call = co_await ctx_.client.call_co(body, session_key, "", on_chunk);
    int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - t0).count();
    ctx_.tps.run_end(tps_id, got_out ? out_tok : 0);

    if (call.is_stream() && call.status >= 200 && call.status < 300) {
      // SSE 成功：usage 记账（message_start/message_delta 提取值）
      if (in_tok > 0 || got_out)
        ctx_.usage_record(call.account_name, model, in_tok, out_tok, 0);
      // record 已在 call_co 外无法拦截——透传路径记账如上；recent 记录：
      domain::RecentEntry e; e.kind = "messages"; e.model = model;
      e.account = call.account_name; e.status = 200; e.in_tok = in_tok; e.out_tok = out_tok; e.ms = ms;
      ctx_.record(e);
      co_return; // SSE 流已直通写完，server 收尾
    }

    // 非 SSE / 错误
    if (!call.business_error.is_null()) {
      nlohmann::json err = {{"type", "error"},
                            {"error", {{"type", "upstream_business_error"},
                                       {"message", detail::biz_message(call.business_error)}}}};
      domain::RecentEntry e; e.kind = "messages"; e.model = model;
      e.account = call.account_name; e.status = detail::biz_status(call.business_error); e.ms = ms;
      ctx_.record(e);
      ctx.set_status(e.status);
      ctx.set_content(err.dump(), "application/json");
      co_return;
    }
    if (call.no_account) {
      domain::RecentEntry e; e.kind = "messages"; e.model = model; e.status = 503; e.ms = ms;
      ctx_.record(e);
      ctx.set_status(503);
      ctx.set_content(anthropic_error("no ZCode account available (check /health)").dump(), "application/json");
      co_return;
    }
    if (call.status == 0 || call.status < 200 || call.status >= 300) {
      domain::RecentEntry e; e.kind = "messages"; e.model = model;
      e.account = call.account_name; e.status = call.status == 0 ? 502 : call.status; e.ms = ms;
      ctx_.record(e);
      ctx.set_status(e.status);
      ctx.set_content(call.body.empty() ? anthropic_error("upstream error").dump() : call.body,
                      std::string(call.content_type.empty() ? "application/json" : call.content_type));
      co_return;
    }
    // 非流式成功：usage + recent + 原样转发
    {
      int64_t in2 = 0, out2 = 0;
      try {
        auto j = nlohmann::json::parse(call.body);
        if (j.is_object() && j.contains("usage")) {
          in2 = j["usage"].value("input_tokens", (int64_t)0);
          out2 = j["usage"].value("output_tokens", (int64_t)0);
        }
      } catch (...) {}
      if (in2 > 0 || out2 > 0) ctx_.usage_record(call.account_name, model, in2, out2, 0);
      domain::RecentEntry e; e.kind = "messages"; e.model = model;
      e.account = call.account_name; e.status = 200; e.in_tok = in2; e.out_tok = out2; e.ms = ms;
      ctx_.record(e);
    }
    ctx.set_content(call.body, std::string(call.content_type.empty() ? "application/json" : call.content_type));
  }

private:
  static nlohmann::json anthropic_error(const std::string& msg) {
    return {{"type", "error"}, {"error", {{"type", "zproxy_error"}, {"message", msg}}}};
  }
  AppContext& ctx_;
};

} // namespace zproxy::service
