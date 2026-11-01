// L5 service — /v1/chat/completions：asio 协程直通版
//   上游 SSE chunk → 协程回调 → 直接写客户端 socket：无队列、无 worker 线程、零内核切换。
//   透传重试 / 3009 可调重试 / 提前断流冷却 / AI SDK 严格字段 等语义全部保留。
#pragma once
#include <asio.hpp>
#include <asio/use_awaitable.hpp>
#include "nlohmann/json.hpp"
#include "protocol/anthropic_to_openai.hpp"
#include "protocol/model_map.hpp"
#include "protocol/openai_to_anthropic.hpp"
#include "service/app_context.hpp"
#include "transport/http_ctx.hpp"
#include "util/log.hpp"
#include "util/time_util.hpp"

namespace zproxy::service {

namespace detail {

inline nlohmann::json error_body(const std::string& message, const char* type, const nlohmann::json& code = nullptr) {
  nlohmann::json err = {{"message", message}, {"type", type}};
  if (!code.is_null()) err["code"] = code;
  return {{"error", err}};
}
inline int biz_status(const nlohmann::json& j) {
  int64_t code = 0;
  try { code = j.at("code").get<int64_t>(); } catch (...) {}
  return (code == 1005 || code == 1113 || code == 1302) ? 429 : 502;
}
inline std::string biz_message(const nlohmann::json& j) {
  return "upstream code " + (j.contains("code") ? j["code"].dump() : std::string("?")) + ": " +
         j.value("msg", j.value("message", std::string()));
}

} // namespace detail

class ChatService {
public:
  explicit ChatService(AppContext& ctx) : ctx_(ctx) {}

  // 协程入口（asio server 调用）
  asio::awaitable<void> handle(http::Ctx& ctx) {
    nlohmann::json openai_body;
    try { openai_body = nlohmann::json::parse(ctx.body); } catch (...) {
      ctx.set_status(400);
      ctx.set_content(detail::error_body("invalid JSON body", "zproxy_bad_request").dump(), "application/json");
      co_return;
    }
    std::string raw_model = openai_body.value("model", std::string());
    std::string model = protocol::map_model(ctx_.modelmap, ctx_.cfg.default_model, raw_model);
    nlohmann::json anthropic_body = protocol::translate_request(openai_body, model);
    std::string id = "chatcmpl-" + util::uuid();
    std::string session_key;
    if (ctx_.routing.mode() == "cache") session_key = domain::affinity_key(anthropic_body);
    auto t0 = std::chrono::steady_clock::now();

    if (anthropic_body.value("stream", false)) co_await stream_chat(ctx, anthropic_body, model, id, session_key, t0);
    else co_await plain_chat(ctx, anthropic_body, model, id, session_key, t0);
  }

private:
  asio::awaitable<bool> write_sse_frame(http::Ctx& ctx, const std::string& frame) {
    co_return co_await ctx.sse_writer(frame);
  }

  // ---------- 流式：上游 chunk 协程直通 ----------
  asio::awaitable<void> stream_chat(http::Ctx& ctx, const nlohmann::json& anthropic_body,
                                    const std::string& model, const std::string& id,
                                    const std::string& session_key, std::chrono::steady_clock::time_point t0) {
    const std::string out_model = model;
    int64_t start_wall = util::time_util::now_ms();
    std::string avoid;
    ::mkdir((ctx_.cfg.state_dir + "/logs").c_str(), 0755); // cfg_→ctx_ 由下方修正
    std::string dump_path = ctx_.cfg.state_dir + "/logs/sse-" + id + ".log";
    FILE* dump = std::fopen(dump_path.c_str(), "w"); // 记录上游原始 chunk 与发给客户端的帧

    for (int attempt = 0; attempt < 2; attempt++) {
      protocol::StreamTranslator tr(id, out_model);
      protocol::SseParser parser;
      bool saw_text = false;
      std::string error_event;
      std::string account;
      int64_t first_delta_wall = 0;
      int64_t tps_id = ctx_.tps.run_start("");

      int64_t sent_frames = 0, sent_bytes = 0;
      // 上游 chunk → 翻译 → 直写客户端（无队列无线程）
      auto on_chunk = [&](std::string_view sv) -> asio::awaitable<bool> {
        if (dump) std::fwrite(sv.data(), 1, sv.size(), dump);
        for (auto& ev : parser.feed(sv)) {
          tr.bump_events();
          auto out = tr.feed(ev.event, ev.data);
          for (auto& c : out.chunks) {
            std::string body = c.dump();
            std::string frame;
            frame.reserve(body.size() + 10);
            frame += "data: ";
            frame += body;
            frame += "\n\n";
            if (dump) std::fwrite(frame.data(), 1, frame.size(), dump);
            if (!co_await write_sse_frame(ctx, frame)) {
              util::log("SSE WRITE FAILED to client: frame=" + std::to_string(sent_frames) + " bytes=" + std::to_string(sent_bytes));
              if (dump) std::fclose(dump);
              co_return false;
            }
            sent_frames++; sent_bytes += (int64_t)frame.size();
          }
          if (out.saw_text) {
            if (!first_delta_wall) first_delta_wall = util::time_util::now_ms();
            saw_text = true;
            ctx_.tps.run_delta(tps_id, 1);
          }
          if (!out.error.empty()) co_return false; // error 事件：断上游
        }
        co_return true;
      };

      auto call = co_await ctx_.client.call_co(anthropic_body, session_key, attempt == 0 ? "" : avoid, on_chunk);
      account = call.account_name;
      ctx_.tps.run_end(tps_id, 0);
      int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
      bool premature = call.is_stream() && !tr.saw_stop();

      auto sse_err = [&](const std::string& msg) -> asio::awaitable<void> {
        std::string body;
        body += "data: " + protocol::openai_chunk(id, out_model, {{"role", "assistant"}, {"content", ""}}).dump() + "\n\n";
        body += "data: " + protocol::StreamTranslator::error_chunk(id, out_model, msg).dump() + "\n\n";
        body += "data: [DONE]\n\n";
        co_await write_sse_frame(ctx, body);
      };
      auto retry_or = [&](bool can_retry, const std::string& msg) -> asio::awaitable<bool> {
        if (!saw_text && attempt == 0) { avoid = account; co_return true; }
        co_await sse_err(msg);
        co_return false;
      };

      if (call.business_error.is_object()) {
        if (co_await retry_or(!saw_text && attempt == 0, detail::biz_message(call.business_error))) continue;
        domain::RecentEntry e; e.kind = "chat/stream"; e.model = model; e.account = account;
        e.status = detail::biz_status(call.business_error); e.ms = ms;
        ctx_.record(e);
        co_return;
      }
      if (call.no_account) {
        co_await sse_err("no ZCode account available (check /health)");
        domain::RecentEntry e; e.kind = "chat/stream"; e.model = model; e.account = account;
        e.status = 503; e.ms = ms;
        ctx_.record(e);
        co_return;
      }
      if (!error_event.empty()) {
        if (co_await retry_or(!saw_text && attempt == 0, error_event)) continue;
        domain::RecentEntry e; e.kind = "chat/stream"; e.model = model; e.account = account;
        e.status = 502; e.ms = ms;
        ctx_.record(e);
        co_return;
      }
      if (call.status == 0 || call.status < 200 || call.status >= 300) {
        int status = (call.status == 405 || call.status == 429) ? 502 : call.status;
        co_await sse_err("upstream " + std::to_string(call.status) + ": " + call.body.substr(0, 500));
        domain::RecentEntry e; e.kind = "chat/stream"; e.model = model; e.account = account;
        e.status = status; e.ms = ms;
        ctx_.record(e);
        co_return;
      }
      if (premature) {
        if (!account.empty()) ctx_.pool.mark_cooldown(account, 30'000, model);
        if (co_await retry_or(!saw_text && attempt == 0,
                              "upstream closed stream prematurely after " + std::to_string(tr.event_count()) + " events"))
          continue;
        domain::RecentEntry e; e.kind = "chat/stream"; e.model = model; e.account = account;
        e.status = 502; e.ms = ms; e.note = "premature-close";
        ctx_.record(e);
        co_return;
      }

      // 成功：finish + usage + [DONE]
      int64_t in_tok = 0, out_tok = 0, cache_tok = 0;
      tr.usage_numbers(in_tok, out_tok, cache_tok);
      ctx_.tps.run_end(tps_id, out_tok);
      ctx_.usage_record(account, model, in_tok, out_tok, cache_tok);
      domain::RecentEntry e; e.kind = "chat/stream"; e.model = model; e.account = account;
      e.status = 200; e.in_tok = in_tok; e.out_tok = out_tok; e.cache_tok = cache_tok; e.ms = ms;
      e.has_ttft = first_delta_wall > 0;
      if (e.has_ttft) e.ttft = first_delta_wall - start_wall;
      ctx_.record(e);
      for (auto& c : tr.finalize()) {
        std::string body = c.dump();
        std::string frame;
        frame.reserve(body.size() + 10);
        frame += "data: ";
        frame += body;
        frame += "\n\n";
        co_await write_sse_frame(ctx, frame);
      }
      co_await write_sse_frame(ctx, "data: [DONE]\n\n");
      util::log("SSE COMPLETE: id=" + id + " frames=" + std::to_string(sent_frames) +
                " bytes=" + std::to_string(sent_bytes) + " DONE sent");
      if (dump) std::fclose(dump);
      co_return;
    }
  }

  // ---------- 非流式 ----------
  asio::awaitable<void> plain_chat(http::Ctx& ctx, const nlohmann::json& anthropic_body,
                                   const std::string& model, const std::string& id,
                                   const std::string& session_key, std::chrono::steady_clock::time_point t0) {
    auto call = co_await ctx_.client.call_co(anthropic_body, session_key, "", nullptr);
    int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - t0).count();
    domain::RecentEntry e; e.kind = "chat"; e.model = model; e.account = call.account_name; e.ms = ms;

    if (call.business_error.is_object()) {
      e.status = detail::biz_status(call.business_error);
      ctx_.record(e);
      ctx.set_status(e.status);
      ctx.set_content(detail::error_body(detail::biz_message(call.business_error), "zproxy_upstream_business_error",
                                         call.business_error["code"]).dump(), "application/json");
      co_return;
    }
    if (call.no_account) {
      e.status = 503;
      ctx_.record(e);
      ctx.set_status(503);
      ctx.set_content(detail::error_body("no ZCode account available (check /health)", "zproxy_no_account").dump(),
                      "application/json");
      co_return;
    }
    if (call.status == 0 || call.status < 200 || call.status >= 300) {
      int status = (call.status == 405 || call.status == 429) ? 502 : call.status;
      e.status = status;
      ctx_.record(e);
      ctx.set_status(status);
      ctx.set_content(detail::error_body("upstream " + std::to_string(call.status) + ": " + call.body.substr(0, 500),
                                         "zproxy_upstream_error", call.status).dump(), "application/json");
      co_return;
    }
    nlohmann::json data;
    try { data = nlohmann::json::parse(call.body); } catch (...) { data = nullptr; }
    if (!data.is_object()) {
      e.status = 502;
      ctx_.record(e);
      ctx.set_status(502);
      ctx.set_content(detail::error_body("upstream returned invalid JSON", "zproxy_upstream_error").dump(),
                      "application/json");
      co_return;
    }
    if (data.contains("code") && !data["code"].is_null() && data.value("code", (int64_t)0) != 0 &&
        !(data.contains("content") && data["content"].is_array())) {
      int64_t code = data.value("code", (int64_t)0);
      if (code == 1005 || code == 1113 || code == 1302)
        if (!call.account_name.empty()) ctx_.pool.mark_cooldown(call.account_name, ctx_.cfg.cooldown_429_ms, model);
      e.status = (code == 1005 || code == 1113 || code == 1302) ? 429 : 502;
      ctx_.record(e);
      ctx.set_status(e.status);
      ctx.set_content(detail::error_body("upstream code " + data["code"].dump() + ": " + data.value("msg", std::string()),
                                         "zproxy_upstream_business_error", data["code"]).dump(), "application/json");
      co_return;
    }
    nlohmann::json out = protocol::anthropic_to_openai_completion(data, id, model);
    int64_t in_tok = 0, out_tok = 0, cache_tok = 0;
    if (data.contains("usage") && data["usage"].is_object()) {
      in_tok = data["usage"].value("input_tokens", (int64_t)0);
      out_tok = data["usage"].value("output_tokens", (int64_t)0);
      cache_tok = data["usage"].value("cache_read_input_tokens", (int64_t)0);
    }
    ctx_.usage_record(call.account_name, model, in_tok, out_tok, cache_tok);
    e.status = 200; e.in_tok = in_tok; e.out_tok = out_tok; e.cache_tok = cache_tok;
    ctx_.record(e);
    ctx.set_content(out.dump(), "application/json");
  }

  AppContext& ctx_;
};

} // namespace zproxy::service
