// L4 protocol — Anthropic 响应 → OpenAI 响应（非流式 + 流式状态机；纯函数/零 IO）
#pragma once
#include <map>
#include <optional>
#include <string>
#include "nlohmann/json.hpp"
#include "protocol/sse_parser.hpp"
#include "util/time_util.hpp"
#include "util/uuid.hpp"

namespace zproxy::protocol {

// null-safe 字符串提取：上游字段缺失/为 null 时给默认值（nlohmann value() 遇 null 会抛）
inline std::string safe_str(const nlohmann::json& j, const char* key, const std::string& dflt = "") {
  if (j.is_object() && j.contains(key) && j[key].is_string()) return j[key].get<std::string>();
  return dflt;
}

// stop_reason 映射（未知 → "stop" 由调用方兜底）
inline std::string map_stop_reason(const std::string& sr) {
  if (sr == "end_turn") return "stop";
  if (sr == "stop_sequence") return "stop";
  if (sr == "tool_use") return "tool_calls";
  if (sr == "max_tokens") return "length";
  return "stop";
}

// ---- 非流式：Anthropic response JSON → OpenAI chat.completion JSON ----
inline nlohmann::json anthrop_to_openai_message(const nlohmann::json& data) {
  std::string content, reasoning;
  nlohmann::json tool_calls = nlohmann::json::array();
  if (data.contains("content") && data["content"].is_array()) {
    for (auto& b : data["content"]) {
      if (!b.is_object()) continue;
      std::string type = b.value("type", "");
      if (type == "text") content += b.value("text", "");
      else if (type == "thinking") reasoning += b.value("thinking", "");
      else if (type == "tool_use") {
        tool_calls.push_back({
          {"id", safe_str(b, "id")},
          {"type", "function"},
          {"function", {{"name", safe_str(b, "name")},
                        {"arguments", (b.contains("input") && !b["input"].is_null())
                                          ? b["input"].dump()
                                          : std::string("{}")}}},
        });
      }
    }
  }
  nlohmann::json msg = {{"role", "assistant"}, {"content", content.empty() ? nlohmann::json(nullptr) : nlohmann::json(content)}};
  if (!reasoning.empty()) msg["reasoning_content"] = reasoning;
  if (!tool_calls.empty()) msg["tool_calls"] = tool_calls;
  return msg;
}

inline nlohmann::json openai_usage_from_anthropic(const nlohmann::json& u) {
  int64_t in = 0, out = 0;
  if (u.is_object()) {
    in = u.value("input_tokens", (int64_t)0);
    out = u.value("output_tokens", (int64_t)0);
  }
  nlohmann::json usage = {{"prompt_tokens", in}, {"completion_tokens", out}, {"total_tokens", in + out}};
  // cache_read_input_tokens / cache_read 存在才带 prompt_cache_hit_tokens（对齐 Node）
  bool has_cache = false;
  int64_t cache = 0;
  if (u.is_object()) {
    if (u.contains("cache_read_input_tokens")) { has_cache = true; cache = u.value("cache_read_input_tokens", (int64_t)0); }
    else if (u.contains("cache_read")) { has_cache = true; cache = u.value("cache_read", (int64_t)0); }
  }
  if (has_cache) usage["prompt_cache_hit_tokens"] = cache;
  return usage;
}

inline nlohmann::json anthropic_to_openai_completion(const nlohmann::json& data, const std::string& id,
                                                   const std::string& model) {
  nlohmann::json out = {
    {"id", id},
    {"object", "chat.completion"},
    {"created", util::time_util::now_sec()},
    {"model", model},
    {"choices", nlohmann::json::array({
      {{"index", 0},
       {"message", anthrop_to_openai_message(data)},
       {"finish_reason", map_stop_reason(data.value("stop_reason", ""))}},
    })},
  };
  if (data.contains("usage")) out["usage"] = openai_usage_from_anthropic(data["usage"]);
  return out;
}

// ---- 流式 chunk 构造 ----
inline nlohmann::json openai_chunk(const std::string& id, const std::string& model, const nlohmann::json& delta,
                                   const char* finish_reason = nullptr, const nlohmann::json* usage = nullptr) {
  nlohmann::json choice = {{"index", 0}, {"delta", delta}, {"finish_reason", finish_reason ? nlohmann::json(finish_reason) : nlohmann::json(nullptr)}};
  nlohmann::json out = {
    {"id", id}, {"object", "chat.completion.chunk"},
    {"created", util::time_util::now_sec()}, {"model", model},
    {"choices", nlohmann::json::array({choice})},
  };
  if (usage) out["usage"] = *usage;
  return out;
}

// ---- 流式状态机：吃 Anthropic SSE 事件 → 吐 OpenAI chunk JSON（每条单独返回）----
// 与 Node handleChatCompletions 流式分支逐事件对齐。
class StreamTranslator {
public:
  StreamTranslator(std::string id, std::string model)
      : id_(std::move(id)), model_(std::move(model)) {}

  struct Input { std::string event, data; };
  struct Output {
    std::vector<nlohmann::json> chunks; // 待写给客户端的 chunk
    bool saw_text = false;              // 本次输入产生过 content/reasoning/tool delta
    std::string error;                  // 非空 = 上游 error 事件，终止
  };

  // 首块：role 占位
  std::vector<nlohmann::json> start() {
    return {openai_chunk(id_, model_, {{"role", "assistant"}, {"content", ""}})};
  }

  // 喂一个上游事件。类型判定对齐 Node switch(ev.event)：以 SSE 帧的 event 字段为准，
  // data JSON 的 type 作为缺失时的回退。
  Output feed(const std::string& event, const std::string& data) {
    Output out;
    if (data == "[DONE]") return out;
    nlohmann::json d;
    try { d = nlohmann::json::parse(data); } catch (...) { return out; }
    if (!d.is_object()) return out;

    std::string type = !event.empty() ? event : d.value("type", "");
    if (type == "message_start") {
      if (d.contains("usage") && d["usage"].is_object()) {
        usage_ = {
          {"input_tokens", d["usage"].value("input_tokens", (int64_t)0)},
          {"output_tokens", (int64_t)0},
          {"cache_read", d["usage"].value("cache_read_input_tokens", (int64_t)0)},
          {"cache_creation", d["usage"].value("cache_creation_input_tokens", (int64_t)0)},
        };
      }
      if (d.contains("message") && d["message"].is_object() && d["message"].contains("usage") &&
          d["message"]["usage"].is_object()) {
        const auto& u = d["message"]["usage"];
        usage_ = {
          {"input_tokens", u.value("input_tokens", (int64_t)0)},
          {"output_tokens", (int64_t)0},
          {"cache_read", u.value("cache_read_input_tokens", (int64_t)0)},
          {"cache_creation", u.value("cache_creation_input_tokens", (int64_t)0)},
        };
      }
    } else if (type == "content_block_start") {
      const auto& cb = d.contains("content_block") && d["content_block"].is_object()
                           ? d["content_block"] : nlohmann::json(nullptr);
      if (cb.is_object() && safe_str(cb, "type") == "tool_use") {
        size_t index = d.contains("index") && d["index"].is_number_integer() ? (size_t)(int64_t)d["index"] : tool_acc_.size();
        ToolAcc acc{safe_str(cb, "id"), safe_str(cb, "name"), ""};
        tool_acc_[index] = acc;
        nlohmann::json delta = nlohmann::json::array({
          {{"index", index}, {"id", acc.id}, {"type", "function"},
           {"function", {{"name", acc.name}, {"arguments", ""}}}},
        });
        out.chunks.push_back(openai_chunk(id_, model_, {{"tool_calls", delta}}));
      }
    } else if (type == "content_block_delta") {
      const auto& dd = d.contains("delta") && d["delta"].is_object() ? d["delta"] : nlohmann::json(nullptr);
      if (!dd.is_object()) return out;
      std::string dtype = dd.value("type", "");
      if (dtype == "text_delta") {
        saw_any_ = true;
        out.saw_text = true;
        out.chunks.push_back(openai_chunk(id_, model_, {{"content", dd.value("text", "")}}));
      } else if (dtype == "thinking_delta") {
        saw_any_ = true;
        out.saw_text = true;
        out.chunks.push_back(openai_chunk(id_, model_, {{"reasoning_content", dd.value("thinking", "")}}));
      } else if (dtype == "input_json_delta") {
        std::string partial = safe_str(dd, "partial_json");
        size_t index = d.contains("index") && d["index"].is_number_integer() ? (size_t)(int64_t)d["index"] : 0;
        auto it = tool_acc_.find(index);
        if (it != tool_acc_.end()) it->second.args += partial;
        // 对齐官方 OpenAI 流形状：首帧（content_block_start）带全量 id/type/name，
        // 后续增量帧只带 index + arguments——每帧重复 name 会被部分客户端
        // （WorkBuddy）解析成 N 个独立调用导致组装卡死（官方线路无此问题的根因差异）
        nlohmann::json delta = nlohmann::json::array({
          {{"index", index}, {"function", {{"arguments", partial}}}},
        });
        out.chunks.push_back(openai_chunk(id_, model_, {{"tool_calls", delta}}));
      }
    } else if (type == "message_delta") {
      if (d.contains("delta") && d["delta"].is_object() && d["delta"].contains("stop_reason") &&
          d["delta"]["stop_reason"].is_string()) {
        finish_ = map_stop_reason(d["delta"]["stop_reason"].get<std::string>());
        saw_stop_ = true;
      }
      if (d.contains("usage") && d["usage"].is_object()) {
        // {input:0,out:0,...existing,...new} 语义：新值覆盖
        if (!usage_.is_object()) usage_ = {{"input_tokens", 0}, {"output_tokens", 0}};
        for (auto& [k, v] : d["usage"].items()) usage_[k] = v;
      }
    } else if (type == "message_stop") {
      saw_stop_ = true;
    } else if (type == "error") {
      std::string msg = "upstream stream error";
      if (d.contains("error") && d["error"].is_object()) msg = d["error"].value("message", msg);
      out.error = msg;
    }
    return out;
  }

  // 正常收尾：finish chunk + usage chunk（对齐 Node：先 finish_reason，再单独 usage chunk）
  std::vector<nlohmann::json> finalize() {
    std::vector<nlohmann::json> out;
    out.push_back(openai_chunk(id_, model_, nlohmann::json::object(), finish_.c_str()));
    normalize_usage();
    if (usage_.is_object()) {
      // 双字段：OpenAI 标准名（AI SDK 等严格客户端按此读，缺失按 0）+ Anthropic 透传名
      int64_t in = usage_.value("input_tokens", (int64_t)0);
      int64_t outp = usage_.value("output_tokens", (int64_t)0);
      int64_t cache = usage_.value("cache_read", (int64_t)0);
      usage_["prompt_tokens"] = in;
      usage_["completion_tokens"] = outp;
      usage_["prompt_tokens_details"] = {{"cached_tokens", cache}};
      usage_["completion_tokens_details"] = {{"reasoning_tokens", 0}};
      out.push_back(openai_chunk(id_, model_, nlohmann::json::object(), nullptr, &usage_));
    }
    return out;
  }
  // 出错收尾：错误挂在 choices 为空的 chunk 里（对齐 Node 的透传怪癖）
  static nlohmann::json error_chunk(const std::string& id, const std::string& model, const std::string& message) {
    nlohmann::json out = {
      {"id", id}, {"object", "chat.completion.chunk"},
      {"created", util::time_util::now_sec()}, {"model", model},
      {"choices", nlohmann::json::array()},
      {"error", {{"message", message}, {"type", "zproxy_stream_error"}}},
    };
    return out;
  }

  bool saw_any() const { return saw_any_; }
  bool saw_stop() const { return saw_stop_; }
  int64_t event_count() const { return ev_count_; }
  void bump_events() { ev_count_++; }
  nlohmann::json usage() const { return usage_; }
  const std::string& finish() const { return finish_; }

  // usage 归一化：cache_read ← cache_read_input_tokens（终值）；只删 cache 原生键，input/output 保留（对齐 Node）
  void normalize_usage() {
    if (!usage_.is_object()) return;
    if (usage_.contains("cache_read_input_tokens")) usage_["cache_read"] = usage_["cache_read_input_tokens"];
    if (usage_.contains("cache_creation_input_tokens")) usage_["cache_creation"] = usage_["cache_creation_input_tokens"];
    usage_.erase("cache_read_input_tokens");
    usage_.erase("cache_creation_input_tokens");
  }
  // 供调用方取数：in / out / cache
  void usage_numbers(int64_t& in_tok, int64_t& out_tok, int64_t& cache_tok) const {
    if (!usage_.is_object()) return;
    in_tok = usage_.value("input_tokens", (int64_t)0);
    out_tok = usage_.value("output_tokens", (int64_t)0);
    cache_tok = usage_.value("cache_read", (int64_t)0);
  }

private:
  struct ToolAcc { std::string id, name, args; };
  std::string id_, model_;
  std::map<size_t, ToolAcc> tool_acc_;
  nlohmann::json usage_ = nullptr;
  std::string finish_ = "stop";
  bool saw_stop_ = false;
  bool saw_any_ = false;
  int64_t ev_count_ = 0;
};

} // namespace zproxy::protocol
