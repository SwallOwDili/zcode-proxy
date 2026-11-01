// L4 protocol — OpenAI 请求 → Anthropic 请求（纯函数，零 IO）
//
// 与 Node translateRequest 对齐；唯一行为修正（已批准）：
//   OpenAI 的 system/developer 消息不再丢弃，包裹 <instructions-from-calling-application>
//   作为首条 user 消息注入（与 Anthropic 透传路径同策略）。
#pragma once
#include <cmath>
#include <optional>
#include <string>
#include "nlohmann/json.hpp"
#include "util/uuid.hpp"

namespace zproxy::protocol {

constexpr int64_t kMaxTokensCap = 131072;

// data:image/png;base64,XXXX → (media_type, data)
// 手工解析替代 std::regex：base64 图片动辄数 MB，regex 在其上又慢又耗内存
inline bool parse_data_url(const std::string& url, std::string& media, std::string& data) {
  if (url.compare(0, 5, "data:") != 0) return false;
  auto sep = url.find(";base64,", 5);
  if (sep == std::string::npos) return false;
  media = url.substr(5, sep - 5);
  data = url.substr(sep + 8);
  return media.compare(0, 6, "image/") == 0 && !data.empty();
}

// 按 move 语义从 content 搬运字符串（调用方传入的节点随后即弃）
inline nlohmann::json text_blocks_from_content(nlohmann::json content) {
  nlohmann::json blocks = nlohmann::json::array();
  if (content.is_string()) {
    if (!content.get<std::string>().empty())
      blocks.push_back({{"type", "text"}, {"text", std::move(content.get_ref<std::string&>())}});
    return blocks;
  }
  if (!content.is_array()) return blocks;
  for (auto& part : content) {
    if (!part.is_object()) continue;
    std::string type = part.value("type", "");
    if (type == "text") {
      if (part.contains("text") && part["text"].is_string() && !part["text"].get<std::string>().empty())
        blocks.push_back({{"type", "text"}, {"text", std::move(part["text"].get_ref<std::string&>())}});
    } else if (type == "image_url") {
      if (part.contains("image_url") && part["image_url"].is_object() &&
          part["image_url"].contains("url") && part["image_url"]["url"].is_string()) {
        std::string url = std::move(part["image_url"]["url"].get_ref<std::string&>());
        std::string media, data;
        if (parse_data_url(url, media, data))
          blocks.push_back({{"type", "image"},
                            {"source", {{"type", "base64"}, {"media_type", std::move(media)}, {"data", std::move(data)}}}});
      }
      // 非 data URL 与其他类型：静默丢弃（对齐 Node）
    }
  }
  return blocks;
}

// 按 move 语义消费 in：消息文本/base64/工具 schema 从输入树搬出，全程只保留一份
inline nlohmann::json translate_request(nlohmann::json in, const std::string& mapped_model) {
  nlohmann::json out;
  out["model"] = mapped_model;
  out["stream"] = in.value("stream", false);

  nlohmann::json messages = nlohmann::json::array();
  std::string system_text; // 客户端 system/developer 文本 → 由 transport 层注入为 system 块
  auto append_instruction_prefix = [&](const std::string& text) {
    if (text.empty()) return;
    if (!system_text.empty()) system_text += "\n\n";
    system_text += text;
  };

  if (in.contains("messages") && in["messages"].is_array()) {
    for (auto& msg : in["messages"]) {
      if (!msg.is_object()) continue;
      std::string role = msg.value("role", "");
      if (role == "system" || role == "developer") {
        if (msg.contains("content")) {
          if (msg["content"].is_string()) {
            append_instruction_prefix(std::move(msg["content"].get_ref<std::string&>()));
          } else if (msg["content"].is_array()) {
            for (auto& b : msg["content"]) {
              if (b.is_object() && b.value("type", "") == "text" && b.contains("text"))
                append_instruction_prefix(std::move(b["text"].get_ref<std::string&>()));
            }
          }
        }
        continue;
      }
      if (role == "user") {
        nlohmann::json blocks;
        if (msg.contains("content")) blocks = text_blocks_from_content(std::move(msg["content"]));
        else blocks = text_blocks_from_content(nullptr);
        messages.push_back({{"role", "user"}, {"content", std::move(blocks)}});
      } else if (role == "assistant") {
        nlohmann::json blocks = nlohmann::json::array();
        if (msg.contains("reasoning_content") && msg["reasoning_content"].is_string() &&
            !msg["reasoning_content"].get<std::string>().empty()) {
          blocks.push_back({{"type", "thinking"}, {"thinking", std::move(msg["reasoning_content"])}, {"signature", ""}});
        }
        if (msg.contains("content")) {
          auto tb = text_blocks_from_content(std::move(msg["content"]));
          blocks.insert(blocks.end(), tb.begin(), tb.end());
        }
        if (msg.contains("tool_calls") && msg["tool_calls"].is_array()) {
          for (auto& tc : msg["tool_calls"]) {
            if (!tc.is_object()) continue;
            std::string name;
            nlohmann::json input = nlohmann::json::object();
            if (tc.contains("function") && tc["function"].is_object()) {
              name = tc["function"].value("name", "");
              std::string args = "{}";
              if (tc["function"].contains("arguments") && tc["function"]["arguments"].is_string())
                args = std::move(tc["function"]["arguments"].get_ref<std::string&>());
              if (args.empty()) args = "{}";
              try { input = nlohmann::json::parse(args); if (!input.is_object()) input = nlohmann::json::object(); }
              catch (...) { input = nlohmann::json::object(); }
            }
            std::string id = tc.value("id", "");
            if (id.empty()) id = "call_" + util::uuid();
            blocks.push_back({{"type", "tool_use"}, {"id", id}, {"name", name}, {"input", input}});
          }
        }
        if (!blocks.empty()) messages.push_back({{"role", "assistant"}, {"content", blocks}});
      } else if (role == "tool") {
        std::string text;
        if (msg.contains("content") && msg["content"].is_string())
          text = std::move(msg["content"].get_ref<std::string&>());
        messages.push_back({
          {"role", "user"},
          {"content", nlohmann::json::array({{{"type", "tool_result"},
            {"tool_use_id", msg.value("tool_call_id", "")},
            {"content", nlohmann::json::array({{{"type", "text"}, {"text", text}}})}}})},
        });
      }
    }
  }
  // system_text 已在消息循环内收集完毕（append_instruction_prefix 现为收集函数，
  // 此处旧残留调用曾把文本追加进自身——"be nice\n\nbe nice" 双倍即由此来）
  if (!system_text.empty())
    out["system"] = nlohmann::json::array({{{"type", "text"}, {"text", std::move(system_text)}}});
  out["messages"] = std::move(messages);

  // max_tokens：max_completion_tokens ?? max_tokens，cap 131072，默认 8192
  int64_t mt = 8192;
  nlohmann::json mt_raw = nullptr;
  if (in.contains("max_completion_tokens")) mt_raw = in["max_completion_tokens"];
  else if (in.contains("max_tokens")) mt_raw = in["max_tokens"];
  if (!mt_raw.is_null()) {
    try {
      double v = mt_raw.get<double>();
      if (std::isfinite(v) && v >= 1) mt = std::min((int64_t)std::floor(v), kMaxTokensCap);
    } catch (...) {}
  }
  out["max_tokens"] = mt;

  if (in.contains("temperature") && !in["temperature"].is_null()) out["temperature"] = std::move(in["temperature"]);
  if (in.contains("top_p") && !in["top_p"].is_null()) out["top_p"] = std::move(in["top_p"]);

  if (in.contains("stop") && !in["stop"].is_null()) {
    if (in["stop"].is_string()) out["stop_sequences"] = nlohmann::json::array({std::move(in["stop"])});
    else if (in["stop"].is_array()) out["stop_sequences"] = std::move(in["stop"]);
  }

  if (in.contains("tools") && in["tools"].is_array()) {
    nlohmann::json tools = nlohmann::json::array();
    for (auto& t : in["tools"]) {
      if (!t.is_object()) continue;
      nlohmann::json fn = nullptr;
      if (t.value("type", "") == "function" && t.contains("function") && t["function"].is_object())
        fn = std::move(t["function"]);
      else if (t.contains("function") && t["function"].is_object()) fn = std::move(t["function"]);
      else if (t.contains("name")) fn = std::move(t);
      if (fn.is_null() || !fn.contains("name")) continue;
      nlohmann::json schema = nlohmann::json{{"type", "object"}, {"properties", nlohmann::json::object()}};
      if (fn.contains("parameters") && fn["parameters"].is_object()) schema = std::move(fn["parameters"]);
      tools.push_back({
        {"name", std::move(fn["name"])},
        {"description", fn.value("description", "")},
        {"input_schema", std::move(schema)},
      });
    }
    if (!tools.empty()) out["tools"] = tools;
    if (in.contains("tool_choice") && !in["tool_choice"].is_null()) {
      const auto& tc = in["tool_choice"];
      if (tc.is_string()) {
        std::string s = tc.get<std::string>();
        if (s == "none") out["tool_choice"] = {{"type", "none"}};
        else if (s == "required") out["tool_choice"] = {{"type", "any"}};
        // "auto"/其他 → 省略（对齐 Node）
      } else if (tc.is_object() && tc.value("type", "") == "function") {
        std::string fname;
        if (tc.contains("function") && tc["function"].is_object()) fname = tc["function"].value("name", "");
        out["tool_choice"] = {{"type", "tool"}, {"name", fname}};
      }
    }
  }
  return out;
}

} // namespace zproxy::protocol
