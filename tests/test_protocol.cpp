// tests — 协议翻译 golden 用例
#include <cassert>
#include <cstdio>
#include "nlohmann/json.hpp"
#include "protocol/anthropic_to_openai.hpp"
#include "protocol/openai_to_anthropic.hpp"
#include "protocol/sse_parser.hpp"

using nlohmann::json;
static int g_pass = 0, g_fail = 0;
#define CHECK(cond)                                                                                                    \
  do {                                                                                                                 \
    if (cond) { g_pass++; } else { g_fail++; std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); }              \
  } while (0)

static void test_sse_parser() {
  zproxy::protocol::SseParser p;
  auto evs = p.feed("event: message\ndata: {\"a\":1}\n\n");
  CHECK(evs.size() == 1 && evs[0].event == "message" && evs[0].data == "{\"a\":1}");
  // 分块跨帧
  auto e1 = p.feed("event: message\ndata: {\"b\"");
  CHECK(e1.empty());
  auto e2 = p.feed(":2}\n\n");
  CHECK(e2.size() == 1 && e2[0].data == "{\"b\":2}");
  // CRLF 帧（Node 怪癖兼容）
  zproxy::protocol::SseParser p2;
  auto evs2 = p2.feed("event: message\r\ndata: x\r\n\r\n");
  CHECK(evs2.size() == 1 && evs2[0].data == "x");
  // 多行 data 合并
  zproxy::protocol::SseParser p3;
  auto evs3 = p3.feed("data: l1\ndata: l2\n\n");
  CHECK(evs3.size() == 1 && evs3[0].data == "l1\nl2");
  // 无 data 的事件被跳过
  auto evs4 = p3.feed("event: ping\n\n");
  CHECK(evs4.empty());
}

static void test_translate_request() {
  json in = {
    {"model", "deepseek-chat"},
    {"stream", true},
    {"messages", json::array({
      {{"role", "system"}, {"content", "be nice"}},
      {{"role", "user"}, {"content", "hi"}},
      {{"role", "assistant"}, {"content", "hello"},
       {"tool_calls", json::array({
         {{"id", "call_1"}, {"type", "function"},
          {"function", {{"name", "f"}, {"arguments", "{\"x\":1}"}}}},
       })}},
      {{"role", "tool"}, {"tool_call_id", "call_1"}, {"content", "result"}},
    })},
    {"max_tokens", 100.7},
    {"temperature", 0.5},
    {"stop", "END"},
    {"tools", json::array({
      {{"type", "function"}, {"function", {{"name", "f"}, {"description", "d"},
        {"parameters", {{"type", "object"}, {"properties", {{"x", {{"type", "integer"}}}}}}}}}},
    })},
    {"tool_choice", "required"},
  };
  auto out = zproxy::protocol::translate_request(in, "GLM-5.3-Flash");
  CHECK(out["model"] == "GLM-5.3-Flash");
  CHECK(out["stream"] == true);
  CHECK(out["max_tokens"] == 100);
  CHECK(out["stop_sequences"] == json::array({"END"}));
  CHECK(out["temperature"] == 0.5);
  // 客户端 system 升格为 out["system"] 块（transport 层注入 ZCode 必需块后追加尾部）
  auto& msgs = out["messages"];
  CHECK(msgs.size() == 3);
  CHECK(out["system"].is_array() && out["system"][0]["text"] == "be nice");
  CHECK(msgs[0]["role"] == "user" && msgs[0]["content"][0]["text"] == "hi");
  CHECK(msgs[1]["role"] == "assistant");
  CHECK(msgs[1]["content"][0]["type"] == "text"); // 文本块在前
  CHECK(msgs[1]["content"][1]["type"] == "tool_use");
  CHECK(msgs[1]["content"][1]["input"] == json({{"x", 1}}));
  CHECK(msgs[2]["content"][0]["type"] == "tool_result");
  CHECK(msgs[2]["content"][0]["tool_use_id"] == "call_1");
  CHECK(out["tools"][0]["input_schema"]["type"] == "object");
  CHECK(out["tool_choice"]["type"] == "any");

  // max_tokens 默认 / 上限
  json in2 = {{"messages", json::array({{{"role", "user"}, {"content", "x"}}})}};
  auto out2 = zproxy::protocol::translate_request(in2, "GLM-5.3");
  CHECK(out2["max_tokens"] == 8192);
  json in3 = {{"max_tokens", 99999999}, {"messages", json::array({{{"role", "user"}, {"content", "x"}}})}};
  CHECK(zproxy::protocol::translate_request(in3, "GLM-5.3")["max_tokens"] == 131072);

  // 图片 data URL
  json in4 = {
    {"messages", json::array({
      {
        {"role", "user"},
        {"content", json::array({
          {{"type", "text"}, {"text", "look"}},
          {{"type", "image_url"}, {"image_url", {{"url", "data:image/png;base64,AAAA"}}}},
        })},
      },
    })},
  };
  auto out4 = zproxy::protocol::translate_request(in4, "GLM-5.3");
  auto& blocks = out4["messages"][0]["content"];
  CHECK(blocks[1]["type"] == "image");
  CHECK(blocks[1]["source"]["media_type"] == "image/png");
  CHECK(blocks[1]["source"]["data"] == "AAAA");
}

static void test_response_translation() {
  json data = {
    {"content", json::array({
      {{"type", "thinking"}, {"thinking", "hmm"}},
      {{"type", "text"}, {"text", "answer"}},
      {{"type", "tool_use"}, {"id", "tu_1"}, {"name", "f"}, {"input", {{"k", "v"}}}},
    })},
    {"stop_reason", "tool_use"},
    {"usage", {{"input_tokens", 10}, {"output_tokens", 5}, {"cache_read_input_tokens", 3}}},
  };
  auto out = zproxy::protocol::anthropic_to_openai_completion(data, "chatcmpl-1", "GLM-5.3");
  auto& msg = out["choices"][0]["message"];
  CHECK(msg["content"] == "answer");
  CHECK(msg["reasoning_content"] == "hmm");
  CHECK(msg["tool_calls"][0]["function"]["name"] == "f");
  CHECK(msg["tool_calls"][0]["function"]["arguments"] == "{\"k\":\"v\"}");
  CHECK(out["choices"][0]["finish_reason"] == "tool_calls");
  CHECK(out["usage"]["prompt_tokens"] == 10);
  CHECK(out["usage"]["prompt_cache_hit_tokens"] == 3);
}

static void test_stream_translator() {
  zproxy::protocol::StreamTranslator tr("id1", "GLM-5.3");
  auto o1 = tr.feed("message_start", R"({"type":"message_start","message":{"usage":{"input_tokens":7}}})");
  CHECK(o1.chunks.empty());
  auto o2 = tr.feed("content_block_delta", R"({"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi"}})");
  CHECK(o2.chunks.size() == 1 && o2.chunks[0]["choices"][0]["delta"]["content"] == "Hi");
  CHECK(o2.saw_text);
  auto o3 = tr.feed("content_block_start", R"({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"f"}})");
  CHECK(o3.chunks.size() == 1 && o3.chunks[0]["choices"][0]["delta"]["tool_calls"][0]["id"] == "t1");
  auto o4 = tr.feed("content_block_delta", R"({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"a\":"}})");
  CHECK(o4.chunks.size() == 1);
  // 官方形状：增量帧只带 index+arguments（首帧才带 id/type/name）
  const auto& tc0 = o4.chunks[0]["choices"][0]["delta"]["tool_calls"][0];
  CHECK(!tc0.contains("id"));
  CHECK(!tc0.contains("type"));
  CHECK(!tc0["function"].contains("name"));
  CHECK(tc0["function"]["arguments"] == "{\"a\":");
  auto o5 = tr.feed("message_delta", R"({"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":9}})");
  CHECK(o5.chunks.empty());
  CHECK(tr.finish() == "tool_calls");
  auto o6 = tr.feed("message_stop", R"({"type":"message_stop"})");
  CHECK(tr.saw_stop());
  auto fin = tr.finalize();
  CHECK(fin.size() == 2);
  CHECK(fin[0]["choices"][0]["finish_reason"] == "tool_calls");
  CHECK(fin[1]["usage"]["output_tokens"] == 9);
  CHECK(fin[1]["usage"]["cache_read"] == 0);
  // OpenAI 标准字段（严格客户端按此读，缺失按 0 统计）
  CHECK(fin[1]["usage"]["prompt_tokens"] == 7);
  CHECK(fin[1]["usage"]["completion_tokens"] == 9);
  CHECK(fin[1]["usage"]["prompt_tokens_details"]["cached_tokens"] == 0);
  CHECK(!fin[1]["usage"].contains("input_tokens") == false); // input_tokens 保留
  // error 事件
  zproxy::protocol::StreamTranslator tr2("id2", "m");
  auto oe = tr2.feed("error", R"({"type":"error","error":{"message":"boom"}})");
  CHECK(oe.error == "boom");
}

int main() {
  test_sse_parser();
  test_translate_request();
  test_response_translation();
  test_stream_translator();
  std::printf("pass=%d fail=%d\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
