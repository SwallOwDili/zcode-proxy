// L4 upstream — ZCode 上游客户端：WAF 特征头、system 注入、多账号轮询重试（callUpstream 等价）
//
// 指纹要点（逐位复刻 Node 行为）：
//   callUpstream 的最终头 = withZcodeEndpointHeaders(buildUpstreamHeaders(jwt), acc)
//   即 {...zcodeSourceHeaders(acc), ...buildUpstreamHeaders(jwt)}。
//   两套对象里 User-Agent/X-Title/X-Platform 等键大小写不同，undici Headers 把同名逻辑头
//   以逗号拼接（append 语义）——WAF 当前放行的正是这种"逗号重复"指纹，必须复刻。
#pragma once
#include <atomic>
#include <chrono>
#include <optional>
#include <thread>
#include <unordered_set>
#include "domain/account_pool.hpp"
#include "domain/sysprompt.hpp"
#include "nlohmann/json.hpp"
#include "protocol/sse_parser.hpp"
#include "transport/http_client.hpp"
#include "upstream/http.hpp"
#include "upstream/sysinfo.hpp"
#include "util/config.hpp"
#include "util/log.hpp"
#include "util/time_util.hpp"
#include "util/uuid.hpp"

namespace zhttp = ::zproxy::http; // 协程 transport（区别于旧阻塞 upstream::http）

namespace zproxy::upstream {

// ---------- system 注入（withInjectedSystem 等价；WAF 硬依赖） ----------
inline std::string client_system_to_text(const nlohmann::json& system) {
  if (system.is_string()) {
    std::string t = util::trim(system.get<std::string>());
    return t;
  }
  if (system.is_array()) {
    std::string out;
    for (auto& b : system) {
      if (b.is_object() && b.value("type", "") == "text" && b.contains("text") && b["text"].is_string()) {
        if (!out.empty()) out += "\n\n";
        out += b["text"].get<std::string>();
      }
    }
    return util::trim(out);
  }
  return "";
}

inline nlohmann::json with_injected_system(const nlohmann::json& body,
                                           const std::vector<nlohmann::json>& required_blocks) {
  // system = [ZCode身份块, ZCode主段(会话路径随机化), ...客户端system块]
  // 消融实验：WAF 要求前两块开头（缺一 405），客户端块可追加尾部；第三块非必须
  nlohmann::json sys = nlohmann::json::array();
  for (auto& b : required_blocks) {
    nlohmann::json blk = b;
    // 消融实证：主段的 "# ZCode Desktop Context" 段（1884c，含运营者家目录路径）可整段删除
    // ——删除后上游 200 通过；多用户下运营者路径从源头消失（无需随机化）
    if (blk.contains("text") && blk["text"].is_string()) {
      std::string t = blk["text"].get<std::string>();
      auto dc = t.find("# ZCode Desktop Context");
      if (dc != std::string::npos) {
        t = t.substr(0, dc);
        while (!t.empty() && (t.back() == '\n' || t.back() == '\r' || t.back() == ' ')) t.pop_back();
        blk["text"] = t;
      }
    }
    // 会话级动态路径随机化：多用户代理下运营者家目录不能写死在共享提示词里；
    // 每请求独立哈希 = 每请求独立会话，关联特征聚集消失
    static const std::regex vis_re("/Users/[^/]+/\\.zcode/v2/visualizations/[0-9a-fA-F-]+");
    if (blk.contains("text") && blk["text"].is_string())
      blk["text"] = std::regex_replace(blk["text"].get<std::string>(), vis_re,
                                       "/Users/user/.zcode/v2/visualizations/" + util::random_hex(32));
    sys.push_back(std::move(blk));
  }
  // 客户端 system（string 或 blocks 数组）追加尾部——客户端提示词升格为 system
  if (body.contains("system") && !body["system"].is_null()) {
    const auto& cs = body["system"];
    if (cs.is_string() && !cs.get<std::string>().empty())
      sys.push_back({{"type", "text"}, {"text", cs.get<std::string>()}});
    else if (cs.is_array())
      for (auto& b : cs) if (b.is_object()) sys.push_back(b);
  }
  if (!sys.empty()) sys[sys.size() - 1]["cache_control"] = {{"type", "ephemeral"}};

  nlohmann::json out = body;
  out["system"] = std::move(sys);
  out["messages"] = body.contains("messages") && body["messages"].is_array()
                        ? body["messages"] : nlohmann::json::array();
  return out;
}

inline Headers source_headers(const domain::AccountPool::Lease& l) {
  return {
    {"http-referer", "https://zcode.z.ai"},
    {"user-agent", "ZCode/" + l.app_version + " ai-sdk/anthropic/2.0.0"},
    {"x-zcode-app-version", l.app_version},
    {"x-title", "Z Code@electron"},
    {"x-release-channel", "production"},
    {"x-client-language", l.fp_language},
    {"x-client-timezone", sysinfo::tz_name()},
    {"x-zcode-agent", "glm"},
    {"x-platform", l.fp_platform},
    {"x-os-category", "macos"},
    {"x-os-version", sysinfo::kernel_release()},
  };
}
// zcodeSourceHeaders(acc)：zcode-plan 全家桶用（Title-Case 键，固定值 + X-Device-Mid）
inline Headers zcode_source_headers(const std::string& jwt, const std::string& device_mid,
                                    const std::string& app_version) {
  return {
    {"User-Agent", "ZCode/" + app_version},
    {"X-ZCode-App-Version", app_version},
    {"X-Title", "Z Code@electron"},
    {"X-Platform", "darwin-arm64"},
    {"X-Release-Channel", "stable"},
    {"X-Client-Language", "zh-CN"},
    {"X-Client-Timezone", "Asia/Shanghai"},
    {"X-Os-Category", "macos"},
    {"X-Os-Version", sysinfo::kernel_version()},
    {"X-Device-Mid", device_mid},
    {"HTTP-Referer", "https://zcode.z.ai"},
  };
}

// withZcodeEndpointHeaders(caller, acc)：JS 对象 spread 合并——同名键覆盖、大小写不同共存，
// undici 再按逻辑头逗号拼接。这里直接产出拼接后的最终头（顺序 = zcodeSource 在前、caller 在后）。
inline Headers combine_zcode_endpoint(Headers caller, const std::string& jwt, const std::string& device_mid,
                                      const std::string& app_version) {
  Headers out = zcode_source_headers(jwt, device_mid, app_version);
  for (auto& [k, v] : caller) {
    bool merged = false;
    for (auto& [ok, ov] : out) {
      if (util::iequals(ok, k)) { ov += ", "; ov += v; merged = true; break; } // undici append 语义（免临时串）
    }
    if (!merged) out.emplace_back(k, v);
  }
  return out;
}

// buildUpstreamHeaders(sessionId, jwt) + authorization/x-api-key
inline Headers build_upstream_caller(const domain::AccountPool::Lease& l) {
  Headers h = source_headers(l);
  h.emplace_back("content-type", "application/json");
  h.emplace_back("anthropic-version", "2023-06-01");
  h.emplace_back("x-request-id", util::uuid());
  h.emplace_back("x-session-id", l.session_id);
  h.emplace_back("x-zcode-session-type", "main");
  h.emplace_back("x-zcode-trace-id", util::uuid());
  h.emplace_back("x-query-id", util::uuid());
  h.emplace_back("x-zcode-query-source", "main_turn");
  h.emplace_back("authorization", "Bearer " + l.jwt);
  h.emplace_back("x-api-key", l.jwt);
  return h;
}

// ---------- callUpstream ----------
struct CallResult {
  int status = 0;
  std::string content_type;
  std::string body;                 // 已缓冲体（JSON / 429 错误体 / 透传 JSON）
  std::string account_name;         // 成功或最后一次尝试的账号
  nlohmann::json business_error;    // 200 包裹的业务错误
  bool no_account = false;
  bool is_stream() const { return content_type.find("text/event-stream") != std::string::npos; }
};

class ZcodeClient {
public:
  // 协程版（chat 主链路）：轮换/3009/业务码逻辑与阻塞版 call() 一致，
  // 上游 IO 全异步——事件循环不被阻塞，on_chunk 协程回调直写客户端 socket
  asio::awaitable<CallResult> call_co(const nlohmann::json& anthropic_body, const std::string& session_key,
                                      const std::string& avoid_name,
                                      const std::function<asio::awaitable<bool>(std::string_view)>& on_chunk) {
    nlohmann::json payload = with_injected_system(anthropic_body, sys_.effective_blocks());
    CallResult out;
    int tries = std::max((int)pool_.size(), 1);
    int had_status = 0;
    std::string last_content_type;
    for (int i = 0; i < tries; i++) {
      auto name = pool_.pick(session_key, avoid_name, payload.value("model", ""));
      if (!name) { out.no_account = true; break; }
      auto lease = pool_.lease(*name);
      if (!lease.valid) break;
      out.account_name = *name;
      Headers headers = combine_zcode_endpoint(build_upstream_caller(lease), lease.jwt, lease.device_mid,
                                               lease.app_version);
      std::string body_str = payload.dump();
      auto t0 = std::chrono::steady_clock::now();
      auto res = co_await zhttp::co_post_stream(cfg_.upstream, zhttp::full_path(cfg_.upstream, "/v1/messages"), headers, body_str, on_chunk);
      int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
      util::log("upstream account=" + *name + " status=" + std::to_string(res.status) + " ms=" +
                std::to_string(ms) + (res.error.empty() ? "" : " err=" + res.error));
      if (!res.ok()) { pool_.release(*name); continue; }
      pool_.release(*name);
      had_status = res.status;
      last_content_type = res.content_type;
      if (res.status == 401) { pool_.mark_cooldown(*name, cfg_.cooldown_401_ms); continue; }
      if (res.status == 429) {
        if (util::contains(res.body, "3009")) {
          bool recovered = false;
          for (int k = 0; k < cfg_.retry_3009_max; k++) {
            asio::steady_timer tm(co_await asio::this_coro::executor);
            tm.expires_after(std::chrono::milliseconds(cfg_.retry_3009_ms));
            co_await tm.async_wait(asio::use_awaitable);
            auto lease2 = pool_.lease(*name);
            if (!lease2.valid) break;
            Headers h2 = combine_zcode_endpoint(build_upstream_caller(lease2), lease2.jwt, lease2.device_mid,
                                                lease2.app_version);
            auto res2 = co_await zhttp::co_post_stream(cfg_.upstream, "/v1/messages", h2, body_str, on_chunk);
            pool_.release(*name);
            res = res2;
            if (res.status != 429) { recovered = true; break; }
            if (!util::contains(res.body, "3009")) break;
          }
          if (res.status == 429 && !recovered) {
            out.status = res.status; out.content_type = res.content_type; out.body = res.body;
            co_return out; // 快速失败：不冷却
          }
        }
        if (res.status == 429) {
          pool_.mark_cooldown(*name, cfg_.cooldown_429_ms, payload.value("model", ""));
          continue;
        }
      }
      bool sse = res.content_type.find("text/event-stream") != std::string::npos;
      if (!sse && res.content_type.find("json") != std::string::npos) {
        nlohmann::json j;
        try { j = nlohmann::json::parse(res.body); } catch (...) { j = nullptr; }
        bool is_biz = j.is_object() && j.contains("code") && !j["code"].is_null() &&
                      !(j.contains("content") && j["content"].is_array());
        if (is_biz) {
          int64_t code = 0;
          try { code = j["code"].get<int64_t>(); } catch (...) {}
          if (code == 1005 || code == 1113 || code == 1302) {
            pool_.mark_cooldown(*name, cfg_.cooldown_429_ms, payload.value("model", ""));
            continue;
          }
          out.status = res.status; out.content_type = res.content_type; out.body = res.body;
          out.business_error = j;
          co_return out;
        }
      }
      out.status = res.status;
      out.content_type = res.content_type;
      out.body = res.body;
      co_return out;
    }
    out.status = had_status;
    out.content_type = last_content_type;
    co_return out;
  }

  ZcodeClient(const Config& cfg, domain::AccountPool& pool, domain::SysPrompt& sys)
      : cfg_(cfg), pool_(pool), sys_(sys) {}

  // on_chunk：仅 content-type 为 SSE 时逐块回调（转发给客户端）；返回 false 中断
  CallResult call(const nlohmann::json& anthropic_body, const std::string& session_key = "",
                  const std::string& avoid_name = "",
                  const std::function<bool(std::string_view)>& on_chunk = nullptr) {
    nlohmann::json payload = with_injected_system(anthropic_body, sys_.effective_blocks());
    CallResult out;
    int tries = std::max((int)pool_.size(), 1);
    int had_status = 0;
    std::string last_content_type;
    for (int i = 0; i < tries; i++) {
      auto name = pool_.pick(session_key, avoid_name, payload.value("model", ""));
      if (!name) { out.no_account = true; break; }
      auto lease = pool_.lease(*name);
      if (!lease.valid) break;
      out.account_name = *name;
      Headers headers = combine_zcode_endpoint(build_upstream_caller(lease), lease.jwt, lease.device_mid,
                                               lease.app_version);
      std::string body_str = payload.dump();
      // 调试转储（重放定位用）：ZPROXY_DUMP_REQUEST=1 时写 /tmp/zproxy-last-req.json
      if (util::fs::getenv_str("ZPROXY_DUMP_REQUEST")) {
        nlohmann::json dump;
        dump["headers"] = headers; // pair 序列化为 ["k","v"]
        dump["body_len"] = body_str.size();
        dump["body"] = body_str;
        util::fs::write_file("/tmp/zproxy-last-req.json", dump.dump());
      }
      auto t0 = std::chrono::steady_clock::now();
      auto res = http::post_stream(cfg_.upstream, "/v1/messages", headers, body_str, on_chunk);
      int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
      util::log("upstream account=" + *name + " status=" + std::to_string(res.status) + " ms=" +
                std::to_string(ms) + (res.error.empty() ? "" : " err=" + res.error));

      if (!res.ok()) {
        // 网络/超时：换下一个账号
        pool_.release(*name);
        continue;
      }
      pool_.release(*name);
      had_status = res.status;
      last_content_type = res.content_type;

      if (res.status == 401) {
        pool_.mark_cooldown(*name, cfg_.cooldown_401_ms);
        continue;
      }
      if (res.status == 429) {
        if (util::contains(res.body, "3009")) {
          // 模型并发占用：短退避原账号重试（不冷却）——间隔/次数可调（20s 卡顿治理）
          bool recovered = false;
          for (int k = 0; k < cfg_.retry_3009_max; k++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(cfg_.retry_3009_ms));
            auto lease2 = pool_.lease(*name);
            if (!lease2.valid) break;
            Headers h2 = combine_zcode_endpoint(build_upstream_caller(lease2), lease2.jwt, lease2.device_mid,
                                                lease2.app_version);
            auto res2 = http::post_stream(cfg_.upstream, "/v1/messages", h2, body_str, on_chunk);
            pool_.release(*name);
            res = res2;
            if (res.status != 429) { recovered = true; break; }
            if (!util::contains(res.body, "3009")) break;
          }
          if (!recovered && res.status == 429) {
            // 快速失败返回客户端，账号不冷却（对齐 Node）
            out.status = res.status; out.content_type = std::move(res.content_type); out.body = std::move(res.body);
            return out;
          }
          if (res.status != 429) { /* 3009 期恢复 */ }
        }
        if (res.status == 429) {
          pool_.mark_cooldown(*name, cfg_.cooldown_429_ms, payload.value("model", ""));
          continue;
        }
      }
      // 200 包裹业务错误检测（JSON 非流式）
      bool sse = res.content_type.find("text/event-stream") != std::string::npos;
      if (!sse && res.content_type.find("json") != std::string::npos) {
        nlohmann::json j;
        try { j = nlohmann::json::parse(res.body); } catch (...) { j = nullptr; }
        bool is_biz = j.is_object() && j.contains("code") && !j["code"].is_null() &&
                      !(j.contains("content") && j["content"].is_array());
        if (is_biz) {
          int64_t code = 0;
          try { code = j["code"].get<int64_t>(); } catch (...) {}
          if (code == 1005 || code == 1113 || code == 1302) {
            pool_.mark_cooldown(*name, cfg_.cooldown_429_ms, payload.value("model", ""));
            continue;
          }
          out.status = res.status; out.content_type = std::move(res.content_type); out.body = std::move(res.body);
          out.business_error = std::move(j);
          return out;
        }
      }
      out.status = res.status;
      out.content_type = std::move(res.content_type);
      out.body = std::move(res.body);
      return out;
    }
    out.status = had_status;
    out.content_type = last_content_type;
    return out;
  }

private:
  const Config& cfg_;
  domain::AccountPool& pool_;
  domain::SysPrompt& sys_;
};

} // namespace zproxy::upstream
