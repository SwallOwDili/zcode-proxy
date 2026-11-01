// L0 — 全局配置（环境变量 + 启动参数 → 不可变 Config；与 Node 版 ZPROXY_* 语义一致）
#pragma once
#include <pwd.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#include <string>
#include "crypto/sha256.hpp"
#include "nlohmann/json.hpp"
#include "util/env.hpp"
#include "util/fs.hpp"

namespace zproxy {

struct Config {
  // 服务
  std::string host = "127.0.0.1";
  int port = 8787;
  std::string client_token; // 空 = 不鉴权
  // 模型
  std::string default_model = "GLM-5.3-Flash";
  nlohmann::json env_model_map; // ZPROXY_MODEL_MAP（可能为 null）
  // 上游
  std::string upstream = "https://zcode.z.ai/api/v1/zcode-plan/anthropic";
  std::string app_version = "3.16.3";
  // 冷却/重试
  int64_t cooldown_401_ms = 10 * 60 * 1000;
  int64_t cooldown_429_ms = 60 * 1000;
  int64_t retry_3009_ms = 2000;   // 新增：3009 短退避基数（原版写死 2000）
  int retry_3009_max = 3;         // 新增：3009 重试次数（原版写死 3）
  // 路径
  std::string state_dir; // 所有状态文件所在目录
  std::string web_dir;   // 管理页静态文件目录
  std::string creds_path;
  std::string rollout_dir;
  std::string tokens_file_override; // ZPROXY_TOKENS_FILE
  std::string routing_mode_default = "tps";
  // 账号池定时刷盘间隔（内存权威 → tokens.json 异步同步）
  int64_t sync_ms = 5000;
  // claim / 风控重试
  int claim_concurrency = 4;
  bool blocked_retry = false;
  int64_t blocked_retry_ms = 2 * 60 * 60 * 1000;
  // 凭据密钥
  std::string credential_secret_override; // ZCODE_CREDENTIAL_SECRET

  std::string path(const std::string& name) const { return util::fs::join(state_dir, name); }

  // 与 Node 版 LOCAL_SECRET 对齐：zcode-credential-fallback:<platform>:<homedir>:<username>
  std::string local_secret() const {
    if (!credential_secret_override.empty()) return credential_secret_override;
    return "zcode-credential-fallback:" + node_platform() + ":" + util::fs::home_dir() + ":" + os_username();
  }
  std::vector<uint8_t> local_key() const { return crypto::sha256_raw(local_secret()); }

  static std::string node_platform() {
#if defined(__APPLE__)
    return "darwin";
#elif defined(__linux__)
    return "linux";
#elif defined(_WIN32)
    return "win32";
#else
    return "unknown";
#endif
  }
  static std::string os_username() {
    struct passwd pw{};
    struct passwd* res = nullptr;
    char buf[4096];
    if (getpwuid_r(geteuid(), &pw, buf, sizeof(buf), &res) == 0 && res) return pw.pw_name;
    auto u = util::fs::getenv_str("USER");
    return u ? *u : "unknown";
  }
  static std::string node_process_platform_arch() {
#if defined(__APPLE__) && defined(__aarch64__)
    return "darwin-arm64";
#elif defined(__APPLE__) && defined(__x86_64__)
    return "darwin-x64";
#elif defined(__linux__) && defined(__aarch64__)
    return "linux-arm64";
#elif defined(__linux__)
    return "linux-x64";
#else
    return "unknown";
#endif
  }

  // 从环境变量构建；argv 提供 --state-dir / --web-dir / --port
  static Config from_env(int argc = 0, char** argv = nullptr);
};

inline Config Config::from_env(int argc, char** argv) {
  Config c;
  c.host = util::env::str("ZPROXY_HOST", c.host);
  c.port = (int)util::env::i64("ZPROXY_PORT", c.port);
  c.client_token = util::env::str("ZPROXY_TOKEN", "");
  c.default_model = util::env::str("ZPROXY_DEFAULT_MODEL", c.default_model);
  if (auto m = util::env::str_opt("ZPROXY_MODEL_MAP")) {
    try { c.env_model_map = nlohmann::json::parse(*m); } catch (...) {}
  }
  c.upstream = util::env::str("ZPROXY_UPSTREAM", c.upstream);
  c.app_version = util::env::str("ZPROXY_APP_VERSION", c.app_version);
  c.cooldown_401_ms = util::env::i64("ZPROXY_COOLDOWN_401_MS", c.cooldown_401_ms);
  c.cooldown_429_ms = util::env::i64("ZPROXY_COOLDOWN_429_MS", c.cooldown_429_ms);
  c.retry_3009_ms = util::env::i64("ZPROXY_RETRY_3009_MS", c.retry_3009_ms);
  c.retry_3009_max = (int)util::env::i64("ZPROXY_RETRY_3009_MAX", c.retry_3009_max);
  c.creds_path = util::fs::expanduser(util::env::str("ZPROXY_CREDS", "~/.zcode/v2/credentials.json"));
  c.rollout_dir = util::fs::expanduser(util::env::str("ZPROXY_ROLLOUT_DIR", "~/.zcode/cli/rollout"));
  c.tokens_file_override = util::env::str("ZPROXY_TOKENS_FILE", "");
  c.routing_mode_default = util::env::str("ZPROXY_ROUTING_MODE", c.routing_mode_default);
  c.claim_concurrency = (int)util::env::i64("ZPROXY_CLAIM_CONCURRENCY", c.claim_concurrency);
  c.sync_ms = util::env::i64("ZPROXY_SYNC_MS", c.sync_ms);
  c.blocked_retry = util::env::boolean("ZPROXY_BLOCKED_RETRY", false);
  c.blocked_retry_ms = util::env::i64("ZPROXY_BLOCKED_RETRY_MS", c.blocked_retry_ms);
  c.credential_secret_override = util::env::str("ZCODE_CREDENTIAL_SECRET", "");

  // state 目录：--state-dir > ZPROXY_STATE_DIR > 可执行文件所在目录 > cwd
  std::string arg_state, arg_web;
  int arg_port = -1;
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : ""; };
    if (a == "--state-dir") arg_state = next();
    else if (a == "--web-dir") arg_web = next();
    else if (a == "--port") arg_port = std::atoi(next().c_str());
  }
  c.state_dir = !arg_state.empty() ? arg_state : util::env::str("ZPROXY_STATE_DIR", "");
  if (c.state_dir.empty()) {
    char buf[4096];
    uint32_t size = sizeof(buf);
    std::string exe_dir;
#if defined(__APPLE__)
    if (_NSGetExecutablePath(buf, &size) == 0) {
      char real[4096];
      if (realpath(buf, real)) {
        std::string p = real;
        auto pos = p.find_last_of('/');
        if (pos != std::string::npos) exe_dir = p.substr(0, pos);
      }
    }
#endif
    c.state_dir = exe_dir.empty() ? "." : exe_dir;
  }
  if (arg_port > 0) c.port = arg_port;

  // web 目录：--web-dir > ZPROXY_WEB_DIR > <state>/web（存在）> ./web
  c.web_dir = !arg_web.empty() ? arg_web : util::env::str("ZPROXY_WEB_DIR", "");
  if (c.web_dir.empty()) {
    std::string cand = c.path("web");
    c.web_dir = util::fs::is_dir(cand) ? cand : "./web";
  }
  return c;
}

} // namespace zproxy
