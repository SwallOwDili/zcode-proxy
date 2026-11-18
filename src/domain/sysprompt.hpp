// L3 domain — 系统提示词：bundled zcode-system-prompt.json → rollout dump 反向扫描回填
//              （WAF 硬依赖：不注入则上游 3012）
#pragma once
#include <algorithm>
#include <optional>
#include "nlohmann/json.hpp"
#include "util/config.hpp"
#include "util/fs.hpp"
#include "util/log.hpp"

namespace zproxy::domain {

class SysPrompt {
public:
  explicit SysPrompt(const Config& cfg) : cfg_(cfg) { load(); load_override(); }

  // 原始 blocks（低频：admin 展示用）
  const std::vector<nlohmann::json>& blocks() const { return blocks_; }
  // WAF 必须集：前两块（身份块 + 主段）——消融实验实证，缺一 405；第三块非必须
  std::vector<nlohmann::json> required_blocks() const {
    if (blocks_.size() >= 2) return {blocks_[0], blocks_[1]};
    return blocks_;
  }

  // 用户编辑版（state/sysprompt-edit.json）优先；无则用自动提取（block0 + block1 去DC段）
  std::vector<nlohmann::json> effective_blocks() const {
    if (has_override_) return override_blocks_;
    auto req = required_blocks();
    std::vector<nlohmann::json> out;
    for (auto b : req) {
      if (b.contains("text") && b["text"].is_string()) {
        std::string t = b["text"].get<std::string>();
        auto dc = t.find("# ZCode Desktop Context");
        if (dc != std::string::npos) {
          t = t.substr(0, dc);
          while (!t.empty() && (t.back() == '\n' || t.back() == '\r' || t.back() == ' ')) t.pop_back();
          b["text"] = t;
        }
      }
      out.push_back(std::move(b));
    }
    return out;
  }
  void set_override(std::vector<nlohmann::json> blocks) {
    override_blocks_ = std::move(blocks);
    has_override_ = !override_blocks_.empty();
    nlohmann::json arr = nlohmann::json::array();
    for (auto& b : override_blocks_) arr.push_back(b);
    util::fs::write_file(cfg_.state_dir + "/sysprompt-edit.json", arr.dump(2) + "\n");
  }
  bool has_override() const { return has_override_; }
  void load_override() {
    auto p = cfg_.state_dir + "/sysprompt-edit.json";
    override_blocks_.clear();
    has_override_ = false;
    if (auto raw = util::fs::read_file(p)) {
      try {
        auto j = nlohmann::json::parse(*raw);
        if (j.is_array() && !j.empty()) { override_blocks_ = j.get<std::vector<nlohmann::json>>(); has_override_ = true; }
      } catch (...) {}
    }
  }
  size_t size() const { return blocks_.size(); }

  // 注入用 blocks（末块带 cache_control）——惰性缓存，避免每请求深拷贝整份 system prompt
  const nlohmann::json& injected() {
    std::lock_guard<std::mutex> lk(mu_);
    if (injected_.is_null()) {
      injected_ = blocks_;
      if (injected_.is_array() && !injected_.empty())
        injected_[injected_.size() - 1]["cache_control"] = {{"type", "ephemeral"}};
    }
    return injected_;
  }

  // 手动刷新（启动时已做；admin 可扩展）
  void refresh() { load(); }

private:
  // 从单个 rollout 文件反向扫描最新一条带 system 的请求（找不到返回 false）
  bool extract_from_rollout(const std::string& p, std::vector<nlohmann::json>& out) {
    auto raw = util::fs::read_file(p);
    if (!raw) return false;
    auto lines = util::split(*raw, '\n');
    for (auto it = lines.rbegin(); it != lines.rend(); ++it) {
      if (it->empty()) continue;
      try {
        auto j = nlohmann::json::parse(*it);
        if (j.contains("request") && j["request"].is_object() &&
            j["request"].contains("body") && j["request"]["body"].is_object() &&
            j["request"]["body"].contains("system")) {
          const auto& sys = j["request"]["body"]["system"];
          if (sys.is_array() && !sys.empty()) { out = sys.get<std::vector<nlohmann::json>>(); return true; }
        }
      } catch (...) {}
    }
    return false;
  }

  void load() {
    { std::lock_guard<std::mutex> lk(mu_); injected_ = nullptr; }
    std::string bundled = cfg_.path("zcode-system-prompt.json");
    // bundled 落后于最新 rollout = app 升级改了 system prompt 而代理还在发旧指纹
    // （实测：3.16.3→3.17.1 身份块/主段全变，旧注入块直接触发上游风控软封禁 <block>no）。
    // 只要 rollout 更新就回填覆盖；回填后 bundled mtime ≥ rollout，下次启动不再扫大文件
    std::string newest;
    double newest_m = 0;
    for (auto& f : util::fs::list_dir(cfg_.rollout_dir)) {
      if (util::starts_with(f, "model-io-") && util::ends_with(f, ".jsonl")) {
        std::string p = util::fs::join(cfg_.rollout_dir, f);
        double m = util::fs::mtime_ms(p);
        if (m > newest_m) { newest_m = m; newest = p; }
      }
    }
    bool bundled_ok = false;
    if (auto raw = util::fs::read_file(bundled)) {
      try {
        auto j = nlohmann::json::parse(*raw);
        if (j.is_array() && !j.empty()) bundled_ok = true;
      } catch (...) {}
    }
    if (!newest.empty() && (!bundled_ok || newest_m > util::fs::mtime_ms(bundled) + 1000)) {
      std::vector<nlohmann::json> fresh;
      if (extract_from_rollout(newest, fresh)) {
        blocks_ = std::move(fresh);
        util::fs::write_file(bundled, nlohmann::json(blocks_).dump(2) + "\n");
        util::log("system prompt refreshed from " + newest + " (" + std::to_string(blocks_.size()) + " blocks)");
        return;
      }
    }
    if (bundled_ok) {
      blocks_ = nlohmann::json::parse(*util::fs::read_file(bundled)).get<std::vector<nlohmann::json>>();
      return;
    }
    // bundled 缺失/损坏：逐个 rollout 兜底扫描（mtime 降序）
    std::vector<std::pair<double, std::string>> files;
    for (auto& f : util::fs::list_dir(cfg_.rollout_dir)) {
      if (util::starts_with(f, "model-io-") && util::ends_with(f, ".jsonl")) {
        std::string p = util::fs::join(cfg_.rollout_dir, f);
        double m = util::fs::mtime_ms(p);
        if (m > 0) files.push_back({m, p});
      }
    }
    std::sort(files.begin(), files.end(), [](auto& a, auto& b) { return a.first > b.first; });
    for (auto& [m, p] : files) {
      std::vector<nlohmann::json> fresh;
      if (extract_from_rollout(p, fresh)) {
        blocks_ = std::move(fresh);
        util::fs::write_file(bundled, nlohmann::json(blocks_).dump(2) + "\n");
        util::log("system prompt refreshed from " + p + " (" + std::to_string(blocks_.size()) + " blocks)");
        return;
      }
    }
    util::log("WARN: no system prompt available (upstream will reject with 3012); run one ZCode conversation first");
    blocks_.clear();
  }

  const Config& cfg_;
  std::vector<nlohmann::json> blocks_;
  std::vector<nlohmann::json> override_blocks_;
  bool has_override_ = false;
  nlohmann::json injected_ = nullptr; // 注入缓存（末块 cache_control）
  std::mutex mu_;
};

} // namespace zproxy::domain
