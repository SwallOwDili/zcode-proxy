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
  void load() {
    { std::lock_guard<std::mutex> lk(mu_); injected_ = nullptr; }
    std::string bundled = cfg_.path("zcode-system-prompt.json");
    // 1) bundled
    if (auto raw = util::fs::read_file(bundled)) {
      try {
        auto j = nlohmann::json::parse(*raw);
        if (j.is_array() && !j.empty()) { blocks_ = j.get<std::vector<nlohmann::json>>(); return; }
      } catch (...) {}
    }
    // 2) 扫描 rollout dump（mtime 降序，行从后往前找 request.body.system 非空数组）
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
      auto raw = util::fs::read_file(p);
      if (!raw) continue;
      auto lines = util::split(*raw, '\n');
      for (auto it = lines.rbegin(); it != lines.rend(); ++it) {
        std::string line = *it;
        if (line.empty()) continue;
        try {
          auto j = nlohmann::json::parse(line);
          if (j.contains("request") && j["request"].is_object() &&
              j["request"].contains("body") && j["request"]["body"].is_object() &&
              j["request"]["body"].contains("system")) {
            const auto& sys = j["request"]["body"]["system"];
            if (sys.is_array() && !sys.empty()) {
              blocks_ = sys.get<std::vector<nlohmann::json>>();
              util::fs::write_file(bundled, j["request"]["body"]["system"].dump(2) + "\n");
              util::log("system prompt refreshed from " + p + " (" + std::to_string(blocks_.size()) + " blocks)");
              return;
            }
          }
        } catch (...) {}
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
