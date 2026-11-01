// L2 store — model-map.json：别名 → 目标模型（null 值表示删除该别名）
#pragma once
#include <map>
#include <optional>
#include <string>
#include "nlohmann/json.hpp"
#include "store/json_store.hpp"
#include "util/config.hpp"

namespace zproxy::store {

class ModelMapStore : public JsonFile {
public:
  ModelMapStore(std::string path, const Config& cfg) : JsonFile(std::move(path)) {
    builtin_ = {
      {"deepseek-chat", "GLM-5.3-Flash"},
      {"deepseek-reasoner", "GLM-5.3"},
      {"deepseek-v4.1-flash", "GLM-5.3-Flash"},
    };
    if (cfg.env_model_map.is_object()) {
      for (auto it = cfg.env_model_map.begin(); it != cfg.env_model_map.end(); ++it) {
        if (it.value().is_string()) env_[it.key()] = it.value().get<std::string>();
      }
    }
  }

  // 有效映射 = 内置默认 < 环境变量 < model-map.json（文件里 null 等效删除）。
  // 缓存合并结果（mtime 变化才重建），热路径返回 const& —— 原版每请求重建/拷贝整张 map。
  const std::map<std::string, std::string>& effective() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!loaded_ || changed_on_disk()) {
      loaded_ = true;
      file_.clear();
      effective_.clear();
      auto j = read_nolock(); // 已持 mu_；read() 是自加锁版本，再入即死锁
      if (j && j->is_object()) {
        for (auto it = j->begin(); it != j->end(); ++it) {
          if (it.value().is_string()) file_[it.key()] = it.value().get<std::string>();
        }
      }
      effective_ = builtin_;
      for (auto& [k, v] : env_) effective_[k] = v;
      for (auto& [k, v] : file_) effective_[k] = v;
    }
    return effective_;
  }

  // PUT /admin/modelmap：map 中 optional 为空 = 删除该别名
  bool save_map(const std::map<std::string, std::optional<std::string>>& m) {
    nlohmann::json j = nlohmann::json::object();
    std::map<std::string, std::string> eff = builtin_;
    for (auto it = m.begin(); it != m.end(); ++it) {
      if (it->second) { j[it->first] = *it->second; eff[it->first] = *it->second; }
    }
    file_ = eff; // 内置别名未包含 = 置 null 移除
    loaded_ = true;
    return write(j, 0);
  }

private:
  std::map<std::string, std::string> builtin_;
  std::map<std::string, std::string> env_;
  std::map<std::string, std::string> file_;
  std::map<std::string, std::string> effective_;
  bool loaded_ = false;
};

} // namespace zproxy::store
