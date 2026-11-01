// L4 protocol — 模型名映射（mapModel 语义：内置 < env < model-map.json；未知非 GLM 回落默认）
#pragma once
#include <cctype>
#include <string>
#include "store/modelmap_store.hpp"
#include "util/config.hpp"

namespace zproxy::protocol {

// GLM-* 原样透传判定：前缀比较（原版每请求构造 std::regex ~μs 级，纯浪费）
inline bool is_glm_prefix(const std::string& model) {
  if (model.size() < 3) return false;
  return std::tolower((unsigned char)model[0]) == 'g' &&
         std::tolower((unsigned char)model[1]) == 'l' &&
         std::tolower((unsigned char)model[2]) == 'm';
}

inline std::string map_model(store::ModelMapStore& mms, const std::string& cfg_default, const std::string& model) {
  if (model.empty()) return cfg_default;
  const auto& m = mms.effective(); // 引用绑定：effective() 已缓存，勿拷贝
  auto it = m.find(model);
  if (it != m.end()) return it->second;
  if (is_glm_prefix(model)) return model; // GLM-* 原样透传
  return cfg_default;
}

} // namespace zproxy::protocol
