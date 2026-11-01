// L2 store — tokens.json（多账号持久化；语义映射在 domain 层）
#pragma once
#include <optional>
#include "nlohmann/json.hpp"
#include "store/json_store.hpp"

namespace zproxy::store {

class TokensStore : public JsonFile {
public:
  explicit TokensStore(std::string path) : JsonFile(std::move(path)) {}

  // 返回原样 JSON（array 或 {"accounts":[...]}，domain 层做归一化）
  std::optional<nlohmann::json> load() { return read(); }
  bool save(const nlohmann::json& arr) { return write(arr, 2); }
};

} // namespace zproxy::store
