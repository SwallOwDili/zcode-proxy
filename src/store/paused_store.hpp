// L2 store — paused.json：暂停账号名单（JSON 数组）
#pragma once
#include <set>
#include <string>
#include "store/json_store.hpp"

namespace zproxy::store {

class PausedStore : public JsonFile {
public:
  explicit PausedStore(std::string path) : JsonFile(std::move(path)) {}

  std::set<std::string> paused() {
    if (changed_on_disk()) {
      auto j = read();
      std::set<std::string> out;
      if (j && j->is_array()) {
        for (auto& e : *j) if (e.is_string()) out.insert(e.get<std::string>());
      }
      paused_ = out;
    }
    return paused_;
  }
  bool set_paused(const std::set<std::string>& p) {
    paused_ = p;
    nlohmann::json j = nlohmann::json::array();
    for (auto& s : p) j.push_back(s);
    return write(j, 0);
  }

private:
  std::set<std::string> paused_;
};

} // namespace zproxy::store
