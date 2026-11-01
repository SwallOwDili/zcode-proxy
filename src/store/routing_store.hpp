// L2 store — routing.json：{"mode":"tps"|"cache"}
#pragma once
#include <string>
#include "store/json_store.hpp"
#include "util/config.hpp"

namespace zproxy::store {

class RoutingStore : public JsonFile {
public:
  RoutingStore(std::string path, const Config& cfg) : JsonFile(std::move(path)), mode_(cfg.routing_mode_default) {}

  std::string mode() {
    if (changed_on_disk()) {
      auto j = read();
      if (j && j->is_object() && j->contains("mode") && (*j)["mode"].is_string()) {
        std::string m = (*j)["mode"].get<std::string>();
        if (m == "tps" || m == "cache") mode_ = m;
      }
    }
    return mode_;
  }
  bool set_mode(const std::string& m) {
    if (m != "tps" && m != "cache") return false;
    mode_ = m;
    nlohmann::json j = {{"mode", m}};
    return write(j, 1);
  }

private:
  std::string mode_;
};

} // namespace zproxy::store
