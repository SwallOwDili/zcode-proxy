// L2 store — pricing.json：{model:{in,out}}（CNY / 1M tokens），热重载
#pragma once
#include <cctype>
#include <map>
#include <optional>
#include <string>
#include "nlohmann/json.hpp"
#include "store/json_store.hpp"

namespace zproxy::store {

struct Price { double in = 0, out = 0; };

class PricingStore : public JsonFile {
public:
  explicit PricingStore(std::string path) : JsonFile(std::move(path)) {}

  std::map<std::string, Price> prices() {
    if (changed_on_disk() || !loaded_) {
      loaded_ = true;
      file_.clear();
      auto j = read();
      if (j && j->is_object()) {
        for (auto m = j->begin(); m != j->end(); ++m) {
          if (m.value().is_object() && m.value().contains("in") && m.value().contains("out")) {
            file_[m.key()] = Price{m.value()["in"].get<double>(), m.value()["out"].get<double>()};
          }
        }
      }
    }
    std::map<std::string, Price> out = defaults_;
    for (auto& [k, v] : file_) out[k] = v;
    return out;
  }

  std::optional<Price> model_price(const std::string& model) {
    if (model.empty()) return std::nullopt;
    auto m = prices();
    auto it = m.find(model);
    if (it != m.end()) return it->second;
    std::string low = util_lower(model);
    it = m.find(low);
    if (it != m.end()) return it->second;
    return std::nullopt;
  }

  bool save_file_prices(const std::map<std::string, Price>& p) {
    nlohmann::json j = nlohmann::json::object();
    for (auto& [k, v] : p) j[k] = {{"in", v.in}, {"out", v.out}};
    file_ = p;
    loaded_ = true;
    return write(j, 2);
  }

  static const std::map<std::string, Price>& defaults() {
    static const std::map<std::string, Price> d = {
      {"GLM-5.3", {8, 28}},
      {"GLM-5.3-Flash", {0.8, 2.8}},
      {"GLM-5.3-FlashX", {2, 7}},
    };
    return d;
  }

private:
  static std::string util_lower(std::string s) {
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
  }
  std::map<std::string, Price> defaults_ = defaults();
  std::map<std::string, Price> file_;
  bool loaded_ = false;
};

} // namespace zproxy::store
