// L5 service — /v1/models 与 /health
#pragma once
#include <set>
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "service/app_context.hpp"
#include "util/time_util.hpp"

namespace zproxy::service {

class ApiService {
public:
  explicit ApiService(AppContext& ctx) : ctx_(ctx) {}

  void handle_models(httplib::Response& res) {
    std::set<std::string> ids{ctx_.cfg.default_model, "GLM-5.3", "GLM-5.3-Flash"};
    for (auto& [k, v] : ctx_.modelmap.effective()) {
      ids.insert(k);
      ids.insert(v);
    }
    nlohmann::json data = nlohmann::json::array();
    for (auto& id : ids) data.push_back({{"id", id}, {"object", "model"}, {"owned_by", "zcode-proxy"}});
    res.set_content(nlohmann::json({{"object", "list"}, {"data", data}}).dump(), "application/json");
  }

  nlohmann::json health_json() {
    auto accs = ctx_.pool.accounts();
    auto paused = ctx_.paused.paused();
    bool any_ready = false;
    nlohmann::json list = nlohmann::json::array();
    for (auto& a : accs) {
      bool is_paused = paused.count(a.name) > 0;
      bool cooled = ctx_.pool.cooled_for(a, "");
      if (!is_paused && !cooled) any_ready = true;
      std::string status = is_paused ? "paused"
                                     : (ctx_.pool.cooldown_desc(a) == "healthy" ? "healthy" : ctx_.pool.cooldown_desc(a));
      list.push_back({{"name", a.name},
                      {"jwt", a.jwt.empty() ? "MISSING" : "loaded (" + std::to_string(a.jwt.size()) + " chars)"},
                      {"region", a.region}, {"status", status}});
    }
    nlohmann::json mm = nlohmann::json::object();
    for (auto& [k, v] : ctx_.modelmap.effective()) mm[k] = v;
    return {
      {"ok", any_ready && ctx_.sys.size() > 0},
      {"accountSource", ctx_.pool.source()},
      {"accounts", list},
      {"systemPromptBlocks", ctx_.sys.size()},
      {"defaultModel", ctx_.cfg.default_model},
      {"modelMap", mm},
      {"void", util::time_util::now_ms()},
    };
  }
  nlohmann::json models_json() {
    std::set<std::string> ids{ctx_.cfg.default_model, "GLM-5.3", "GLM-5.3-Flash"};
    for (auto& [k, v] : ctx_.modelmap.effective()) {
      ids.insert(k);
      ids.insert(v);
    }
    nlohmann::json data = nlohmann::json::array();
    for (auto& id : ids) data.push_back({{"id", id}, {"object", "model"}, {"owned_by", "zcode-proxy"}});
    return {{"object", "list"}, {"data", data}};
  }

  void handle_health(httplib::Response& res) {
    auto accs = ctx_.pool.accounts();
    auto paused = ctx_.paused.paused();
    bool any_ready = false;
    nlohmann::json list = nlohmann::json::array();
    for (auto& a : accs) {
      bool is_paused = paused.count(a.name) > 0;
      bool cooled = ctx_.pool.cooled_for(a, "");
      if (!is_paused && !cooled) any_ready = true;
      std::string status;
      if (is_paused) status = "paused";
      else {
        std::string cd = ctx_.pool.cooldown_desc(a);
        status = cd == "healthy" ? "healthy" : cd;
      }
      nlohmann::json j = {{"name", a.name},
                          {"jwt", a.jwt.empty() ? "MISSING" : "loaded (" + std::to_string(a.jwt.size()) + " chars)"},
                          {"region", a.region},
                          {"status", status}};
      if (a.user_info.present && !a.user_info.name.empty()) j["profile"] = a.user_info.name;
      list.push_back(std::move(j));
    }
    nlohmann::json out = {
      {"ok", any_ready && ctx_.sys.size() > 0},
      {"accountSource", ctx_.pool.source()},
      {"accounts", list},
      {"systemPromptBlocks", ctx_.sys.size()},
      {"defaultModel", ctx_.cfg.default_model},
      {"void", util::time_util::now_ms()},
    };
    // modelMap（与 Node health 字段对齐）
    nlohmann::json mm = nlohmann::json::object();
    for (auto& [k, v] : ctx_.modelmap.effective()) mm[k] = v;
    out["modelMap"] = mm;
    res.set_content(out.dump(), "application/json");
  }

private:
  AppContext& ctx_;
};

} // namespace zproxy::service
