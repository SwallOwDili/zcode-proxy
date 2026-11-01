// L5 service — 应用上下文：配置 + 全部 store/domain/client 的装配点（DI 根）
#pragma once
#include <memory>
#include "domain/account_pool.hpp"
#include "domain/recent.hpp"
#include "domain/sysprompt.hpp"
#include "domain/tps.hpp"
#include "store/modelmap_store.hpp"
#include "store/claim_store.hpp"
#include "store/paused_store.hpp"
#include "store/pricing_store.hpp"
#include "store/routing_store.hpp"
#include "store/tokens_store.hpp"
#include "store/usage_store.hpp"
#include "upstream/zcode_client.hpp"
#include "util/config.hpp"

namespace zproxy::service {

struct AppContext {
  Config cfg;
  store::TokensStore tokens;
  store::PausedStore paused;
  store::RoutingStore routing;
  store::ModelMapStore modelmap;
  store::PricingStore pricing;
  store::UsageStore usage;
  store::ClaimStore claim;
  domain::AccountPool pool;
  domain::SysPrompt sys;
  domain::TpsStats tps;
  domain::RecentLog recent;
  upstream::ZcodeClient client;

  AppContext(Config c)
      : cfg(std::move(c)),
        tokens(cfg.tokens_file_override.empty() ? cfg.path("tokens.json") : cfg.tokens_file_override),
        paused(cfg.path("paused.json")),
        routing(cfg.path("routing.json"), cfg),
        modelmap(cfg.path("model-map.json"), cfg),
        pricing(cfg.path("pricing.json")),
        usage(cfg.path("usage.json")),
        claim(cfg.path("claim-state.json")),
        pool(cfg, tokens, paused),
        sys(cfg),
        client(cfg, pool, sys) {
    pool.set_routing_mode_getter([this] { return routing.mode(); });
    recent.set_broadcast([this](const nlohmann::json& msg) {
      if (live_broadcast) live_broadcast(msg);
    });
  }

  // SSE live 广播钩子 + 速率快照 getter（LiveService 构造时挂载）
  std::function<void(const nlohmann::json&)> live_broadcast;
  std::function<nlohmann::json()> live_rate_getter;

  // recordRecent 等价（含 WS→SSE 广播）
  void record(const domain::RecentEntry& e) { recent.record(e); }

  void usage_record(const std::string& account, const std::string& model, int64_t in_tok, int64_t out_tok,
                    int64_t cache_tok) {
    if (account.empty()) return;
    usage.record(account, model, in_tok, out_tok, cache_tok);
  }
};

} // namespace zproxy::service
