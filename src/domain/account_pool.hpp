// L3 domain — 账号池：**内存权威**架构
//   启动时从 tokens.json 一次性恢复（不存在则回退本机 credentials.json）；
//   运行时一切增删改只改内存 + 置 dirty；后台线程定时把内存快照异步刷回 tokens.json
//   （原子写，可配间隔）；停机时 flush。
//   运行时不再读 tokens.json（外部手工改文件需重启或走 admin API 生效）。
//   索引：by_name / by_jwt / by_uid —— lease/find/upsert/remove/mark_cooldown 全部 O(1)。
//   pick() 的冷却过滤仍是 O(N) 全表扫描（账号 ≥1 万时需改就绪队列，见 README）。
#pragma once
#include <atomic>
#include <set>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <vector>
#include "crypto/sha256.hpp"
#include "domain/account.hpp"
#include "store/creds_store.hpp"
#include "store/paused_store.hpp"
#include "store/tokens_store.hpp"
#include "util/config.hpp"
#include "util/log.hpp"
#include "util/time_util.hpp"

namespace zproxy::domain {

struct AffinityEntry {
  std::string account;
  int64_t at = 0;
};

class AccountPool {
public:
  AccountPool(const Config& cfg, store::TokensStore& tokens, store::PausedStore& paused)
      : cfg_(cfg), tokens_(tokens), paused_(paused) {
    tokens_path_ = cfg.tokens_file_override.empty() ? tokens.path() : cfg.tokens_file_override;
    load_once();
    sync_thread_ = std::thread([this] { sync_loop(); });
  }
  ~AccountPool() {
    stop_ = true;
    if (sync_thread_.joinable()) sync_thread_.join();
    flush_now();
  }

  const std::string& source() const { return source_; }

  // 账号数（call 热路径）
  size_t size() {
    std::shared_lock<std::shared_mutex> lk(rw_);
    return accounts_.size();
  }

  // 快照（拷贝；admin 低频路径用）
  std::vector<Account> accounts() {
    std::shared_lock<std::shared_mutex> lk(rw_);
    return accounts_;
  }

  // 单账号快照（O(1) 索引；admin 单账号路径用，避免大表拷贝）
  std::optional<Account> get(const std::string& name) {
    std::shared_lock<std::shared_mutex> lk(rw_);
    auto it = by_name_.find(name);
    if (it == by_name_.end()) return std::nullopt;
    return accounts_[it->second];
  }

  // ---- 选号：per-model 就绪表 + atomic 轮转（热路径零锁零扫描）----
  // 就绪表（ReadyIndex）由维护路径异步重建（sync 线程周期全量 + mark_cooldown 即时摘除），
  // pick 通过 atomic<shared_ptr> 读快照：O(1)、无锁、多核并行。
  // 轮转替代 Node 的「全局最小 inflight」——round-robin 本身即均匀分布，伪需求不保留。
  // 全冷却（就绪表为空）时回落全表扫描，保 Node「照样试」语义。
  std::optional<std::string> pick(const std::string& session_key, const std::string& avoid_name,
                                  const std::string& model) {
    std::shared_ptr<const ReadyIndex> snap;
    {
      std::lock_guard<std::mutex> lk(ready_mu_);
      snap = ready_;
    }
    const std::vector<std::string>* list = snap->find(model);
    // 取数顺序：先精确模型桶（该模型无冷却的账号），无则 any 兜底桶（完全无模型冷却的账号）
    if (!list || list->empty()) list = snap->find(std::string(kAnyModel));
    if (!list || list->empty())
      return pick_fallback(session_key, avoid_name, model); // 全冷却：Node「照样试」语义

    std::string routing = routing_mode_getter_ ? routing_mode_getter_() : "tps";
    // cache 模式：亲和命中 → O(1) 校验该账号仍在就绪表 → 直取
    if (routing == "cache" && !session_key.empty()) {
      std::string aff;
      {
        std::lock_guard<std::mutex> lk(aff_mu_);
        auto ait = affinity_.find(session_key);
        if (ait != affinity_.end()) {
          if (util::time_util::now_ms() - ait->second.at > affinity_ttl_ms) affinity_.erase(ait);
          else aff = ait->second.account;
        }
      }
      if (!aff.empty() && aff != avoid_name && snap->member.count(aff)) {
        touch_affinity(session_key, aff);
        return aff;
      }
    }
    // 轮转：thread_local 计数——零共享写、零 cacheline 争抢（32 worker 各转各的），
    // 对快照大小取模后分布依然均匀。avoid 仅作用于亲和路径（对齐 Node pickAccount）。
    static thread_local uint64_t tl_cursor = 0;
    const std::string& name = (*list)[tl_cursor++ % list->size()];
    if (routing == "cache" && !session_key.empty()) touch_affinity(session_key, name);
    return name;
  }

private:
  // 全冷却回落：Node「照样试」语义（低频异常路径，性能不敏感）
  std::optional<std::string> pick_fallback(const std::string& session_key, const std::string& avoid_name,
                                           const std::string& model) {
    std::unique_lock<std::shared_mutex> lk(rw_);
    std::vector<size_t> pool;
    auto paused_set = paused_.paused();
    for (size_t i = 0; i < accounts_.size(); i++) {
      if (!paused_set.count(accounts_[i].name)) pool.push_back(i); // 全冷却：不按冷却过滤
    }
    if (pool.empty()) return std::nullopt;
    size_t chosen = pool[rr_ % pool.size()];
    rr_ = (rr_ + 1) % 1000000;
    return accounts_[chosen].name;
  }
  void touch_affinity(const std::string& key, const std::string& account) {
    std::lock_guard<std::mutex> lk(aff_mu_);
    affinity_[key] = {account, util::time_util::now_ms()};
    if (affinity_.size() > 500) {
      int64_t now = util::time_util::now_ms();
      for (auto it2 = affinity_.begin(); it2 != affinity_.end();) {
        if (now - it2->second.at > affinity_ttl_ms) it2 = affinity_.erase(it2); else ++it2;
      }
      while (affinity_.size() > 500) {
        auto oldest = affinity_.begin();
        for (auto it2 = affinity_.begin(); it2 != affinity_.end(); ++it2)
          if (it2->second.at < oldest->second.at) oldest = it2;
        affinity_.erase(oldest);
      }
    }
  }

public:
  // 在请求路径取账号信息 + 挂在途计数（O(1) 索引）
  struct Lease {
    std::string name, jwt, device_mid, session_id, region, fp_platform, fp_language, app_version;
    bool valid = false;
    int64_t lease_ms = 0;
  };
  Lease lease(const std::string& name) {
    std::unique_lock<std::shared_mutex> lk(rw_);
    auto it = by_name_.find(name);
    if (it == by_name_.end()) return {};
    Account& a = accounts_[it->second];
    Lease l;
    l.valid = true;
    l.name = a.name; l.jwt = a.jwt; l.region = a.region;
    l.device_mid = ensure_device_mid(a);
    l.session_id = ensure_session_id(a);
    l.fp_platform = a.fp_platform; l.fp_language = a.fp_language;
    l.app_version = cfg_.app_version;
    a.inflight++;
    return l;
  }
  void release(const std::string& name) {
    std::unique_lock<std::shared_mutex> lk(rw_);
    auto it = by_name_.find(name);
    if (it != by_name_.end()) accounts_[it->second].inflight--;
  }

  // ---- 冷却（运行时状态，不持久化——与 Node 一致）----
  // billing 拉取后回写模型剩余额度（pick 用它跳过已耗尽模型）
  void set_model_remaining(const std::string& name, const std::string& model, int64_t remaining) {
    std::unique_lock<std::shared_mutex> lk(rw_);
    auto it = by_name_.find(name);
    if (it == by_name_.end()) return;
    accounts_[it->second].model_remaining[model] = remaining;
  }

  void mark_cooldown(const std::string& name, int64_t ms, const std::string& model = "") {
    std::unique_lock<std::shared_mutex> lk(rw_);
    auto it = by_name_.find(name);
    if (it == by_name_.end()) return;
    Account& a = accounts_[it->second];
    int64_t until = util::time_util::now_ms() + ms;
    if (!model.empty()) {
      int64_t& cur = a.model_cooldowns[model];
      cur = std::max(cur, until);
    } else {
      a.cooldown_until = std::max(a.cooldown_until, until);
    }
    // 即时摘出就绪表（冷却中的账号不能等到下一轮重建再被选中）
    rebuild_ready_locked();
  }
  bool cooled_for(const Account& a, const std::string& model) const {
    int64_t now = util::time_util::now_ms();
    if (a.cooldown_until > now) return true;
    auto it = a.model_cooldowns.find(model);
    return it != a.model_cooldowns.end() && it->second > now;
  }
  std::string cooldown_desc(const Account& a) const {
    int64_t now = util::time_util::now_ms();
    std::string out;
    if (a.cooldown_until > now) out = "cooldown " + std::to_string((a.cooldown_until - now + 999) / 1000) + "s";
    std::vector<std::string> ms;
    for (auto& [m, until] : a.model_cooldowns) {
      if (until > now) ms.push_back(m + " " + std::to_string((until - now + 999) / 1000) + "s");
    }
    if (!ms.empty()) {
      std::string j = util_join(ms, ", ");
      if (!out.empty()) out += ", " + j; else out = "cooldown " + j;
    }
    return out.empty() ? "healthy" : out;
  }

  // ---- 增删改（admin / OAuth；只改内存 + 置 dirty，由 sync 线程落盘）----
  // adopt_runtime=true：更新时沿用既有 deviceMid/sessionId/指纹（账号编辑）；
  // false：以传入值为准（OAuth 登录强制新设备指纹）。
  bool upsert(Account acc, const std::string& old_name = "", bool adopt_runtime = true) {
    std::unique_lock<std::shared_mutex> lk(rw_);
    // 同 jwt 或同 userId 去重（对齐 addAccountFromToken）
    std::string uid = acc.jwt_user_id();
    size_t* slot = nullptr;
    if (auto it = by_jwt_.find(acc.jwt); it != by_jwt_.end()) slot = &it->second;
    else if (!uid.empty())
      if (auto it = by_uid_.find(uid); it != by_uid_.end()) slot = &it->second;
    if (slot) {
      Account& a = accounts_[*slot];
      if (!old_name.empty() && a.name != old_name) return false;
      if (adopt_runtime) {
        if (acc.device_mid.empty()) acc.device_mid = a.device_mid;
        if (acc.session_id.empty()) acc.session_id = a.session_id;
        if (!acc.has_fingerprint) { acc.has_fingerprint = a.has_fingerprint; acc.fp_platform = a.fp_platform; acc.fp_language = a.fp_language; }
      }
      std::string new_name = acc.name.empty() ? a.name : acc.name;
      if (new_name != a.name) reindex_name_locked(a.name, new_name, *slot);
      a = acc;
      a.name = new_name;
      dirty_ = true;
      rebuild_ready_locked();
      return true;
    }
    if (!old_name.empty()) {
      auto it = by_name_.find(old_name);
      if (it == by_name_.end()) return false;
      size_t idx = it->second;
      Account& a = accounts_[idx];
      acc.device_mid = acc.device_mid.empty() ? a.device_mid : acc.device_mid;
      acc.session_id = acc.session_id.empty() ? a.session_id : acc.session_id;
      std::string new_name = acc.name.empty() ? old_name : acc.name;
      if (new_name != old_name) reindex_name_locked(old_name, new_name, idx);
      a = acc;
      a.name = new_name;
      dirty_ = true;
      return true;
    }
    // 新增：默认名
    if (acc.name.empty()) {
      std::string base = !uid.empty() && uid.size() >= 8 ? "user-" + uid.substr(0, 8) : "account-" + std::to_string(util::time_util::now_ms());
      acc.name = base;
      int n = 2;
      while (by_name_.count(acc.name)) { base = acc.name + "-" + std::to_string(n++); }
      acc.name = base;
    }
    size_t idx = accounts_.size();
    accounts_.push_back(std::move(acc));
    by_name_[accounts_[idx].name] = idx;
    by_jwt_[accounts_[idx].jwt] = idx;
    if (!uid.empty()) by_uid_[uid] = idx;
    dirty_ = true;
    return true;
  }
  bool remove(const std::string& name) {
    std::unique_lock<std::shared_mutex> lk(rw_);
    auto it = by_name_.find(name);
    if (it == by_name_.end()) return false;
    size_t idx = it->second;
    size_t last = accounts_.size() - 1;
    if (idx != last) {
      // swap-with-last + 修索引
      Account& moved = accounts_[last];
      reindex_name_locked(moved.name, moved.name, idx); // 先清旧映射
      accounts_[idx] = std::move(moved);
      by_name_[accounts_[idx].name] = idx;
      by_jwt_[accounts_[idx].jwt] = idx;
      std::string uid = accounts_[idx].jwt_user_id();
      if (!uid.empty()) by_uid_[uid] = idx;
    }
    accounts_.pop_back();
    by_name_.erase(name);
    dirty_ = true;
    rebuild_ready_locked();
    return true;
  }

  // import-local / OAuth 成功后：切换为 tokens 持久化模式（否则护栏会阻止落盘）
  void enable_persist() {
    std::unique_lock<std::shared_mutex> lk(rw_);
    source_ = "tokens";
    dirty_ = true;
  }

  // 立即把内存快照刷回 tokens.json（停机 / 测试 / 关键变更）
  void flush_now() {
    if (!dirty_.exchange(false)) return;
    if (source_ != "tokens") return; // 护栏：creds 模式不写盘
    nlohmann::json arr;
    {
      std::shared_lock<std::shared_mutex> lk(rw_);
      arr = nlohmann::json::array();
      for (auto& a : accounts_) arr.push_back(a.to_json());
    }
    // 锁外序列化 + 原子写（大表序列化可达秒级，不阻塞请求）
    if (tokens_path_ == tokens_.path()) tokens_.save(arr);
    else util::fs::write_file(tokens_path_, arr.dump(2) + "\n");
  }

  void set_routing_mode_getter(std::function<std::string()> g) { routing_mode_getter_ = std::move(g); }

  size_t affinity_size() {
    std::shared_lock<std::shared_mutex> lk(rw_);
    return affinity_.size();
  }

  static constexpr int64_t affinity_ttl_ms = 6 * 3600 * 1000;

private:
  // ---- 启动恢复（仅此一次；运行时内存为权威）----
  void load_once() {
    std::unique_lock<std::shared_mutex> lk(rw_);
    if (util::fs::is_file(tokens_path_)) {
      auto j = util::fs::read_file(tokens_path_);
      if (j) {
        nlohmann::json parsed;
        try { parsed = nlohmann::json::parse(*j); } catch (...) { parsed = nullptr; }
        auto list = parse_accounts(parsed);
        if (!list.empty()) {
          accounts_ = std::move(list);
          reindex_all_locked();
          rebuild_ready_locked();
          source_ = "tokens";
          util::log("accounts restored from tokens.json: " + std::to_string(accounts_.size()));
          return;
        }
      }
    }
    // 回退本机 credentials.json
    if (util::fs::exists(cfg_.creds_path)) {
      auto creds = store::load_local_creds(cfg_);
      if (creds && !creds->jwt.empty()) {
        Account a;
        a.name = "local-zcode";
        a.jwt = creds->jwt;
        if (!creds->user_info_raw.empty()) {
          try {
            auto u = nlohmann::json::parse(creds->user_info_raw);
            if (u.is_object()) {
              a.user_info.present = true;
              a.user_info.name = u.value("name", u.value("nickname", ""));
              a.user_info.email = u.value("email", "");
              a.user_info.avatar = u.value("avatar", u.value("picture", ""));
            }
          } catch (...) {}
        }
        accounts_.push_back(std::move(a));
        reindex_all_locked();
        rebuild_ready_locked();
        source_ = "creds";
        util::log("accounts restored from local credentials (tokens.json absent)");
        return;
      }
    }
    util::log("no accounts available (tokens.json absent, local creds unavailable)");
  }
  std::vector<Account> parse_accounts(const nlohmann::json& j) {
    std::vector<Account> out;
    nlohmann::json arr = nullptr;
    if (j.is_array()) arr = j;
    else if (j.is_object() && j.contains("accounts") && j["accounts"].is_array()) arr = j["accounts"];
    if (!arr.is_array()) return out;
    int idx = 1;
    for (auto& e : arr) {
      if (e.is_string()) {
        Account a;
        a.name = "acc-" + std::to_string(idx++);
        a.jwt = e.get<std::string>();
        out.push_back(std::move(a));
      } else if (e.is_object()) {
        out.push_back(Account::from_json(e, "acc-" + std::to_string(idx++)));
      }
    }
    return out;
  }
  void reindex_all_locked() {
    by_name_.clear(); by_jwt_.clear(); by_uid_.clear();
    by_name_.reserve(accounts_.size() * 2);
    by_jwt_.reserve(accounts_.size() * 2);
    for (size_t i = 0; i < accounts_.size(); i++) {
      by_name_[accounts_[i].name] = i;
      by_jwt_[accounts_[i].jwt] = i;
      std::string uid = accounts_[i].jwt_user_id();
      if (!uid.empty()) by_uid_[uid] = i;
    }
  }
  // 改名时修 by_jwt/by_uid 指向（by_name 由调用方处理）
  void reindex_name_locked(const std::string& old_name, const std::string& new_name, size_t idx) {
    (void)old_name;
    by_name_.erase(old_name);
    by_name_[new_name] = idx;
  }

  // ---- 定时异步刷盘 ----
  void sync_loop() {
    const int64_t interval = std::max<int64_t>(1000, cfg_.sync_ms);
    int64_t last_ready_rebuild = 0;
    while (!stop_) {
      for (int i = 0; i < 50 && !stop_; i++) std::this_thread::sleep_for(std::chrono::milliseconds(interval / 50 + 1));
      if (stop_) break;
      // 冷却到期回收：周期重建就绪表（低频后台 O(N)，1s 内新冷却到期的账号回归）
      int64_t now = util::time_util::now_ms();
      if (now - last_ready_rebuild >= 1000) {
        std::unique_lock<std::shared_mutex> lk(rw_);
        rebuild_ready_locked();
        last_ready_rebuild = now;
      }
      if (dirty_) flush_now();
    }
  }

  // 重建 per-model 就绪表（需持写锁）：!paused && !cooled。
  // 临时 map 聚合 → 线性向量（热路径 find 是 ≤十几个条目的顺序扫，快于树/哈希）。
  void rebuild_ready_locked() {
    auto paused_set = paused_.paused();
    auto next = std::make_shared<ReadyIndex>();
    std::map<std::string, std::vector<std::string>> buckets;
    int64_t now = util::time_util::now_ms();
    for (auto& a : accounts_) {
      if (paused_set.count(a.name)) continue;
      if (a.cooldown_until > now) continue; // 账号级冷却 → 不进任何桶
      bool has_model_cooldown = false;
      for (auto& [m, until] : a.model_cooldowns) {
        if (until > now) { has_model_cooldown = true; continue; } // 该模型冷却中 → 不进该桶
        buckets[m].push_back(a.name);
        next->member.insert(a.name);
      }
      if (!has_model_cooldown) {
        buckets[std::string(kAnyModel)].push_back(a.name); // 完全无模型冷却 → any 兜底桶
        next->member.insert(a.name);
      }
    }
    for (auto& [m, v] : buckets) next->by_model.push_back({m, std::move(v)});
    std::lock_guard<std::mutex> lk(ready_mu_);
    ready_ = std::move(next);
  }

  std::string ensure_device_mid(Account& a) {
    if (a.device_mid.empty()) {
      a.device_mid = util::uuid();
      if (source_ == "tokens") dirty_ = true; // 懒生成；由 sync 线程落盘
    }
    return a.device_mid;
  }
  std::string ensure_session_id(Account& a) {
    if (a.session_id.empty()) {
      a.session_id = "session_" + util::uuid();
      if (source_ == "tokens") dirty_ = true;
    }
    return a.session_id;
  }
  static std::string util_join(const std::vector<std::string>& v, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < v.size(); i++) { if (i) out += sep; out += v[i]; }
    return out;
  }

  struct ReadyIndex {
    // 自包含快照：只存 name（SSO 覆盖，约 15B/账号）——pick 不回查 accounts_，
    // 旧快照在结构变更后依然有效（无悬空/错位窗口）。桶数 ≤ 十几个，线性扫快于任何树/哈希。
    std::vector<std::pair<std::string, std::vector<std::string>>> by_model;
    std::set<std::string> member; // 就绪账号名（亲和 O(1) 校验）
    const std::vector<std::string>* find(const std::string& m) const {
      for (auto& [k, v] : by_model) if (k == m) return &v;
      return nullptr;
    }
  };
  static constexpr const char* kAnyModel = "\x01any"; // 无模型冷却账号的兜底桶

  const Config& cfg_;
  store::TokensStore& tokens_;
  store::PausedStore& paused_;
  std::string tokens_path_;
  std::string source_; // 启动时定型：tokens | creds
  std::vector<Account> accounts_;
  // libc++ 暂不支持 atomic<shared_ptr>（P0718）：mutex + 拷贝快照代替。
  // pick 锁内仅做一次 shared_ptr 引用计数增减（~几十 ns），锁外使用——等效无锁读路径。
  mutable std::mutex ready_mu_;
  std::shared_ptr<const ReadyIndex> ready_{std::make_shared<ReadyIndex>()};
  std::atomic<uint64_t> cursor_{0};
  std::mutex aff_mu_;
  std::unordered_map<std::string, size_t> by_name_;
  std::unordered_map<std::string, size_t> by_jwt_;
  std::unordered_map<std::string, size_t> by_uid_;
  std::unordered_map<std::string, AffinityEntry> affinity_; // aff_mu_ 保护
  size_t rr_ = 0; // fallback 轮转
  std::atomic<bool> dirty_{false};
  std::atomic<bool> stop_{false};
  std::thread sync_thread_;
  std::function<std::string()> routing_mode_getter_;
  std::shared_mutex rw_;
};

// 会话亲和键：sha256([system, firstUser.content]) 前 16 hex（对齐 Node affinityKey 语义）
inline std::string affinity_key(const nlohmann::json& anthropic_body) {
  std::string system;
  if (anthropic_body.contains("system")) {
    const auto& s = anthropic_body["system"];
    if (s.is_string()) system = s.get<std::string>();
    else system = s.dump();
  }
  std::string first_user;
  if (anthropic_body.contains("messages") && anthropic_body["messages"].is_array()) {
    for (auto& m : anthropic_body["messages"]) {
      if (m.value("role", "") == "user") {
        const auto& c = m.contains("content") ? m["content"] : nlohmann::json(nullptr);
        if (c.is_string()) first_user = c.get<std::string>();
        else if (c.is_array()) {
          for (auto& b : c) if (b.value("type", "") == "text") first_user += b.value("text", "");
        }
        break;
      }
    }
  }
  // 多段流式 hash：免 "system + \x1f + first_user" 的大串拼接临时
  return crypto::sha256_hex_multi({system, std::string_view("\x1f", 1), first_user}).substr(0, 16);
}

} // namespace zproxy::domain
