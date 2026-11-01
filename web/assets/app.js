/* zcode-proxy 管理台 — 公共脚本：布局 / 菜单 / API / 工具 */

let TOKEN = localStorage.getItem("zproxy_token") || "";

/* ---------------- 菜单配置（功能分菜单） ---------------- */
const NAV = [
  {
    group: "概览",
    items: [
      { key: "index", label: "仪表盘", icon: "📊", href: "/admin/index.html" },
    ],
  },
  {
    group: "账号",
    items: [
      { key: "accounts", label: "账号列表", icon: "👥", href: "/admin/accounts.html", badge: "accounts" },
      { key: "add-account", label: "添加 / 登录", icon: "➕", href: "/admin/add-account.html" },
      { key: "quota", label: "额度套餐", icon: "💎", href: "/admin/quota.html" },
      { key: "claim", label: "每日领取", icon: "🎁", href: "/admin/claim.html" },
    ],
  },
  {
    group: "统计",
    items: [
      { key: "usage", label: "用量统计", icon: "📈", href: "/admin/usage.html" },
      { key: "requests", label: "请求日志", icon: "📜", href: "/admin/requests.html" },
    ],
  },
  {
    group: "配置",
    items: [
      { key: "sysprompt", label: "注入提示词", icon: "✏️", href: "/admin/sysprompt.html" },
      { key: "models", label: "模型映射", icon: "🔀", href: "/admin/models.html" },
      { key: "pricing", label: "价目设置", icon: "💰", href: "/admin/pricing.html" },
    ],
  },
  {
    group: "调试",
    items: [
      { key: "playground", label: "模拟对话", icon: "💬", href: "/admin/playground.html" },
      { key: "status", label: "服务状态", icon: "🩺", href: "/admin/status.html" },
    ],
  },
];

/* ---------------- 工具 ---------------- */
/* HTML 实体表用 charCode 构造，避免源码中出现裸实体 */
const ENT = (() => {
  const A = String.fromCharCode(38), S = String.fromCharCode(59);
  return { "&": A + "amp" + S, "<": A + "lt" + S, ">": A + "gt" + S, '"': A + "quot" + S };
})();
function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) => ENT[c]);
}
function maskJwt(jwt) { return jwt.length > 24 ? jwt.slice(0, 14) + "…" + jwt.slice(-6) + ` (${jwt.length})` : jwt; }
function fmtUnits(n) {
  if (n == null) return "?";
  if (n >= 0.1e12) return (n / 1e12).toFixed(2) + "T";
  if (n >= 0.1e9) return (n / 1e9).toFixed(2) + "B";
  if (n >= 0.1e6) return (n / 1e6).toFixed(2) + "M";
  if (n >= 0.1e3) return (n / 1e3).toFixed(1) + "K";
  return String(n);
}
function fmtTime(t) {
  if (!t) return "–";
  const d = new Date(t);
  if (Number.isNaN(d.getTime())) return String(t);
  return d.toLocaleTimeString([], { hour12: false });
}
/* 到期时间展示：精确到秒的本地时间，如 10-30 22:30:15 */
function fmtEnds(t) {
  if (!t) return "";
  const d = new Date(t);
  if (Number.isNaN(d.getTime())) return String(t);
  const p = (n, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
/* 距到期剩余：{ expired, days, hours, mins, secs, totalSecs }；传 endsAt（ISO） */
function remainOf(t) {
  const d = new Date(t);
  if (!t || Number.isNaN(d.getTime())) return null;
  let s = Math.floor((d.getTime() - Date.now()) / 1000);
  const expired = s <= 0;
  if (expired) s = 0;
  return {
    expired,
    days: Math.floor(s / 86400),
    hours: Math.floor((s % 86400) / 3600),
    mins: Math.floor((s % 3600) / 60),
    secs: s % 60,
    totalSecs: s,
  };
}
/* 剩余时间文案：>2 天显示“剩 N 天”，否则显示“剩 N天HH:mm:ss”，已过期提示 */
function remainText(r) {
  if (!r) return "";
  if (r.expired) return "已过期";
  if (r.days >= 2) return `剩 ${r.days} 天`;
  const p = (n) => String(n).padStart(2, "0");
  return `剩 ${r.days}天${p(r.hours)}:${p(r.mins)}:${p(r.secs)}`;
}

let _toastTimer = null;
function toast(msg, err) {
  const t = document.getElementById("toast");
  if (!t) return;
  t.textContent = msg;
  t.className = "toast" + (err ? " err" : "");
  void t.offsetWidth;
  t.classList.add("show");
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove("show"), 3500);
}

async function api(path, opts = {}) {
  const headers = { "content-type": "application/json", ...(TOKEN ? { authorization: `Bearer ${TOKEN}` } : {}) };
  const res = await fetch(path, { ...opts, headers });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) {
    TOKEN = prompt("此代理设置了访问令牌（ZPROXY_TOKEN），请输入：") || "";
    localStorage.setItem("zproxy_token", TOKEN);
    if (TOKEN) return api(path, opts);
    throw new Error("需要访问令牌");
  }
  if (!res.ok) throw new Error(data.error?.message ?? data.error ?? `HTTP ${res.status}`);
  return data;
}

const badge = (cls, txt) => `<span class="badge ${cls}"><span class="dot"></span>${esc(txt)}</span>`;
const statusBadge = (s) => s === "healthy" ? badge("b-green", "healthy")
  : String(s).startsWith("cooldown") ? badge("b-yellow", s)
  : badge("b-red", s);

/* ---------------- 布局注入 ---------------- */
function renderLayout(activeKey) {
  const navHtml = NAV.map((g) => `
    <div class="nav-group">
      <div class="nav-group-title">${esc(g.group)}</div>
      ${g.items.map((it) => `
        <a class="nav-item${it.key === activeKey ? " active" : ""}" href="${it.href}" data-nav-key="${it.key}">
          <span class="ico">${it.icon}</span>
          <span class="lbl">${esc(it.label)}</span>
          ${it.badge ? `<span class="nav-badge" data-badge="${it.badge}" hidden>0</span>` : ""}
        </a>`).join("")}
    </div>`).join("");

  const collapsed = localStorage.getItem("zproxy_nav_collapsed") === "1";
  if (collapsed) document.body.classList.add("nav-collapsed");
  if (localStorage.getItem("zproxy_privacy") === "1") document.body.classList.add("privacy");

  document.body.insertAdjacentHTML("afterbegin", `
    <div class="layout">
      <aside class="sidebar">
        <div class="sidebar-head">
          <div class="logo">⚡</div>
          <div class="txt"><b>zcode<em>proxy</em></b><span>CONSOLE</span></div>
        </div>
        <nav class="sidebar-nav">${navHtml}</nav>
        <div class="sidebar-foot">
          <span class="st" id="sbListen">–</span>
          <button class="sidebar-collapse" id="btnCollapse" title="收起 / 展开菜单">⟨</button>
        </div>
      </aside>
      <div class="main">
        <header class="topbar">
          <div class="crumb">
            <h1 id="pageTitle">–</h1>
            <span class="sub" id="pageSub"></span>
          </div>
          <div class="spacer"></div>
          <div class="topstatus">
            <button class="badge b-gray" id="routingPill" onclick="toggleRouting()" style="cursor:pointer" title="点击切换：TPS 优先（负载最小，并发强）/ 缓存优先（会话亲和，缓存命中高）">路由 –</button>
            <button class="badge b-gray" id="privacyPill" onclick="togglePrivacy()" style="cursor:pointer" title="隐私模式：隐藏账号名 / 邮箱 / 用户ID / JWT 等敏感信息">隐私 关</button>
            <span id="topBadgeWrap"><span class="badge b-gray"><span class="dot"></span>检测中…</span></span>
            <span class="listen" id="topListen"></span>
          </div>
          <button onclick="location.reload()">刷新</button>
        </header>
        <main class="content" id="pageContent"></main>
      </div>
    </div>`);

  document.getElementById("btnCollapse").addEventListener("click", () => {
    document.body.classList.toggle("nav-collapsed");
    localStorage.setItem("zproxy_nav_collapsed", document.body.classList.contains("nav-collapsed") ? "1" : "0");
    document.getElementById("btnCollapse").textContent = document.body.classList.contains("nav-collapsed") ? "⟩" : "⟨";
  });
  if (collapsed) document.getElementById("btnCollapse").textContent = "⟩";

  refreshNavBadges();
}

/* 顶部状态条 + 侧栏监听地址 */
async function refreshStatusBar() {
  try {
    const h = await api("/admin/summary");
    const bw = document.getElementById("topBadgeWrap");
    if (bw) bw.innerHTML = h.ok ? badge("b-green", "服务正常") : badge("b-red", "服务异常");
    const pp = document.getElementById("privacyPill");
    if (pp) {
      const on = localStorage.getItem("zproxy_privacy") === "1";
      pp.className = "badge " + (on ? "b-blue" : "b-gray");
      pp.innerHTML = `<span class="dot"></span>隐私 ${on ? "开" : "关"}`;
    }
    const rp = document.getElementById("routingPill");
    if (rp) {
      const mode = h.routingMode;
      rp.className = "badge " + (mode === "tps" ? "b-yellow" : "b-blue");
      rp.innerHTML = `<span class="dot"></span>${mode === "tps" ? "TPS 优先" : "缓存优先"}${h.affinitySessions ? ` · ${h.affinitySessions}` : ""}`;
    }
    const tl = document.getElementById("topListen");
    if (tl) tl.textContent = h.listen ?? "";
    const sb = document.getElementById("sbListen");
    if (sb) sb.textContent = h.listen ?? "";
    return h;
  } catch {
    const bw = document.getElementById("topBadgeWrap");
    if (bw) bw.innerHTML = badge("b-red", "服务异常");
    return null;
  }
}

window.togglePrivacy = function () {
  const on = localStorage.getItem("zproxy_privacy") === "1";
  localStorage.setItem("zproxy_privacy", on ? "0" : "1");
  document.body.classList.toggle("privacy", !on);
  const pp = document.getElementById("privacyPill");
  if (pp) { pp.className = "badge " + (!on ? "b-blue" : "b-gray"); pp.innerHTML = `<span class="dot"></span>隐私 ${!on ? "开" : "关"}`; }
  toast(!on ? "🔒 隐私模式已开启：账号名/邮箱/用户ID/JWT 已打码" : "隐私模式已关闭");
};

window.toggleRouting = async function () {
  try {
    const cur = (await api("/admin/routing")).mode;
    const next = cur === "tps" ? "cache" : "tps";
    await api("/admin/routing", { method: "PUT", body: JSON.stringify({ mode: next }) });
    toast(next === "tps" ? "已切换：TPS 优先（负载最小，不看会话亲和）" : "已切换：缓存优先（会话亲和优先，缓存命中高）");
    refreshStatusBar();
  } catch (e) { toast(e.message ?? String(e), true); }
};

/* 侧栏徽标：账号数 */
async function refreshNavBadges() {
  try {
    const list = await api("/admin/accounts");
    const el = document.querySelector('[data-badge="accounts"]');
    if (el) {
      el.textContent = list.accounts.length;
      el.hidden = list.accounts.length === 0;
    }
  } catch {}
}

/* 页面统一启动钩子 */
function bootPage(activeKey, title, sub) {
  renderLayout(activeKey);
  document.getElementById("pageTitle").textContent = title;
  document.getElementById("pageSub").textContent = sub ?? "";
  document.title = `${title} · zcode-proxy`;
  refreshStatusBar();
  setInterval(refreshStatusBar, 5000);
}

/* 请求行费用估算：in×输入价 + cache×缓存价(默认=输入价) + out×输出价 */
let _pricesCache = null;
async function getPrices() {
  if (_pricesCache) return _pricesCache;
  try { _pricesCache = (await api("/admin/pricing")).prices ?? {}; } catch { _pricesCache = {}; }
  return _pricesCache;
}
function rowCost(prices, model, r) {
  const p = prices?.[model] ?? prices?.[String(model ?? "").toLowerCase()];
  if (!p || !(r.in || r.out || r.cache)) return "";
  const cin = p.cache ?? p.in;
  const cost = ((r.in ?? 0) * p.in + (r.cache ?? 0) * cin + (r.out ?? 0) * p.out) / 1e6;
  return cost > 0 ? " · ¥" + cost.toFixed(4).replace(/\.?0+$/, "") : "";
}

/* 报价计算：输入/输出 tokens → 元 */
function costOf(prices, model, i, o) {
  const p = prices[model] ?? prices[String(model).toLowerCase()];
  if (!p) return "—";
  return ((i / 1e6) * p.in + (o / 1e6) * p.out).toFixed(4).replace(/\.?0+$/, "") || "0";
}
