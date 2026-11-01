<div align="center">

# ⚡ zcode-proxy

**把 ZCode 订阅变成 OpenAI 兼容 API**

C++20 · asio 协程 · 单二进制 · 万级并发

[English](README.md) | [简体中文](README.zh-CN.md)

</div>

---

## 这是什么

本地网关，把已登录的 ZCode（GLM Start Plan）订阅包装成标准 **OpenAI / Anthropic** API。任何 agent 框架指到 `http://127.0.0.1:8787/v1` 即可使用——内置多账号额度池、故障切换和完整管理控制台。

```
WorkBuddy / harness / 任意 OpenAI 客户端
        │
        ▼
┌─────────────────────────────┐
│  zcode-proxy (127.0.0.1:8787)    │
│  · 协议翻译                       │
│  · 账号池与故障切换               │
│  · 用量计费                       │
└─────────────────────────────┘
        │
        ▼
  GLM-5.3 / GLM-5.3-Flash
```

## 亮点

| | |
|---|---|
| 🚀 **协程 I/O** | asio C++20 协程——每连接 KB 级内存，无 thread-per-request |
| 🔀 **多账号额度池** | 轮询 + 会话亲和 + 模型级冷却，O(1) 无锁选号 |
| 🛠 **完整工具调用** | 流式 `tool_calls` 采用官方 OpenAI 增量形状，严格 SDK（AI SDK 等）兼容 |
| 📊 **管理控制台** | 仪表盘 / 账号 / 额度 / 每日领取 / 用量分析——内置 Web UI |
| 🔐 **WAF 安全** | 经消融实验验证的提示词注入集，每请求会话隔离 |
| ⏱ **全链路超时** | 连接 30s · 读 300s · 任何路径无无限等待 |

## 快速开始

```bash
brew install cmake openssl@3 nlohmann-json

git clone <本仓库> && cd zcode-proxy
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j

./build/zproxy --state-dir state --web-dir web
```

> **管理台** → `http://127.0.0.1:8787/admin`

重启：`./restart.sh`

## 接口

```
POST  /v1/chat/completions     OpenAI 协议（流式/非流式）
POST  /v1/messages             Anthropic 协议（透传）
GET   /v1/models               模型列表
GET   /health                  账号池状态
GET   /admin/*                 管理台 API（账号 · 领取 · 用量 · 额度 · …）
```

## 使用示例

**OpenAI 协议**（流式、工具调用、reasoning）：

```bash
curl http://127.0.0.1:8787/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-5.3-Flash",
    "stream": true,
    "messages": [{"role": "user", "content": "你好"}]
  }'
```

**Anthropic 协议**（透传——原生 message 形状原样返回）：

```bash
curl http://127.0.0.1:8787/v1/messages \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-5.3-Flash",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "你好"}]
  }'
```

两种协议均支持 `system` 提示词、工具定义与流式。Anthropic 端点原样转发上游字节——用量统计在旁路照常进行。

## 配置

全部环境变量驱动：

```bash
ZPROXY_PORT=8787                    # 监听端口
ZPROXY_TOKEN=sk-xxx                 # Bearer 鉴权
ZPROXY_DEFAULT_MODEL=GLM-5.3-Flash # 回落模型
ZPROXY_SYNC_MS=5000                # 账号表→磁盘刷盘间隔
ZPROXY_RETRY_3009_MS=2000          # 并发冲突退避
```

<details>
<summary><b>全部变量</b></summary>

| 变量 | 默认 | 说明 |
|---|---|---|
| `ZPROXY_HOST` | `127.0.0.1` | 绑定地址 |
| `ZPROXY_COOLDOWN_401_MS` / `_429_MS` | `600000` / `60000` | 账号冷却 |
| `ZPROXY_RETRY_3009_MAX` | `3` | 冲突重试次数 |
| `ZPROXY_CREDS` | `~/.zcode/v2/credentials.json` | 本机凭据文件 |
| `ZPROXY_STATE_DIR` / `ZPROXY_WEB_DIR` | 二进制目录 | 运行状态 / Web UI |
| `ZPROXY_CLAIM_CONCURRENCY` | `4` | 每日领取并发 |
| `ZPROXY_BLOCKED_RETRY` / `_MS` | 关 / `7200000` | 风控账号自动重试 |
| `ZPROXY_DUMP_SSE` | 关 | 流式响应转储到 `state/logs/` |

</details>

## 多账号

账号在 `state/tokens.json`——内存权威，定时刷盘：

```json
[
  {
    "name": "work",
    "jwt": "eyJhbGciOi...",
    "region": "global",
    "deviceMid": "…",
    "sessionId": "…",
    "userInfo": { "name": "…", "email": "…" }
  }
]
```

通过管理台添加（页面内 OAuth 登录）或直接放入文件。单账号缺失？自动回退本机 ZCode 登录。

冷却按模型隔离：GLM-5.3 的 429 不影响 GLM-5.3-Flash 流量。

## 架构

```
src/
├── util/       L0  基础工具（log / b64 / uuid / fs / env / config / exec）
├── crypto/     L1  SHA-256 · AES-256-GCM（凭据解密）
├── store/      L2  JSON 状态文件（mtime 热重载 · 原子写）
├── domain/     L3  账号池 · 系统提示词 · TPS · claim 状态
├── protocol/   L4  OpenAI ↔ Anthropic 翻译（纯函数零 IO）· SSE 解析
├── upstream/   L4  上游客户端（WAF 指纹）· billing · oauth · marketing
├── transport/  L6  asio 协程 HTTP server / TLS client（连接池 · chunked · 超时）
├── service/    L5  chat · messages · admin · claim · login · live
├── server/     L6  路由 · 静态文件 · 鉴权
└── main.cpp    L7  装配 · 信号安全停机
```

严格分层强制——依赖只能向下（`scripts/check-layers.sh`）。

**流式路径**协程直通：上游 chunk → 解析 → 翻译 → `co_await` 写客户端。无队列、无线程。

## 可靠性

| 层 | 机制 |
|---|---|
| 连接池 | max-idle 30s 淘汰——半死连接不会交出 |
| 上游读 | 全部读点 300s 无数据超时 |
| 停机 | 信号置标志 → 监视线程落盘 → `_Exit`（无析构挂死） |
| 账号表 | 内存权威 + 定时原子刷盘 + O(1) 索引 |
| 管理端点 | 阻塞上游调用跑在 worker pool——不卡事件循环 |

## 测试

```bash
cd build && ctest                    # 协议 · SSE 分帧 · AES-GCM · 账号池不变量
../scripts/check-layers.sh           # 分层越界检查
./pick_bench                         # 选号微基准：10 万账号 ~15ns
```

## 注意事项

- 上游网关校验客户端指纹并要求 ZCode agent 系统提示词——这是订阅共享模式，**有账号风控风险**，仅限个人自用
- 注入提示词占用每请求约 1.2K 输入 token
- 不支持 `response_format`、`logit_bias`、`n>1`

## 排错

- `/health` 返回 `ok: false` → 账号全部冷却中，或系统提示词缺失（先跑一轮 ZCode 对话）
- 网关 3012 → 指纹过期，跑一轮 ZCode 对话刷新
- 连接卡死 → `./restart.sh` 全量清场

---

<div align="center">
<sub>`ZPROXY_DUMP_SSE=1` 时 `state/logs/` 保留每请求 SSE 转储——用证据定位，不靠猜</sub>
</div>
