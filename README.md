<div align="center">

# ⚡ zcode-proxy

**Turn your ZCode subscription into an OpenAI-compatible API**

C++20 · asio coroutines · single binary · 10K+ concurrent connections

[![build](https://img.shields.io/badge/build-CMake%20%2B%20Ninja-blue)](#build)
[![std](https://img.shields.io/badge/C%2B%2B-20-00599c)](#)
[![license](https://img.shields.io/badge/license-private-lightgrey)](#)

</div>

[English](README.md) | [简体中文](README.zh-CN.md)

---

## What is this

A local gateway that exposes your logged-in ZCode (GLM Start Plan) subscription as standard **OpenAI** and **Anthropic** APIs. Point any agent framework at `http://127.0.0.1:8787/v1` and it just works — with a multi-account quota pool, failover, and a full admin console behind it.

```
WorkBuddy / harness / any OpenAI client
        │
        ▼
┌─────────────────────────────┐
│  zcode-proxy  (127.0.0.1:8787)   │
│  · protocol translation          │
│  · account pool & failover       │
│  · quota accounting              │
└─────────────────────────────┘
        │
        ▼
  GLM-5.3 / GLM-5.3-Flash
```

## Highlights

| | |
|---|---|
| 🚀 **Coroutine I/O** | asio C++20 coroutines — per-connection cost is KBs, no thread-per-request |
| 🔀 **Multi-account pool** | Round-robin + session affinity + per-model cooldowns, O(1) lock-free account selection |
| 🛠 **Full tool calling** | Streaming `tool_calls` in official OpenAI delta shape, works with strict SDKs (AI SDK et al) |
| 📊 **Admin console** | Dashboard, accounts, quotas, daily claims, usage analytics — built-in web UI |
| 🔐 **WAF-safe** | Verified system-prompt injection set, per-request session isolation |
| ⏱ **Hard timeouts everywhere** | Connect 30s · read 300s · no infinite waits on any path |

## Quick start

```bash
brew install cmake openssl@3 nlohmann-json

git clone <this-repo> && cd zcode-proxy
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j

./build/zproxy --state-dir state --web-dir web
```

> **Admin console** → `http://127.0.0.1:8787/admin`

Reboot-proof restart: `./restart.sh`

## Endpoints

```
POST  /v1/chat/completions     OpenAI protocol (stream & non-stream)
POST  /v1/messages             Anthropic protocol (passthrough)
GET   /v1/models               model list
GET   /health                  account pool status
GET   /admin/*                 console API (accounts · claims · usage · quotas · …)
```

## Usage

**OpenAI protocol** (streaming, tool calls, reasoning):

```bash
curl http://127.0.0.1:8787/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-5.3-Flash",
    "stream": true,
    "messages": [{"role": "user", "content": "hello"}]
  }'
```

**Anthropic protocol** (passthrough — native message shape comes out untouched):

```bash
curl http://127.0.0.1:8787/v1/messages \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-5.3-Flash",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "hello"}]
  }'
```

Both accept `system` prompts, tool definitions, and streaming. The Anthropic endpoint relays upstream bytes as-is — token accounting still happens on the side.

## Configuration

Everything is env-driven:

```bash
ZPROXY_PORT=8787                    # listen port
ZPROXY_TOKEN=sk-xxx                 # require Bearer auth
ZPROXY_DEFAULT_MODEL=GLM-5.3-Flash # fallback model
ZPROXY_SYNC_MS=5000                # account table → disk interval
ZPROXY_RETRY_3009_MS=2000          # concurrency-conflict backoff
```

<details>
<summary><b>All variables</b></summary>

| Variable | Default | Purpose |
|---|---|---|
| `ZPROXY_HOST` | `127.0.0.1` | bind address |
| `ZPROXY_COOLDOWN_401_MS` / `_429_MS` | `600000` / `60000` | account cooldowns |
| `ZPROXY_RETRY_3009_MAX` | `3` | conflict retry count |
| `ZPROXY_CREDS` | `~/.zcode/v2/credentials.json` | local credential file |
| `ZPROXY_STATE_DIR` / `ZPROXY_WEB_DIR` | binary dir | runtime state / web UI |
| `ZPROXY_CLAIM_CONCURRENCY` | `4` | daily-claim workers |
| `ZPROXY_BLOCKED_RETRY` / `_MS` | off / `7200000` | retry risk-flagged accounts |
| `ZPROXY_DUMP_SSE` | off | dump streaming responses to `state/logs/` |

</details>

## Multi-account

Accounts live in `state/tokens.json` — memory-authoritative, periodically flushed to disk:

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

Add accounts via the admin console (in-page OAuth login) or drop the file in. Single account missing? Falls back to your local ZCode login automatically.

Cooldowns are per-model: a 429 on GLM-5.3 doesn't block GLM-5.3-Flash traffic.

## Architecture

```
src/
├── util/       L0  primitives — log / b64 / uuid / fs / env / config / exec
├── crypto/     L1  SHA-256 · AES-256-GCM (credential decrypt)
├── store/      L2  JSON state files (mtime hot-reload · atomic write)
├── domain/     L3  account pool · system prompt · TPS · claim state
├── protocol/   L4  OpenAI ↔ Anthropic translation (pure, zero-IO) · SSE parser
├── upstream/   L4  upstream client (WAF fingerprint) · billing · oauth · marketing
├── transport/  L6  asio coroutine HTTP server / TLS client (pool · chunked · timeouts)
├── service/    L5  chat · messages · admin · claim · login · live
├── server/     L6  routing · static files · auth
└── main.cpp    L7  wiring · signal-safe shutdown
```

Strict layering enforced — dependencies only point downward (`scripts/check-layers.sh`).

**Streaming path** is coroutine-direct: upstream chunk → parse → translate → `co_await` write to client. No queues, no worker threads.

## Reliability

| Layer | Mechanism |
|---|---|
| Connection pool | max-idle 30s eviction — stale half-closed conns never handed out |
| Upstream reads | 300s no-data timeout on every read point |
| Shutdown | signal sets a flag → flush on watchdog thread → `_Exit` (no destructor hangs) |
| Account table | memory-authoritative + periodic atomic flush + O(1) indexes |
| Admin handlers | blocking upstream calls run on a worker pool — never on the event loop |

## Testing

```bash
cd build && ctest                    # protocol · SSE framing · AES-GCM · pool invariants
../scripts/check-layers.sh           # layer-boundary lint
./pick_bench                         # account selection: ~15ns @ 100k accounts
```

## Caveats

- The upstream gateway validates client fingerprints and requires the ZCode agent system prompt — this is a subscription-sharing pattern with **account risk**, personal use only
- Injected prompt costs ~1.2K input tokens per request
- `response_format`, `logit_bias`, `n>1` are not supported

## Troubleshooting

- `ok: false` on `/health` → all accounts cooling down, or system prompt missing (run one ZCode conversation to refresh)
- Gateway 3012 → fingerprint stale, refresh via a ZCode conversation
- Stuck connections → `./restart.sh` force-clears everything

---

<div align="center">
<sub>state/logs/ keeps per-request SSE dumps when ZPROXY_DUMP_SSE=1 — bring receipts, not guesses</sub>
</div>
