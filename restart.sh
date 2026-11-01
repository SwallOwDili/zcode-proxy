#!/bin/zsh
# zcode-proxy-cpp 一键重启：杀旧 → 起 8787 → 等就绪
set -e
PROXY_DIR="$HOME/Documents/code/zcode-proxy"
PORT=8787
NODE_BIN=""
echo "▶ 重启 zcode-proxy-cpp ($PROXY_DIR)"
OLD=$(lsof -nP -tiTCP:$PORT -sTCP:LISTEN 2>/dev/null || true)
if [ -n "$OLD" ]; then
  kill -TERM $OLD 2>/dev/null || true
  for i in {1..20}; do
    [ -z "$(lsof -nP -tiTCP:$PORT -sTCP:LISTEN 2>/dev/null || true)" ] && break
    sleep 0.3
    (( i == 7 )) && { kill -9 $OLD 2>/dev/null || true; echo "▶ TERM 未退出，已 SIGKILL"; }
  done
  RESIDUE=$(lsof -nP -tiTCP:$PORT -sTCP:LISTEN 2>/dev/null || true)
  if [ -n "$RESIDUE" ]; then kill -9 $RESIDUE 2>/dev/null; sleep 0.5; echo "▶ 已强杀残留监听进程"; fi
  # 全量清场：bind 失败但未退出的旧 zproxy 会以 ESTABLISHED 连接残留（macOS SO_REUSEADDR 双 bind 陷阱）
  pkill -9 -f "build/zproxy" 2>/dev/null && { echo "▶ 已清场全部 zproxy 残留"; sleep 0.5; } || true
  # 关键：等端口完全释放再起新进程（否则就绪检查被将死的旧进程骗过）
  for i in {1..15}; do
    [ -z "$(lsof -nP -tiTCP:$PORT -sTCP:LISTEN 2>/dev/null || true)" ] && break
    sleep 0.3
  done
fi
: >> /tmp/zproxy-cpp.log
nohup "$PROXY_DIR/build/zproxy" --state-dir "$PROXY_DIR/state" --web-dir "$PROXY_DIR/web" >> /tmp/zproxy-cpp.log 2>&1 < /dev/null &
PID=$!
disown 2>/dev/null || true
for i in {1..30}; do
  curl -s --noproxy '*' -m 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && { echo "✅ zcode-proxy-cpp 就绪 (PID $PID): http://127.0.0.1:$PORT/admin"; exit 0; }
  kill -0 $PID 2>/dev/null || { echo "❌ 进程退出，最近日志："; tail -10 /tmp/zproxy-cpp.log; exit 1; }
  sleep 0.5
done
echo "❌ 启动超时"; tail -10 /tmp/zproxy-cpp.log; exit 1
