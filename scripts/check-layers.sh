#!/bin/zsh
# 分层校验：include 依赖只能向下（L0←L1←L2←L3←L4←L5←L6←L7），越界即失败
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LEVELS=(util crypto store domain protocol upstream service server)
rank() {
  local i=0
  for l in "${LEVELS[@]}"; do
    [[ "$1" == "$l" ]] && echo $i && return 0
    i=$((i + 1))
  done
  echo -1
}

fail=0
for f in $(find "$ROOT/src" "$ROOT/tools" -name '*.hpp' -o -name '*.cpp' | sort); do
  self=$(basename "$(dirname "$f")")
  [[ "$f" == */src/main.cpp ]] && self=main
  [[ "$self" == tools ]] && self=tools
  my=$(rank "$self")
  [[ "$my" -lt 0 ]] && continue
  for inc in $(grep -oE '#include "[a-z_/]+\.hpp"' "$f" | sed 's/#include "//; s/"//'); do
    dep=$(echo "$inc" | cut -d/ -f1)
    r=$(rank "$dep")
    [[ "$r" -lt 0 ]] && continue
    # tools/main 可引用任意层；同层允许；向下引用允许；向上引用禁止
    if [[ "$self" != tools && "$self" != main && "$r" -gt "$my" ]]; then
      echo "❌ 越界: $f -> $inc (L$my -> L$r)"
      fail=1
    fi
  done
done
[[ "$fail" -eq 0 ]] && echo "✅ 分层校验通过"
exit $fail
