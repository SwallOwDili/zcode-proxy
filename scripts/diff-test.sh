#!/bin/zsh
# 差分测试：对 Node(8787) 与 C++(8788) 发相同请求，规范化后比对
# 用法: ./diff-test.sh   （⚠ 仅双版本并行验证期可用；8788 退役后此脚本闲置——
#    单版本时代的回归由 ctest + scripts/check-layers.sh + 真实请求验收覆盖）
set -e
NODE=8787; CPP=8788
norm() { python3 -c "
import json,sys
d = json.load(sys.stdin)
def walk(o):
    # 生成文本有随机性：只比对结构骨架（键名/类型/枚举值），文本替换为占位
    if isinstance(o, dict):
        for k in ('id','created'): o.pop(k, None)
        out = {}
        for k, v in o.items():
            if k in ('content','reasoning_content','arguments'):
                out[k] = '<text>' if v is not None else None
            elif k == 'usage':
                out[k] = sorted(v.keys()) if isinstance(v, dict) else v  # 数值随缓存状态浮动，只比键集
            else:
                out[k] = walk(v)
        return out
    if isinstance(o, list): return [walk(x) for x in o]
    return o
print(json.dumps(walk(d), ensure_ascii=False, sort_keys=True))
"; }

req() { curl -s --noproxy '*' -m 90 "http://127.0.0.1:$1/v1/chat/completions" -H 'Content-Type: application/json' -d "$2"; }

fail=0
t() {
  local name="$1" body="$2"
  local a b
  a=$(req $NODE "$body" | norm) || a="ERR"
  b=$(req $CPP "$body" | norm) || b="ERR"
  if [[ "$a" == "$b" ]]; then echo "✅ $name"
  else echo "❌ $name"; echo "  node: ${a:0:200}"; echo "  cpp:  ${b:0:200}"; fail=1; fi
}

t "非流式"      '{"model":"GLM-5.3-Flash","messages":[{"role":"user","content":"回复：OK"}],"max_tokens":8}'
t "模型映射"    '{"model":"deepseek-chat","messages":[{"role":"user","content":"回复：OK"}],"max_tokens":8}'
t "usage字段"   '{"model":"GLM-5.3-Flash","messages":[{"role":"user","content":"1+1=?"}],"max_tokens":8}'

# 流式：只比对事件序列的形状（首帧 role、含 finish_reason、含 usage、以 [DONE] 结尾）
stream_shape() { python3 -c "
import sys, json
events = []
for line in sys.stdin:
    line = line.strip()
    if not line.startswith('data: '): continue
    p = line[6:]
    if p == '[DONE]': events.append('DONE'); continue
    try: d = json.loads(p)
    except: continue
    if 'error' in d: events.append('error')
    ch = d.get('choices') or []
    if ch and ch[0].get('finish_reason'): events.append('finish:'+ch[0]['finish_reason'])
    if 'usage' in d and d.get('choices') == []: events.append('usage')
print('|'.join(events))
"; }
a=$(curl -s --noproxy '*' -m 90 -N "http://127.0.0.1:$NODE/v1/chat/completions" -H 'Content-Type: application/json' -d '{"model":"GLM-5.3-Flash","stream":true,"messages":[{"role":"user","content":"回复：OK"}],"max_tokens":8}' | stream_shape)
b=$(curl -s --noproxy '*' -m 90 -N "http://127.0.0.1:$CPP/v1/chat/completions" -H 'Content-Type: application/json' -d '{"model":"GLM-5.3-Flash","stream":true,"messages":[{"role":"user","content":"回复：OK"}],"max_tokens":8}' | stream_shape)
if [[ "$a" == "$b" ]]; then echo "✅ 流式事件序列"; else echo "❌ 流式事件序列"; echo "  node: $a"; echo "  cpp:  $b"; fail=1; fi

# Anthropic 透传：字段形状
amsg() { curl -s --noproxy '*' -m 90 "http://127.0.0.1:$1/v1/messages" -H 'Content-Type: application/json' -d '{"model":"GLM-5.3-Flash","max_tokens":8,"messages":[{"role":"user","content":"回复：OK"}]}' | python3 -c "
import json,sys
d = json.load(sys.stdin)
print(d.get('type'), d.get('role'), d.get('stop_reason'), sorted(d.get('usage', {}).keys()))
"; }
a=$(amsg $NODE); b=$(amsg $CPP)
if [[ "$a" == "$b" ]]; then echo "✅ Anthropic 透传形状"; else echo "❌ Anthropic 透传形状"; echo "  node: $a"; echo "  cpp:  $b"; fail=1; fi

[[ $fail -eq 0 ]] && echo "✅ 差分测试全部通过" || exit 1
