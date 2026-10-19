#!/usr/bin/env bash
# 银行全套三 arm 实验：直连 / Guard 拦截 / Guard 只监控。
# 每个 arm 4 个分片并行（144 对 = 4 × 36），arm 之间串行，避免 QPS 过载。
# 预计 ~2.5-3 小时、~¥100-150。停止：pkill -f agentdojo_compare
set -u
cd "$(dirname "$0")/.."

CHATINJECT=/tmp/chatinject-agent-guard/src/agentdojo/attacks/multi_turn_data/with_utility_multi_turn_7_generation_output.json
ATTACKS="chatinject_plain_multiturn chatinject_kimi_k2 chatinject_kimi_k2_multiturn"
RANGES=("0:36" "36:72" "72:108" "108:144")
mkdir -p logs

run_shard() {  # arm shard_idx range
  local arm=$1 idx=$2 range=$3
  .venv-agentdojo/bin/python scripts/agentdojo_compare.py \
    --provider kimi-k2.6 --kimi-thinking disabled \
    --pair-set banking_full --pair-range "$range" \
    --arm "$arm" --guard-detector deepseek-v41-flash \
    --attacks $ATTACKS \
    --chatinject-dialogues "$CHATINJECT" \
    --output "docs/bankfull_${arm}_shard${idx}.json" \
    > "logs/bankfull_${arm}_shard${idx}.log" 2>&1
}

for arm in direct agent_guard agent_guard_monitor; do
  echo "[$(date +%H:%M:%S)] 启动 arm=$arm 的 4 个分片..."
  for i in 0 1 2 3; do
    run_shard "$arm" "$i" "${RANGES[$i]}" &
  done
  wait
  echo "[$(date +%H:%M:%S)] arm=$arm 完成"
done
echo "[$(date +%H:%M:%S)] 全部完成"
