#!/usr/bin/env bash
# 下载 Qwen3-4B 量化模型（GGUF Q4_K_M）到 models/（已 gitignore）
set -euo pipefail
cd "$(dirname "$0")/.."

MODEL_DIR="models"
MODEL="$MODEL_DIR/Qwen3-4B-Q4_K_M.gguf"
URL="https://huggingface.co/Qwen/Qwen3-4B-GGUF/resolve/main/Qwen3-4B-Q4_K_M.gguf"

mkdir -p "$MODEL_DIR"
if [[ -f "$MODEL" ]]; then
    echo "模型已存在: $MODEL"
    exit 0
fi
echo "下载 $URL"
curl -fL --retry 3 -C - "$URL" -o "$MODEL.part"
mv "$MODEL.part" "$MODEL"
echo "完成: $MODEL"
