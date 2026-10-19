#!/usr/bin/env bash
# 启动本地 llama.cpp server（OpenAI 兼容端点 127.0.0.1:8080）。
# GPU 优先（--n-gpu-layers 999），无 GPU 回退 CPU（--threads N）。
# 协议不变：客户端只看到 http://127.0.0.1:8080/v1。
set -euo pipefail
cd "$(dirname "$0")/.."

SERVER="third_party/llamacpp/llama-server"
MODEL="models/Qwen3-4B-Q4_K_M.gguf"

# 预编译包的 libggml-*.so 与 llama-server 同目录
export LD_LIBRARY_PATH="$PWD/third_party/llamacpp:${LD_LIBRARY_PATH:-}"

if [[ ! -x "$SERVER" ]]; then
    echo "未找到 llama-server，先运行 scripts/build_llamacpp.sh" >&2
    exit 1
fi
if [[ ! -f "$MODEL" ]]; then
    echo "未找到模型，先运行 scripts/fetch_model.sh" >&2
    exit 1
fi

gpu_flags=()
if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi >/dev/null 2>&1; then
    echo "后端: CUDA"
    gpu_flags=(--n-gpu-layers 999)
elif [[ -e /dev/dri/renderD128 ]] && compgen -G '/usr/share/vulkan/icd.d/*.json' >/dev/null; then
    echo "后端: Vulkan"
    gpu_flags=(--n-gpu-layers 999)
else
    echo "后端: CPU（threads=$(nproc)）"
    gpu_flags=(--n-gpu-layers 0 --threads "$(nproc)")
fi

exec "$SERVER" \
    -m "$MODEL" \
    --host 127.0.0.1 --port 8080 \
    -c 8192 \
    --no-webui \
    "${gpu_flags[@]}" "$@"
