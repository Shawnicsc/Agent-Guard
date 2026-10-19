#!/usr/bin/env bash
# 获取 llama.cpp：GPU 优先（CUDA/Vulkan），CPU 兜底。
# 优先官方预编译二进制（nightly release），源码构建仅作兜底（需 cmake）。
# 产物: third_party/llamacpp/llama-server
set -euo pipefail
cd "$(dirname "$0")/.."

DEST="third_party/llamacpp"
mkdir -p "$DEST"

if [[ -x "$DEST/llama-server" ]]; then
    echo "llama-server 已存在: $DEST/llama-server"
    exit 0
fi

detect_backend() {
    if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi >/dev/null 2>&1; then
        echo "cuda"; return
    fi
    if [[ -e /dev/dri/renderD128 ]] && compgen -G '/usr/share/vulkan/icd.d/*.json' >/dev/null; then
        echo "vulkan"; return
    fi
    echo "cpu"
}

BACKEND="$(detect_backend)"
echo "检测到推理后端: $BACKEND"

case "$BACKEND" in
    cuda)   ASSET_RE='llama-b[0-9]+-bin-ubuntu-cuda-13\.4-x64\.tar\.gz'
            CUDART_RE='cudart-llama-b[0-9]+-bin-ubuntu-cuda-13\.4-x64\.tar\.gz' ;;
    vulkan) ASSET_RE='llama-b[0-9]+-bin-ubuntu-vulkan-x64\.tar\.gz' ;;
    *)      ASSET_RE='llama-b[0-9]+-bin-ubuntu-x64\.tar\.gz' ;;
esac

fetch_prebuilt() {
    # 扫描最近的 nightly release，找到匹配资产并下载解压
    local urls
    urls=$(curl -fsSL "https://api.github.com/repos/ggml-org/llama.cpp/releases?per_page=10" \
        | grep -oE '"browser_download_url": "https://[^"]+"' \
        | grep -oE 'https://[^"]+' || true)
    local url
    url=$(grep -E "$ASSET_RE" <<<"$urls" | head -1 || true)
    if [[ -z "$url" ]]; then
        return 1
    fi
    echo "下载预编译包: $url"
    local tmp
    tmp=$(mktemp -d)
    curl -fL "$url" -o "$tmp/pkg.tar.gz"
    tar -xzf "$tmp/pkg.tar.gz" -C "$DEST"
    if [[ "$BACKEND" == "cuda" ]]; then
        local cudart_url
        cudart_url=$(grep -E "$CUDART_RE" <<<"$urls" | head -1 || true)
        if [[ -n "$cudart_url" ]]; then
            curl -fL "$cudart_url" -o "$tmp/cudart.tar.gz"
            tar -xzf "$tmp/cudart.tar.gz" -C "$DEST"
        fi
    fi
    # 资产解压在 llama-bNNNN/ 子目录内：扁平化到 DEST
    local sub
    for sub in "$DEST"/llama-b*/; do
        [[ -d "$sub" ]] || continue
        mv "$sub"* "$DEST/"
        rmdir "$sub"
    done
    chmod +x "$DEST/llama-server" 2>/dev/null || true
    [[ -x "$DEST/llama-server" ]]
}

if fetch_prebuilt; then
    echo "预编译安装完成 (backend=$BACKEND)"
    exit 0
fi
echo "预编译包不可用，回退源码构建（需要 cmake 与编译工具链）"

SRC="third_party/llama.cpp-src"
if [[ ! -d "$SRC" ]]; then
    git clone --depth 1 https://github.com/ggml-org/llama.cpp "$SRC"
fi
if ! command -v cmake >/dev/null 2>&1; then
    echo "缺少 cmake，无法源码构建。请安装 cmake 后重试。" >&2
    exit 1
fi
cmake_flags=(-B "$SRC/build" -DLLAMA_CURL=OFF)
case "$BACKEND" in
    cuda)   cmake_flags+=(-DGGML_CUDA=ON) ;;
    vulkan) cmake_flags+=(-DGGML_VULKAN=ON) ;;
    *)      : ;;
esac
cmake -S "$SRC" "${cmake_flags[@]}"
cmake --build "$SRC/build" --target llama-server -j "$(nproc)"
cp "$SRC/build/bin/llama-server" "$DEST/llama-server"
echo "源码构建完成 (backend=$BACKEND)"
