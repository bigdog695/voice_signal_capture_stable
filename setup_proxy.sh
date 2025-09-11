#!/bin/bash

# CUDA下载代理配置脚本
# 为wget和pip配置代理加速下载

echo "=== CUDA下载代理配置 ==="

# 检查是否提供了代理信息
if [ $# -eq 0 ]; then
    echo "使用方法:"
    echo "  $0 <代理地址> [代理端口]"
    echo ""
    echo "示例:"
    echo "  $0 127.0.0.1 7890    # 本地代理"
    echo "  $0 proxy.company.com 8080  # 公司代理"
    echo "  $0 http://proxy.com:8080   # HTTP代理"
    echo ""
    echo "或者直接设置环境变量:"
    echo "  export http_proxy=http://127.0.0.1:7890"
    echo "  export https_proxy=http://127.0.0.1:7890"
    echo ""
    echo "常用代理工具:"
    echo "- Clash: http://127.0.0.1:7890"
    echo "- V2Ray: http://127.0.0.1:1080"
    echo "- Shadowsocks: http://127.0.0.1:1080"
    exit 1
fi

PROXY_HOST=$1
PROXY_PORT=${2:-7890}

# 构建代理URL
if [[ $PROXY_HOST == http* ]]; then
    # 如果已经包含协议
    PROXY_URL="$PROXY_HOST"
else
    # 添加http协议
    PROXY_URL="http://$PROXY_HOST:$PROXY_PORT"
fi

echo "配置代理: $PROXY_URL"

# 设置环境变量
export http_proxy="$PROXY_URL"
export https_proxy="$PROXY_URL"
export HTTP_PROXY="$PROXY_URL"
export HTTPS_PROXY="$PROXY_URL"

# 添加到bashrc（可选）
read -p "是否将代理配置添加到 ~/.bashrc? (y/N): " add_to_bashrc
if [[ $add_to_bashrc =~ ^[Yy]$ ]]; then
    echo "" >> ~/.bashrc
    echo "# CUDA下载代理配置" >> ~/.bashrc
    echo "export http_proxy=\"$PROXY_URL\"" >> ~/.bashrc
    echo "export https_proxy=\"$PROXY_URL\"" >> ~/.bashrc
    echo "export HTTP_PROXY=\"$PROXY_URL\"" >> ~/.bashrc
    echo "export HTTPS_PROXY=\"$PROXY_URL\"" >> ~/.bashrc
    echo "代理配置已添加到 ~/.bashrc"
fi

echo ""
echo "✅ 代理配置完成"
echo "当前代理设置:"
echo "  http_proxy: $http_proxy"
echo "  https_proxy: $https_proxy"
echo ""

# 测试代理连接
echo "测试代理连接..."
if curl -s --connect-timeout 5 https://www.google.com > /dev/null; then
    echo "✅ 代理连接正常"
else
    echo "❌ 代理连接失败，请检查代理设置"
fi

echo ""
echo "现在可以运行以下命令:"
echo "  ./download_cuda_china.sh    # 使用代理下载CUDA"
echo "  pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121"
echo ""
echo "取消代理: unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY"
