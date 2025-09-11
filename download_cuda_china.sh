#!/bin/bash

# CUDA下载加速脚本 - 中国大陆用户专用
# 提供多种下载方式和镜像源

set -e

echo "=== CUDA下载加速脚本（中国大陆用户） ==="
echo "RTX 5070 推荐配置: CUDA 12.2 + cuDNN 8.9.0"
echo

# 定义版本（RTX 5070推荐）
CUDA_VERSION="12.2.0"
CUDA_BUILD="535.54.03"
CUDNN_VERSION="8.9.0"
CUDNN_BUILD="131"

CUDA_FILE="cuda_${CUDA_VERSION}_${CUDA_BUILD}_linux.run"
CUDNN_FILE="cudnn-linux-x86_64-${CUDNN_VERSION}.${CUDNN_BUILD}_cuda12-archive.tar.xz"

# 显示下载选项
show_menu() {
    echo "请选择下载方式:"
    echo "1. 清华大学镜像 (推荐 - 最快)"
    echo "2. 中科大镜像"
    echo "3. 阿里云镜像"
    echo "4. 华为云镜像"
    echo "5. 官方下载 (最慢)"
    echo "6. 使用迅雷下载"
    echo "7. 使用aria2多线程下载"
    echo "8. 显示所有下载链接"
    echo "9. 检查本地文件"
    echo "0. 退出"
    echo
}

# 下载函数
download_file() {
    local url=$1
    local filename=$2
    local desc=$3

    echo "正在下载 $desc..."
    echo "URL: $url"

    if command -v aria2c &> /dev/null; then
        echo "使用aria2c多线程下载..."
        aria2c -x 16 -s 16 -k 1M "$url" -o "$filename"
    else
        echo "使用wget下载..."
        wget --progress=bar:force "$url" -O "$filename"
    fi

    if [ $? -eq 0 ]; then
        echo "✅ $desc 下载完成: $filename"
        return 0
    else
        echo "❌ $desc 下载失败"
        return 1
    fi
}

# CUDA下载
download_cuda() {
    local mirror_name=$1
    local base_url=$2

    echo "从 $mirror_name 下载CUDA..."
    local cuda_url="${base_url}/compute/cuda/${CUDA_VERSION}/local_installers/${CUDA_FILE}"

    if [ ! -f "$CUDA_FILE" ]; then
        if download_file "$cuda_url" "$CUDA_FILE" "CUDA $CUDA_VERSION"; then
            return 0
        fi
    else
        echo "✅ CUDA文件已存在: $CUDA_FILE"
        return 0
    fi

    return 1
}

# cuDNN下载
download_cudnn() {
    local mirror_name=$1
    local base_url=$2

    echo "从 $mirror_name 下载cuDNN..."
    local cudnn_url="${base_url}/compute/cudnn/${CUDNN_VERSION}/local_installers/${CUDNN_FILE}"

    if [ ! -f "$CUDNN_FILE" ]; then
        if download_file "$cudnn_url" "$CUDNN_FILE" "cuDNN $CUDNN_VERSION"; then
            return 0
        fi
    else
        echo "✅ cuDNN文件已存在: $CUDNN_FILE"
        return 0
    fi

    return 1
}

# 显示所有下载链接
show_all_links() {
    echo "=== CUDA下载链接 ==="
    echo "清华大学: https://mirrors.tuna.tsinghua.edu.cn/nvidia/cuda/${CUDA_VERSION}/local_installers/${CUDA_FILE}"
    echo "中科大: https://mirrors.ustc.edu.cn/nvidia/cuda/${CUDA_VERSION}/local_installers/${CUDA_FILE}"
    echo "阿里云: https://mirrors.aliyun.com/nvidia/cuda/${CUDA_VERSION}/local_installers/${CUDA_FILE}"
    echo "华为云: https://mirrors.huaweicloud.com/nvidia/cuda/${CUDA_VERSION}/local_installers/${CUDA_FILE}"
    echo "官方: https://developer.download.nvidia.com/compute/cuda/${CUDA_VERSION}/local_installers/${CUDA_FILE}"
    echo
    echo "=== cuDNN下载链接 ==="
    echo "清华大学: https://mirrors.tuna.tsinghua.edu.cn/nvidia/cudnn/${CUDNN_VERSION}/local_installers/${CUDNN_FILE}"
    echo "中科大: https://mirrors.ustc.edu.cn/nvidia/cudnn/${CUDNN_VERSION}/local_installers/${CUDNN_FILE}"
    echo "阿里云: https://mirrors.aliyun.com/nvidia/cudnn/${CUDNN_VERSION}/local_installers/${CUDNN_FILE}"
    echo "华为云: https://mirrors.huaweicloud.com/nvidia/cudnn/${CUDNN_VERSION}/local_installers/${CUDNN_FILE}"
    echo "官方: https://developer.download.nvidia.com/compute/cudnn/${CUDNN_VERSION}/local_installers/${CUDNN_FILE}"
    echo
    echo "=== 迅雷下载 ==="
    echo "请复制上述链接到迅雷中下载"
    echo
}

# 检查本地文件
check_local_files() {
    echo "=== 检查本地文件 ==="

    if [ -f "$CUDA_FILE" ]; then
        local cuda_size=$(stat -f%z "$CUDA_FILE" 2>/dev/null || stat -c%s "$CUDA_FILE" 2>/dev/null)
        echo "✅ CUDA文件存在: $CUDA_FILE (${cuda_size} bytes)"
    else
        echo "❌ CUDA文件不存在: $CUDA_FILE"
    fi

    if [ -f "$CUDNN_FILE" ]; then
        local cudnn_size=$(stat -f%z "$CUDNN_FILE" 2>/dev/null || stat -c%s "$CUDNN_FILE" 2>/dev/null)
        echo "✅ cuDNN文件存在: $CUDNN_FILE (${cudnn_size} bytes)"
    else
        echo "❌ cuDNN文件不存在: $CUDNN_FILE"
    fi

    echo
}

# 主循环
while true; do
    show_menu
    read -p "请选择 (0-9): " choice
    echo

    case $choice in
        1)
            echo "使用清华大学镜像..."
            download_cuda "清华大学" "https://mirrors.tuna.tsinghua.edu.cn/nvidia" && download_cudnn "清华大学" "https://mirrors.tuna.tsinghua.edu.cn/nvidia"
            ;;
        2)
            echo "使用中科大镜像..."
            download_cuda "中科大" "https://mirrors.ustc.edu.cn/nvidia" && download_cudnn "中科大" "https://mirrors.ustc.edu.cn/nvidia"
            ;;
        3)
            echo "使用阿里云镜像..."
            download_cuda "阿里云" "https://mirrors.aliyun.com/nvidia" && download_cudnn "阿里云" "https://mirrors.aliyun.com/nvidia"
            ;;
        4)
            echo "使用华为云镜像..."
            download_cuda "华为云" "https://mirrors.huaweicloud.com/nvidia" && download_cudnn "华为云" "https://mirrors.huaweicloud.com/nvidia"
            ;;
        5)
            echo "使用官方下载..."
            download_cuda "官方" "https://developer.download.nvidia.com" && download_cudnn "官方" "https://developer.download.nvidia.com"
            ;;
        6)
            echo "=== 迅雷下载说明 ==="
            echo "请复制以下链接到迅雷中下载:"
            echo
            echo "CUDA: https://developer.download.nvidia.com/compute/cuda/${CUDA_VERSION}/local_installers/${CUDA_FILE}"
            echo "cuDNN: https://developer.download.nvidia.com/compute/cudnn/${CUDNN_VERSION}/local_installers/${CUDNN_FILE}"
            echo
            echo "或者使用国内镜像:"
            echo "CUDA: https://mirrors.tuna.tsinghua.edu.cn/nvidia/cuda/${CUDA_VERSION}/local_installers/${CUDA_FILE}"
            echo "cuDNN: https://mirrors.tuna.tsinghua.edu.cn/nvidia/cudnn/${CUDNN_VERSION}/local_installers/${CUDNN_FILE}"
            ;;
        7)
            echo "安装aria2c多线程下载工具..."
            if command -v apt &> /dev/null; then
                sudo apt update && sudo apt install -y aria2
            elif command -v yum &> /dev/null; then
                sudo yum install -y aria2
            else
                echo "请手动安装aria2: sudo apt install aria2 或 sudo yum install aria2"
                continue
            fi
            echo "✅ aria2c已安装，请重新选择下载选项"
            ;;
        8)
            show_all_links
            ;;
        9)
            check_local_files
            ;;
        0)
            echo "退出下载脚本"
            exit 0
            ;;
        *)
            echo "无效选择，请重新输入"
            ;;
    esac

    echo
    read -p "按回车键继续..."
    echo
done
