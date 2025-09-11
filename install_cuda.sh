#!/bin/bash

# RTX 5070 CUDA安装脚本
# 适用于Ubuntu/Debian系统

set -e

echo "=== RTX 5070 CUDA安装脚本 ==="
echo "推荐配置: CUDA 12.1 + cuDNN 8.9.0"
echo

# 检查是否为root用户
if [[ $EUID -eq 0 ]]; then
   echo "请不要使用root用户运行此脚本"
   exit 1
fi

# 检查显卡
echo "检查NVIDIA显卡..."
if ! command -v nvidia-smi &> /dev/null; then
    echo "❌ 未检测到NVIDIA驱动，请先安装NVIDIA驱动"
    echo "Ubuntu/Debian:"
    echo "  sudo apt update"
    echo "  sudo apt install nvidia-driver-XXX  # XXX为你的驱动版本"
    exit 1
fi

nvidia-smi --query-gpu=name --format=csv,noheader,nounits | head -1
echo

# 安装CUDA 12.2
echo "=== 步骤1: 安装CUDA 12.2 ==="
CUDA_VERSION="12.2.0"
CUDA_FILE="cuda_${CUDA_VERSION}_535.54.03_linux.run"

if [ ! -f "$CUDA_FILE" ]; then
    echo "下载CUDA $CUDA_VERSION..."
    echo "选择下载方式:"
    echo "1. 清华大学镜像 (推荐)"
    echo "2. 官方下载"
    echo "3. 使用代理"

    # 默认使用清华大学镜像
    echo "使用清华大学镜像下载..."
    wget https://mirrors.tuna.tsinghua.edu.cn/nvidia/cuda/${CUDA_VERSION}/local_installers/${CUDA_FILE} || {
        echo "清华大学镜像下载失败，尝试官方下载..."
        wget https://developer.download.nvidia.com/compute/cuda/${CUDA_VERSION}/local_installers/${CUDA_FILE}
    }
fi

echo "安装CUDA (只安装工具包)..."
sudo sh ${CUDA_FILE} --no-opengl-libs --no-man-page --no-doc --no-dev-tools

# 设置CUDA环境变量
echo "设置CUDA环境变量..."
echo 'export PATH=/usr/local/cuda/bin${PATH:+:${PATH}}' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda/lib64${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}' >> ~/.bashrc
export PATH=/usr/local/cuda/bin${PATH:+:${PATH}}
export LD_LIBRARY_PATH=/usr/local/cuda/lib64${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}

echo

# 安装cuDNN
echo "=== 步骤2: 安装cuDNN 8.9.0 ==="
CUDNN_VERSION="8.9.0"
CUDNN_FILE="cudnn-linux-x86_64-${CUDNN_VERSION}.131_cuda12-archive.tar.xz"

if [ ! -f "$CUDNN_FILE" ]; then
    echo "下载cuDNN..."
    echo "使用清华大学镜像下载cuDNN..."
    wget https://mirrors.tuna.tsinghua.edu.cn/nvidia/cudnn/${CUDNN_VERSION}/local_installers/${CUDNN_FILE} || {
        echo "清华大学镜像下载失败，尝试官方下载..."
        wget https://developer.download.nvidia.com/compute/cudnn/${CUDNN_VERSION}/local_installers/${CUDNN_FILE}
    }
fi

echo "解压cuDNN..."
tar -xvf ${CUDNN_FILE}

echo "安装cuDNN..."
sudo cp cudnn-linux-x86_64-${CUDNN_VERSION}.131_cuda12-archive/include/cudnn*.h /usr/local/cuda/include
sudo cp -P cudnn-linux-x86_64-${CUDNN_VERSION}.131_cuda12-archive/lib/libcudnn* /usr/local/cuda/lib64
sudo chmod a+r /usr/local/cuda/include/cudnn*.h /usr/local/cuda/lib64/libcudnn*

echo

# 安装PyTorch
echo "=== 步骤3: 安装PyTorch (CUDA 12.2版本) ==="
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu122

echo

# 安装FunASR
echo "=== 步骤4: 安装FunASR ==="
pip install funasr numpy

echo

# 验证安装
echo "=== 验证安装 ==="

echo "CUDA版本:"
nvcc --version
echo

echo "PyTorch CUDA支持:"
python -c "import torch; print('CUDA available:', torch.cuda.is_available()); print('CUDA device count:', torch.cuda.device_count()); print('Current device:', torch.cuda.current_device() if torch.cuda.is_available() else 'N/A')"
echo

echo "FunASR导入测试:"
python -c "import funasr; print('FunASR version:', funasr.__version__)"
echo

echo "✅ CUDA和FunASR安装完成！"
echo
echo "请重新启动终端或运行 'source ~/.bashrc' 以应用环境变量"
echo "然后运行: python check_cpu_setup.py  # 验证GPU环境"
