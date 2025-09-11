# FunASR 集成使用说明

## 功能介绍

已将阿里云的FunASR实时语音识别功能集成到 `zmq_test.py` 中，可以实时将PCM音频chunks转换为文字并打印结果。

## ⚠️ 重要说明

- **GPU模式**: 脚本已配置为使用GPU进行推理，需要CUDA支持
- **显卡要求**: RTX 50系列显卡（如RTX 5070）
- **CUDA版本**: 推荐CUDA 12.2
- **首次运行**: 会自动下载模型文件，可能需要一些时间

## 安装CUDA和依赖

### 1. 下载CUDA和cuDNN（中国大陆用户加速版）

**方法1：使用下载加速脚本（推荐）**
```bash
# 运行下载加速脚本
./download_cuda_china.sh
```

**方法2：手动下载（清华大学镜像）**
```bash
# 下载CUDA 12.2
wget https://mirrors.tuna.tsinghua.edu.cn/nvidia/cuda/12.2.0/local_installers/cuda_12.2.0_535.54.03_linux.run

# 下载cuDNN 8.9.0
wget https://mirrors.tuna.tsinghua.edu.cn/nvidia/cudnn/8.9.0/local_installers/cudnn-linux-x86_64-8.9.0.131_cuda12-archive.tar.xz
```

**方法3：使用迅雷等下载工具**
复制以下链接到下载工具中：
- CUDA: https://mirrors.tuna.tsinghua.edu.cn/nvidia/cuda/12.2.0/local_installers/cuda_12.2.0_535.54.03_linux.run
- cuDNN: https://mirrors.tuna.tsinghua.edu.cn/nvidia/cudnn/8.9.0/local_installers/cudnn-linux-x86_64-8.9.0.131_cuda12-archive.tar.xz

### 2. 安装CUDA

```bash
# 安装CUDA（只安装CUDA工具包，不要安装驱动）
sudo sh cuda_12.2.0_535.54.03_linux.run --no-opengl-libs --no-man-page --no-doc --no-dev-tools
```

### 3. 安装cuDNN

```bash
# 解压cuDNN
tar -xvf cudnn-linux-x86_64-8.9.0.131_cuda12-archive.tar.xz

# 安装cuDNN
sudo cp cudnn-linux-x86_64-8.9.0.131_cuda12-archive/include/cudnn*.h /usr/local/cuda/include
sudo cp -P cudnn-linux-x86_64-8.9.0.131_cuda12-archive/lib/libcudnn* /usr/local/cuda/lib64
sudo chmod a+r /usr/local/cuda/include/cudnn*.h /usr/local/cuda/lib64/libcudnn*
```

### 4. 设置环境变量

```bash
# 添加到 ~/.bashrc
export PATH=/usr/local/cuda/bin${PATH:+:${PATH}}
export LD_LIBRARY_PATH=/usr/local/cuda/lib64${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}
```

### 5. 安装PyTorch（CUDA版本）

```bash
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu122
```

### 6. 安装FunASR

```bash
pip install funasr numpy
```

### 验证安装

```bash
# 检查CUDA版本
nvcc --version

# 检查PyTorch CUDA支持
python -c "import torch; print(torch.cuda.is_available())"

# 运行环境检查
python check_cpu_setup.py  # 现在是GPU检查脚本
```

## 使用方法

### 基本使用（启用ASR）

```bash
python zmq_test.py --enable-asr
```

### 完整参数

```bash
python zmq_test.py \
  --enable-asr \
  --endpoint tcp://0.0.0.0:5555 \
  --mode bind \
  --asr-model paraformer-zh-streaming \
  --print-every 10
```

### 参数说明

- `--enable-asr`: 启用实时语音识别功能
- `--asr-model`: 指定ASR模型（默认: paraformer-zh-streaming）
- `--endpoint`: ZMQ端点地址
- `--mode`: ZMQ连接模式（bind/connect）
- `--print-every`: 每N个chunks打印一次统计信息

## 输出格式

启用ASR后，每处理一个音频chunk会输出：

```
[14:30:25] [192.168.10.19] [citizen] ASR: 你好，我想咨询一下业务办理流程
  Meta: peer_ip=192.168.10.19, source=citizen, start_ts=1703123425.123, end_ts=1703123425.623, chunk_size=4000
```

## 支持的ASR模型

- `paraformer-zh-streaming`: 中文实时流式语音识别
- `paraformer-zh`: 中文离线语音识别
- `paraformer-zh-online`: 中文在线实时识别

## 注意事项

1. 首次运行会自动下载模型，可能需要一些时间
2. 需要足够的内存来运行模型
3. PCM音频格式假设为16位，采样率8000Hz
4. 只有非空识别结果才会打印

## 故障排除

如果遇到导入错误，请确保已安装相关依赖：

```bash
pip install funasr numpy pyzmq
```

如果模型加载失败，检查网络连接或尝试其他模型。
