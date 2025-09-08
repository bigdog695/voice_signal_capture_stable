#!/bin/bash

# 接收端测试脚本
# 用于验证从热线服务器转发过来的RTP数据是否正常

set -e

# 配置参数
LISTEN_PORT="${LISTEN_PORT:-8888}"
OUTPUT_DIR="${OUTPUT_DIR:-extracted_audio_realtime}"
LOG_FILE="/var/log/rtp_receiver.log"
TEST_PCAP_FILE="/tmp/received_rtp_test.pcap"

# 创建必要目录
mkdir -p $(dirname $LOG_FILE)
mkdir -p $OUTPUT_DIR

echo "=== RTP接收端测试 ==="
echo "监听端口: $LISTEN_PORT"
echo "输出目录: $OUTPUT_DIR"
echo "测试pcap: $TEST_PCAP_FILE"
echo

# 检查依赖
command -v nc >/dev/null 2>&1 || { 
    echo "错误: 需要安装 netcat"
    echo "Ubuntu/Debian: apt-get install netcat"
    echo "CentOS/RHEL: yum install nc"
    exit 1
}

command -v python3 >/dev/null 2>&1 || { 
    echo "错误: 需要安装 python3"
    exit 1
}

command -v tcpdump >/dev/null 2>&1 || { 
    echo "错误: 需要安装 tcpdump"
    exit 1
}

# 检查Python脚本
if [ ! -f "recover_audio_streaming.py" ]; then
    echo "错误: 找不到 recover_audio_streaming.py"
    echo "请确保在正确的目录运行此脚本"
    exit 1
fi

echo "=== 依赖检查完成 ==="
echo

# 清理之前的测试文件
rm -f $TEST_PCAP_FILE
rm -rf $OUTPUT_DIR/*

echo "=== 启动接收测试 ==="
echo "1. 首先启动接收服务"
echo "2. 然后在热线服务器运行: ./start_mirror_safe.sh"
echo "3. 观察是否有数据接收和音频生成"
echo

# 捕获退出信号
trap 'echo; echo "停止测试..."; kill $(jobs -p) 2>/dev/null; rm -f $TEST_PCAP_FILE; echo "测试已停止"; exit 0' SIGINT SIGTERM

echo "正在启动接收服务 (端口 $LISTEN_PORT)..."

# 启动接收并同时保存到文件和管道给Python脚本
# 使用tee同时写入pcap文件和传给Python脚本
nc -l $LISTEN_PORT | tee $TEST_PCAP_FILE | python3 recover_audio_streaming.py /dev/stdin $OUTPUT_DIR &

RECEIVER_PID=$!

echo "✓ 接收服务已启动 (PID: $RECEIVER_PID)"
echo "✓ 正在监听端口 $LISTEN_PORT"
echo "✓ 音频将保存到: $OUTPUT_DIR"
echo "✓ 测试pcap将保存到: $TEST_PCAP_FILE"
echo

# 监控接收状态
echo "=== 实时监控 ==="
echo "等待热线服务器连接..."

LAST_SIZE=0
PACKET_COUNT=0

while kill -0 $RECEIVER_PID 2>/dev/null; do
    # 检查pcap文件大小变化
    if [ -f "$TEST_PCAP_FILE" ]; then
        CURRENT_SIZE=$(stat -c%s "$TEST_PCAP_FILE" 2>/dev/null || echo 0)
        if [ $CURRENT_SIZE -gt $LAST_SIZE ]; then
            echo "$(date '+%H:%M:%S') - 接收数据: ${CURRENT_SIZE} 字节 (+$((CURRENT_SIZE - LAST_SIZE)))"
            LAST_SIZE=$CURRENT_SIZE
        fi
    fi
    
    # 检查音频输出目录
    AUDIO_COUNT=$(find $OUTPUT_DIR -name "*.wav" 2>/dev/null | wc -l)
    if [ $AUDIO_COUNT -gt 0 ]; then
        echo "$(date '+%H:%M:%S') - 已生成音频文件: $AUDIO_COUNT 个"
    fi
    
    sleep 2
done

echo "接收服务已停止"
