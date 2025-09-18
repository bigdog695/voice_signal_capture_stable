#!/bin/bash

# 增强版接收端脚本，包含防止连接断开的机制
LOG_DIR="./receiver_logs"
MAIN_LOG="${LOG_DIR}/receiver_main.log"
SOCAT_LOG="${LOG_DIR}/socat_output.log"
PYTHON_LOG="${LOG_DIR}/python_output.log"

# 创建日志目录
mkdir -p ${LOG_DIR}

echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 启动增强版接收端" | tee -a "$MAIN_LOG"

# 设置keepalive参数，防止连接超时断开
# so-keepalive: 启用TCP keepalive
# keepidle: 空闲多少秒后开始发送keepalive包 (30秒)
# keepintvl: keepalive包发送间隔 (5秒)
# keepcnt: 发送多少次keepalive无响应后断开连接 (10次)
socat -d -d -d \
    TCP-LISTEN:8900,reuseaddr,fork,so-keepalive=1,keepidle=30,keepintvl=5,keepcnt=10 \
    SYSTEM:"stdbuf -oL python3 /home/barryhuang/work/recover_audio_streaming.py /dev/stdin --zmq --zmq-endpoint 'tcp://127.0.0.1:5555' --chunk-seconds 2 2>> $PYTHON_LOG" \
    2>> "$SOCAT_LOG"

SOCAT_EXIT=$?
echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): socat退出，返回码: $SOCAT_EXIT" | tee -a "$MAIN_LOG"

# 检查socat错误日志
if [ -s "$SOCAT_LOG" ]; then
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): socat错误日志:" | tee -a "$MAIN_LOG"
    tail -20 "$SOCAT_LOG" | tee -a "$MAIN_LOG"
fi

echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 接收端脚本结束" | tee -a "$MAIN_LOG"
