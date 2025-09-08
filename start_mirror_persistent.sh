#!/bin/bash

# 持久化RTP流量镜像脚本
# 此脚本会在连接断开后自动重新连接

set -e

# 配置参数
AI_SERVER_IP="${AI_SERVER_IP:-100.120.241.10}"
AI_PORT="${AI_PORT:-8900}"
LOG_FILE="/var/log/rtp_mirror.log"
BUFFER_SIZE=16384  # 16MB缓冲区

# 创建日志目录
mkdir -p $(dirname $LOG_FILE)

# 显示配置
echo "=== 持久化RTP流量镜像 ==="
echo "目标服务器: $AI_SERVER_IP:$AI_PORT"
echo "缓冲区大小: ${BUFFER_SIZE}KB"
echo "日志文件: $LOG_FILE"
echo

# 捕获退出信号
trap 'echo "接收到停止信号，正在退出..."; exit 0' SIGINT SIGTERM

# 持久化镜像循环
echo "启动持久化镜像服务 (按Ctrl+C停止)"
echo "$(date) - 启动持久化镜像服务" >> $LOG_FILE

while true; do
    echo "$(date) - 启动tcpdump捕获..." >> $LOG_FILE
    
    # 使用UDP模式发送数据
    tcpdump -i any -w - -U -B $BUFFER_SIZE \
        'udp and (portrange 10000-20000 or port 5060)' 2>/dev/null | \
        nc -u $AI_SERVER_IP $AI_PORT
    
    # 如果到这里，说明连接断开了
    RECONNECT_DELAY=5
    echo "$(date) - 连接断开，${RECONNECT_DELAY}秒后重连..." >> $LOG_FILE
    echo "连接断开，${RECONNECT_DELAY}秒后重连..."
    sleep $RECONNECT_DELAY
done
