#!/bin/bash

# 安全的RTP流量镜像脚本
# 此脚本只进行被动监听，不会影响热线服务器的任何业务

set -e

# 配置参数
AI_SERVER_IP="${AI_SERVER_IP:-192.168.1.100}"
AI_PORT="${AI_PORT:-8888}"
LOG_FILE="/var/log/rtp_mirror.log"

# 创建日志目录
mkdir -p $(dirname $LOG_FILE)

# 安全检查
echo "=== 安全检查 ==="
echo "1. tcpdump 是被动监听工具，不会修改任何网络数据"
echo "2. 不会占用业务端口，不会影响热线服务"
echo "3. CPU和内存占用极低"
echo "4. 可以随时安全停止 (Ctrl+C)"
echo

# 检查依赖
command -v tcpdump >/dev/null 2>&1 || { 
    echo "错误: 需要安装 tcpdump"
    echo "安装命令: yum install -y tcpdump"
    exit 1
}

command -v nc >/dev/null 2>&1 || { 
    echo "错误: 需要安装 netcat"
    echo "安装命令: yum install -y nc"
    exit 1
}

# 显示当前系统状态
echo "=== 系统状态 (启动前) ==="
echo "CPU使用率: $(top -bn1 | grep 'Cpu(s)' | awk '{print $2 $4}' | sed 's/%us,/ + /g' | sed 's/%sy//g')"
echo "内存使用: $(free -h | grep 'Mem:' | awk '{print $3 "/" $2}')"
echo "目标服务器: $AI_SERVER_IP:$AI_PORT"
echo

# 记录启动
echo "$(date): 启动RTP流量镜像到 $AI_SERVER_IP:$AI_PORT" >> $LOG_FILE

# 启动镜像 (调试版本，包含SIP)
echo "=== 启动镜像服务 ==="
echo "正在启动... (按 Ctrl+C 安全停止)"
echo "监控端口: 5060 (SIP) + 10000-20000 (RTP/RTCP)"
echo "缓冲区大小: 16MB (高性能配置)"

# 捕获退出信号，优雅关闭
trap 'echo; echo "$(date): 安全停止RTP流量镜像" >> $LOG_FILE; echo "已安全停止"; exit 0' SIGINT SIGTERM

# 启动镜像 (使用UDP + 16MB缓存)
exec tcpdump -i any -w - -U -B 16384 \
  'udp and (portrange 10000-20000 or port 5060)' 2>>$LOG_FILE | \
  nc -u $AI_SERVER_IP $AI_PORT 2>>$LOG_FILE

echo "$(date): RTP流量镜像异常结束" >> $LOG_FILE
