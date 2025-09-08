#!/bin/bash

# 具有错误恢复机制的RTP流量镜像脚本

# 配置
AI_SERVER_IP="${AI_SERVER_IP:-100.120.241.10}"
AI_PORT="${AI_PORT:-8900}"
LOG_FILE="/var/log/robust_mirror.log"
MAX_SNAPLEN=524288  # 增加到512KB
BUFFER_SIZE=16384

# 创建日志目录
mkdir -p $(dirname $LOG_FILE)

# 显示配置
echo "=== 具有错误恢复的RTP流量镜像 ==="
echo "目标服务器: $AI_SERVER_IP:$AI_PORT"
echo "最大捕获长度: $MAX_SNAPLEN 字节"
echo "日志文件: $LOG_FILE"
echo

# 捕获退出信号
trap 'echo "$(date): 接收到停止信号，正在退出..." >> $LOG_FILE; exit 0' SIGINT SIGTERM

# 记录启动
echo "$(date): 启动具有错误恢复的RTP流量镜像" > $LOG_FILE

# 持续运行，出错后自动重启
while true; do
    echo "$(date): 启动tcpdump和nc" >> $LOG_FILE
    
    # 使用增加的snaplen、容错参数和错误重定向
    (tcpdump -i any -w - -U -B $BUFFER_SIZE -s $MAX_SNAPLEN \
        -K -Q -V \
        'udp and (portrange 10000-20000 or port 5060)' 2>>$LOG_FILE || \
        echo "$(date): tcpdump退出，错误码: $?" >> $LOG_FILE) | \
    (nc -u $AI_SERVER_IP $AI_PORT 2>>$LOG_FILE || \
        echo "$(date): nc退出，错误码: $?" >> $LOG_FILE)
    
    # 如果到这里，说明命令已结束
    echo "$(date): 连接断开，5秒后重新连接..." >> $LOG_FILE
    sleep 5
done
