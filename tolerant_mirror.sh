#!/bin/bash

# 容错版RTP流量镜像脚本 - 遇到异常数据包直接丢弃而不断开连接

# 配置
AI_SERVER_IP="${AI_SERVER_IP:-100.120.241.10}"
AI_PORT="${AI_PORT:-8900}"
LOG_FILE="/var/log/tolerant_mirror.log"
MAX_SNAPLEN=524288  # 增加到512KB
BUFFER_SIZE=16384

# 创建日志目录
mkdir -p $(dirname $LOG_FILE)

# 显示配置
echo "=== 容错版RTP流量镜像 ==="
echo "目标服务器: $AI_SERVER_IP:$AI_PORT"
echo "最大捕获长度: $MAX_SNAPLEN 字节"
echo "日志文件: $LOG_FILE"
echo

# 捕获退出信号
trap 'echo "$(date): 接收到停止信号，正在退出..." >> $LOG_FILE; exit 0' SIGINT SIGTERM

# 记录启动
echo "$(date): 启动容错版RTP流量镜像" > $LOG_FILE

# 使用更可靠的方式：通过临时文件进行缓冲
echo "$(date): 使用临时文件缓冲方式启动镜像" >> $LOG_FILE

# 创建命名管道
FIFO_PATH="/tmp/rtp_fifo"
rm -f $FIFO_PATH
mkfifo $FIFO_PATH

# 启动接收和发送进程
echo "$(date): 启动tcpdump和nc" >> $LOG_FILE

# 启动发送进程
(cat $FIFO_PATH | nc -u $AI_SERVER_IP $AI_PORT 2>>$LOG_FILE || echo "$(date): nc退出，错误码: $?" >> $LOG_FILE) &
SENDER_PID=$!

# 启动tcpdump，使用容错参数
# -K: 不验证校验和
# -Q: 安静模式，减少错误输出
# -V: 即使有错误也继续处理
# --time-stamp-precision=micro: 使用微秒精度，减少时间戳问题
# -G 60: 每60秒轮换一次输出
tcpdump -i any -w $FIFO_PATH -U -B $BUFFER_SIZE -s $MAX_SNAPLEN \
    -K -Q -V --time-stamp-precision=micro \
    'udp and (portrange 10000-20000 or port 5060)' \
    2>>$LOG_FILE || echo "$(date): tcpdump退出，错误码: $?" >> $LOG_FILE

# 如果tcpdump退出，也停止nc
kill $SENDER_PID 2>/dev/null

# 清理
rm -f $FIFO_PATH

echo "$(date): 镜像服务已停止" >> $LOG_FILE
