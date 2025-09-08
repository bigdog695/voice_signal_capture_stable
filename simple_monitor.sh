#!/bin/bash

# 简单的监控脚本，不依赖strace

# 配置
AI_SERVER_IP="${AI_SERVER_IP:-100.120.241.10}"
AI_PORT="${AI_PORT:-8900}"
LOG_FILE="/var/log/simple_monitor.log"

# 创建日志目录
mkdir -p $(dirname $LOG_FILE)

# 记录启动信息
echo "$(date): 启动监控" > $LOG_FILE
echo "目标: $AI_SERVER_IP:$AI_PORT" >> $LOG_FILE
echo >> $LOG_FILE

# 启动监控进程
(
    while true; do
        echo "$(date): 系统状态" >> $LOG_FILE
        echo "- 内存:" >> $LOG_FILE
        free -h >> $LOG_FILE
        echo "- 网络连接:" >> $LOG_FILE
        netstat -anu | grep $AI_SERVER_IP >> $LOG_FILE 2>&1 || echo "  无连接" >> $LOG_FILE
        echo "- 进程:" >> $LOG_FILE
        ps aux | grep -E "tcpdump|nc" | grep -v grep >> $LOG_FILE
        echo >> $LOG_FILE
        sleep 10
    done
) &
MONITOR_PID=$!

# 记录启动tcpdump和nc
echo "$(date): 启动tcpdump和nc" >> $LOG_FILE

# 启动带错误日志的tcpdump和nc
(tcpdump -i any -w - -U -B 16384 'udp and (portrange 10000-20000 or port 5060)' 2>>$LOG_FILE || \
    echo "$(date): tcpdump退出，错误码: $?" >> $LOG_FILE) | \
(nc -u $AI_SERVER_IP $AI_PORT 2>>$LOG_FILE || \
    echo "$(date): nc退出，错误码: $?" >> $LOG_FILE)

# 如果到这里，说明命令已结束
echo "$(date): 命令已结束" >> $LOG_FILE

# 停止监控
kill $MONITOR_PID 2>/dev/null

echo "$(date): 监控结束，日志保存在 $LOG_FILE" >> $LOG_FILE
echo "查看日志: cat $LOG_FILE"
