#!/bin/bash

# 调试版本的镜像脚本，记录详细日志

set -e

# 配置
AI_SERVER_IP="${AI_SERVER_IP:-100.120.241.10}"
AI_PORT="${AI_PORT:-8900}"
LOG_DIR="/var/log/rtp_mirror"
MAIN_LOG="$LOG_DIR/mirror.log"
ERROR_LOG="$LOG_DIR/error.log"
STATS_LOG="$LOG_DIR/stats.log"
BUFFER_SIZE=16384

# 创建日志目录
mkdir -p $LOG_DIR

# 显示配置
echo "=== 调试版RTP流量镜像 ==="
echo "目标服务器: $AI_SERVER_IP:$AI_PORT"
echo "日志目录: $LOG_DIR"
echo

# 记录系统信息
log_system_info() {
    echo "--- $(date): 系统信息 ---" >> $STATS_LOG
    echo "内存使用:" >> $STATS_LOG
    free -h >> $STATS_LOG
    echo "网络连接:" >> $STATS_LOG
    netstat -anu | grep $AI_SERVER_IP >> $STATS_LOG
    echo "进程状态:" >> $STATS_LOG
    ps aux | grep -E "tcpdump|nc|socat" | grep -v grep >> $STATS_LOG
    echo >> $STATS_LOG
}

# 启动系统监控
start_monitoring() {
    while true; do
        log_system_info
        sleep 60
    done
}

# 启动监控
start_monitoring &
MONITOR_PID=$!

# 捕获退出信号
trap 'echo "$(date): 接收到停止信号" >> $MAIN_LOG; kill $MONITOR_PID 2>/dev/null; exit 0' SIGINT SIGTERM

# 记录启动
echo "$(date): 启动调试版RTP流量镜像" >> $MAIN_LOG

# 使用socat替代nc
echo "$(date): 使用socat启动镜像" >> $MAIN_LOG

# 启动tcpdump和socat，记录详细日志
tcpdump -i any -w - -U -B $BUFFER_SIZE \
    'udp and (portrange 10000-20000 or port 5060)' 2>>$ERROR_LOG | \
    socat -d -d - UDP:$AI_SERVER_IP:$AI_PORT 2>>$ERROR_LOG

# 如果到这里，说明连接断开了
echo "$(date): 连接断开，记录最终状态" >> $MAIN_LOG
log_system_info

echo "$(date): 脚本结束，查看日志了解详情:" >> $MAIN_LOG
echo "  - 主日志: $MAIN_LOG" >> $MAIN_LOG
echo "  - 错误日志: $ERROR_LOG" >> $MAIN_LOG
echo "  - 状态日志: $STATS_LOG" >> $MAIN_LOG
