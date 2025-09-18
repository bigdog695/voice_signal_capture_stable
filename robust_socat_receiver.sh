#!/bin/bash

# 健壮的socat接收端脚本，包含防止连接断开的机制
LOG_DIR="./robust_receiver_logs"
MAIN_LOG="${LOG_DIR}/receiver_main.log"
SOCAT_LOG="${LOG_DIR}/socat_output.log"
PYTHON_LOG="${LOG_DIR}/python_output.log"
WATCHDOG_LOG="${LOG_DIR}/watchdog.log"

# 创建日志目录
mkdir -p ${LOG_DIR}

echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 启动健壮版socat接收端" | tee -a "$MAIN_LOG"

# 启动看门狗进程，监控socat和Python进程
start_watchdog() {
    while true; do
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 看门狗检查进程状态" >> "$WATCHDOG_LOG"
        
        # 检查socat进程
        SOCAT_PIDS=$(pgrep -f "socat.*TCP-LISTEN:8900")
        if [ -z "$SOCAT_PIDS" ]; then
            echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 警告: 未检测到socat进程，将重启主脚本" | tee -a "$WATCHDOG_LOG"
            # 杀死所有相关进程并重启
            pkill -f "python3.*recover_audio_streaming" 2>/dev/null
            # 通过发送USR1信号通知主进程重启
            kill -USR1 $$
            sleep 5
        else
            echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): socat进程正常运行: $SOCAT_PIDS" >> "$WATCHDOG_LOG"
        fi
        
        # 检查ZMQ服务器
        nc -z 127.0.0.1 5555 &>/dev/null
        if [ $? -ne 0 ]; then
            echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 警告: ZMQ服务器(127.0.0.1:5555)不可达" | tee -a "$WATCHDOG_LOG"
        else
            echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): ZMQ服务器正常运行" >> "$WATCHDOG_LOG"
        fi
        
        sleep 30  # 每30秒检查一次
    done
}

# 启动看门狗
start_watchdog &
WATCHDOG_PID=$!

# 处理USR1信号（重启socat）
restart_socat() {
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 收到重启信号，重启socat..." | tee -a "$MAIN_LOG"
    # 杀死当前socat进程
    pkill -f "socat.*TCP-LISTEN:8900" 2>/dev/null
    sleep 2
    # 重新启动socat
    start_socat
}

# 设置信号处理
trap restart_socat USR1
trap 'kill $WATCHDOG_PID 2>/dev/null; exit' EXIT INT TERM

# 启动socat的函数
start_socat() {
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 启动socat..." | tee -a "$MAIN_LOG"
    
    # 确保之前的进程已经清理
    pkill -f "socat.*TCP-LISTEN:8900" 2>/dev/null
    pkill -f "python3.*recover_audio_streaming" 2>/dev/null
    sleep 1
    
    # 设置keepalive参数，防止连接超时断开
    # so-keepalive: 启用TCP keepalive
    # keepidle: 空闲多少秒后开始发送keepalive包 (30秒)
    # keepintvl: keepalive包发送间隔 (5秒)
    # keepcnt: 发送多少次keepalive无响应后断开连接 (10次)
    socat -d -d -d \
        TCP-LISTEN:8900,reuseaddr,so-keepalive=1,keepidle=30,keepintvl=5,keepcnt=10 \
        EXEC:"python3 /home/barryhuang/work/recover_audio_streaming.py /dev/stdin --zmq --zmq-endpoint 'tcp://127.0.0.1:5555' --chunk-seconds 2 2>> $PYTHON_LOG" \
        2>> "$SOCAT_LOG" || {
            echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): socat异常退出，返回码: $?" | tee -a "$MAIN_LOG"
            sleep 5
            echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 尝试自动重启socat..." | tee -a "$MAIN_LOG"
            start_socat  # 递归调用自己重启
        }
}

# 首次启动socat
start_socat

# 主循环，保持脚本运行
while true; do
    # 检查socat是否还在运行
    if ! pgrep -f "socat.*TCP-LISTEN:8900" &>/dev/null; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 检测到socat已退出，重新启动..." | tee -a "$MAIN_LOG"
        start_socat
    fi
    sleep 10
done
