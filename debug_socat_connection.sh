#!/bin/bash

# UDP接收端调试脚本
LOG_DIR="./udp_debug_logs"
MAIN_LOG="${LOG_DIR}/udp_main.log"
SOCAT_LOG="${LOG_DIR}/udp_socat_detailed.log"
PYTHON_LOG="${LOG_DIR}/udp_python_process.log"
NETWORK_LOG="${LOG_DIR}/udp_network_status.log"
STRACE_LOG="${LOG_DIR}/udp_socat_strace.log"
AUDIT_RAW_LOG="${LOG_DIR}/udp_audit_raw.log"
AUDIT_SUMMARY_LOG="${LOG_DIR}/udp_audit_summary.log"
BPFTRACE_LOG="${LOG_DIR}/udp_bpftrace_sigterm.log"
FIFO_PATH="/tmp/udp_stream.fifo"
RESTART_INTERVAL=0.1
# 记录启动时间（用于过滤审计日志）
SCRIPT_START_TIME="$(date +"%Y-%m-%d %H:%M:%S")"

# auditd 信号追踪（方案A）
AUDIT_ENABLED=0
SUDO_BIN="sudo"
BPFTRACE_ENABLED=0
BPFTRACE_PID=""

enable_audit_sigtrace() {
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 尝试启用auditd信号追踪(方案A)" | tee -a "$MAIN_LOG"
    if ! command -v auditctl >/dev/null 2>&1; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 未找到auditctl，跳过审计启用。建议安装auditd并以root运行。" | tee -a "$MAIN_LOG"
        return
    fi
    # 确保auditd在运行
    if ! $SUDO_BIN pgrep -x auditd >/dev/null 2>&1; then
        $SUDO_BIN service auditd start >/dev/null 2>&1 || $SUDO_BIN systemctl start auditd >/dev/null 2>&1
    fi
    if ! $SUDO_BIN pgrep -x auditd >/dev/null 2>&1; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 无法启动auditd（需要root），将无法追踪SIGTERM来源。" | tee -a "$MAIN_LOG"
        return
    fi
    # 添加规则：记录 kill/tkill/tgkill/rt_sigqueueinfo
    $SUDO_BIN auditctl -a always,exit -F arch=b64 -S kill -S tkill -S tgkill -S rt_sigqueueinfo -k sigtrace_udp 2>>"$MAIN_LOG"
    $SUDO_BIN auditctl -a always,exit -F arch=b32 -S kill -S tkill -S tgkill -S rt_sigqueueinfo -k sigtrace_udp 2>>"$MAIN_LOG"
    AUDIT_ENABLED=1
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 已启用auditd规则(key=sigtrace_udp)" | tee -a "$MAIN_LOG"
}

dump_audit_sigtrace() {
    if [ "$AUDIT_ENABLED" -ne 1 ]; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): auditd未启用，跳过信号来源导出" | tee -a "$MAIN_LOG"
        return
    fi
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 导出自${SCRIPT_START_TIME}以来的SIGTERM(15)相关审计记录..." | tee -a "$MAIN_LOG"
    # 导出原始记录
    $SUDO_BIN ausearch -k sigtrace_udp -ts "$SCRIPT_START_TIME" 2>&1 | tee "$AUDIT_RAW_LOG" >/dev/null
    # 生成简要摘要：谁向谁发送了SIGTERM
    echo "==== SIGTERM发送摘要 ====" > "$AUDIT_SUMMARY_LOG"
    $SUDO_BIN ausearch -k sigtrace_udp -ts "$SCRIPT_START_TIME" 2>/dev/null \
      | awk 'BEGIN{RS="--"} /syscall=(kill|tkill|tgkill|rt_sigqueueinfo)/{print $0"\n"}' \
      | sed -n 's/.*pid=\([0-9]\+\).*exe=\([^ ]\+\).*auid=.*/SENDER_PID=\1 SENDER_EXE=\2/p' >> "$AUDIT_SUMMARY_LOG"
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 审计原始输出 -> $AUDIT_RAW_LOG" | tee -a "$MAIN_LOG"
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 审计摘要输出 -> $AUDIT_SUMMARY_LOG" | tee -a "$MAIN_LOG"
}

# bpftrace 信号追踪（无需重启；需root且安装bpftrace）
enable_bpftrace_sigtrace() {
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 尝试启用bpftrace信号追踪(替代方案)" | tee -a "$MAIN_LOG"
    if ! command -v bpftrace >/dev/null 2>&1; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 未找到bpftrace，跳过。可安装后重试：yum/dnf/apt install bpftrace" | tee -a "$MAIN_LOG"
        return
    fi
    # 以root运行bpftrace（若当前不是root）
    BPF_CMD='bpftrace -e '\''tracepoint:signal:signal_generate /args.sig==15/ { printf("%s(%d) -> %d sig=%d\n", comm, pid, args.pid, args.sig); }'\'''
    if [ "$(id -u)" -ne 0 ]; then
        $SUDO_BIN bash -c "$BPF_CMD" >> "$BPFTRACE_LOG" 2>&1 &
    else
        bash -c "$BPF_CMD" >> "$BPFTRACE_LOG" 2>&1 &
    fi
    BPFTRACE_PID=$!
    if kill -0 "$BPFTRACE_PID" 2>/dev/null; then
        BPFTRACE_ENABLED=1
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 已启动bpftrace(记录SIGTERM)：PID=$BPFTRACE_PID -> $BPFTRACE_LOG" | tee -a "$MAIN_LOG"
    else
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 启动bpftrace失败（可能缺少权限或内核支持）" | tee -a "$MAIN_LOG"
    fi
}

# 创建日志目录
mkdir -p ${LOG_DIR}

# 记录系统信息
echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 开始UDP接收调试" | tee -a "$MAIN_LOG"
echo "系统信息:" | tee -a "$MAIN_LOG"
uname -a | tee -a "$MAIN_LOG"
echo "网络接口:" | tee -a "$MAIN_LOG"
ip a | grep -E "inet|state" | tee -a "$MAIN_LOG"

# 启用审计追踪（需要root权限，否则将被跳过）
enable_audit_sigtrace
# 启用bpftrace追踪（无需重启；如有权限则记录SIGTERM来源）
enable_bpftrace_sigtrace

# 监控网络连接
monitor_network() {
    while true; do
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): UDP连接状态" >> "$NETWORK_LOG"
        ss -un | awk -v ts="$(date +'%Y-%m-%d %H:%M:%S.%3N')" '{print ts " ss: " $0}' | grep -E "8900|5555" >> "$NETWORK_LOG"
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 活跃连接详情" >> "$NETWORK_LOG"
        netstat -anup | awk -v ts="$(date +'%Y-%m-%d %H:%M:%S.%3N')" '{print ts " netstat: " $0}' | grep -E "8900|5555" >> "$NETWORK_LOG"
        echo "---" >> "$NETWORK_LOG"
        sleep 1
    done
}

# 启动网络监控
monitor_network &
NETWORK_PID=$!

# 监控Python进程
monitor_python() {
    while true; do
        PYTHON_PIDS=$(pgrep -f "python3.*udp_parser")
        if [ -n "$PYTHON_PIDS" ]; then
            for pid in $PYTHON_PIDS; do
                echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Python进程状态 PID=$pid" >> "$PYTHON_LOG"
                ps -o pid,ppid,stat,wchan:20,cmd -p $pid >> "$PYTHON_LOG"
                
                # 检查文件描述符
                echo "文件描述符:" >> "$PYTHON_LOG"
                ls -l /proc/$pid/fd >> "$PYTHON_LOG" 2>&1
                
                # 检查内存使用
                echo "内存使用:" >> "$PYTHON_LOG"
                cat /proc/$pid/status | grep -E "VmRSS|VmSize" >> "$PYTHON_LOG"
                echo "---" >> "$PYTHON_LOG"
            done
        else
            echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 没有发现Python进程" >> "$PYTHON_LOG"
        fi
        sleep 2
    done
}

# 启动Python监控
monitor_python &
PYTHON_PID=$!

# 确保FIFO存在
ensure_fifo() {
    if [ ! -p "$FIFO_PATH" ]; then
        rm -f "$FIFO_PATH" 2>/dev/null || true
        mkfifo "$FIFO_PATH"
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 已创建FIFO: $FIFO_PATH" | tee -a "$MAIN_LOG"
    fi
}

# 启动独立Python读取进程（与socat解耦）
start_python_reader() {
    # 若已经有读取同路径的进程在运行，则不重复启动
    if pgrep -f "python3.*recover_audio_streaming.py.*$FIFO_PATH" >/dev/null 2>&1; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Python读取进程已在运行（读取$FIFO_PATH）" | tee -a "$MAIN_LOG"
        return
    fi
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 启动Python UDP解析进程（$FIFO_PATH）..." | tee -a "$MAIN_LOG"
    stdbuf -oL /home/barryhuang/miniconda3/envs/py310/bin/python3 \
        /home/barryhuang/work/recover_audio_streaming.py "$FIFO_PATH" \
        --zmq --zmq-endpoint 'tcp://127.0.0.1:5555' --chunk-seconds 2 \
        >> "$PYTHON_LOG" 2>&1 &
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Python读取进程PID: $!" | tee -a "$MAIN_LOG"
}

# 清理函数
cleanup() {
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 正在清理监控进程..." | tee -a "$MAIN_LOG"
    kill $NETWORK_PID $PYTHON_PID 2>/dev/null
    
    # 收集最终状态
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 最终UDP状态:" | tee -a "$MAIN_LOG"
    ss -un | grep -E "8900|5555" | tee -a "$MAIN_LOG"
    
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 最终进程状态:" | tee -a "$MAIN_LOG"
    ps aux | grep -E "socat|python3.*udp_parser" | grep -v grep | tee -a "$MAIN_LOG"
    
    # 导出审计日志，定位SIGTERM来源
    dump_audit_sigtrace
    
    # 终止bpftrace后台任务
    if [ "$BPFTRACE_ENABLED" -eq 1 ] && [ -n "$BPFTRACE_PID" ]; then
        kill "$BPFTRACE_PID" 2>/dev/null
        wait "$BPFTRACE_PID" 2>/dev/null
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 已停止bpftrace并写入 -> $BPFTRACE_LOG" | tee -a "$MAIN_LOG"
    fi
    
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): UDP调试会话结束" | tee -a "$MAIN_LOG"
}

# 设置清理钩子
trap cleanup EXIT

# 启动解耦模式：先保证FIFO和Python常驻，再循环重启socat
ensure_fifo
start_python_reader

echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 进入UDP socat循环（仅提供管道，自动重启）..." | tee -a "$MAIN_LOG"
while true; do
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): 启动socat监听UDP:8900 -> FIFO($FIFO_PATH)" | tee -a "$MAIN_LOG"
    if command -v ts >/dev/null 2>&1; then
        strace -ff -tt -T -e trace=network,read,write,close -o "$STRACE_LOG" \
        socat -d -d -d -d UDP-LISTEN:8900,reuseaddr \
        SYSTEM:"stdbuf -oL sh -c 'cat > \"$FIFO_PATH\"'" \
        2> >(stdbuf -oL -eL ts '%Y-%m-%d %H:%M:%S.%3N' >> "$SOCAT_LOG")
    else
        strace -ff -tt -T -e trace=network,read,write,close -o "$STRACE_LOG" \
        socat -d -d -d -d UDP-LISTEN:8900,reuseaddr \
        SYSTEM:"stdbuf -oL sh -c 'cat > \"$FIFO_PATH\"'" \
        2> >(stdbuf -oL -eL awk '{ cmd="date +\"%Y-%m-%d %H:%M:%S.%3N\""; if ((cmd | getline d) <= 0) { close(cmd); cmd="date +\"%Y-%m-%d %H:%M:%S\""; cmd | getline d; } close(cmd); print d, $0; fflush(); }' >> "$SOCAT_LOG")
    fi

    SOCAT_EXIT=$?
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): socat退出，返回码: $SOCAT_EXIT；${RESTART_INTERVAL}秒后重启" | tee -a "$MAIN_LOG"
    sleep $RESTART_INTERVAL
    # 若Python不在，重启Python读取进程
    start_python_reader
done

# 注意：以上循环常驻运行；收尾日志在清理函数中打印