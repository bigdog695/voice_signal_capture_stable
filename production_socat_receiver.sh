#!/bin/bash

# TCP receiver debug script
LOG_DIR="./debug_logs"
MAIN_LOG="${LOG_DIR}/main.log"
SOCAT_LOG="${LOG_DIR}/socat_detailed.log"
PYTHON_LOG="${LOG_DIR}/python_process.log"
NETWORK_LOG="${LOG_DIR}/network_status.log"
STRACE_LOG="${LOG_DIR}/socat_strace.log"
AUDIT_RAW_LOG="${LOG_DIR}/audit_raw.log"
AUDIT_SUMMARY_LOG="${LOG_DIR}/audit_summary.log"
BPFTRACE_LOG="${LOG_DIR}/bpftrace_sigterm.log"
FIFO_PATH="/tmp/pcap_stream.fifo"
RESTART_INTERVAL=0.1
# Record startup time (for filtering audit logs)
SCRIPT_START_TIME="$(date +"%Y-%m-%d %H:%M:%S")"

# auditd signal tracing (Option A)
AUDIT_ENABLED=0
SUDO_BIN="sudo"
BPFTRACE_ENABLED=0
BPFTRACE_PID=""

enable_audit_sigtrace() {
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Attempting to enable auditd signal tracing (Option A)" | tee -a "$MAIN_LOG"
    if ! command -v auditctl >/dev/null 2>&1; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): auditctl not found, skipping audit enable. Install auditd and run as root." | tee -a "$MAIN_LOG"
        return
    fi
    # Ensure auditd is running
    if ! $SUDO_BIN pgrep -x auditd >/dev/null 2>&1; then
        $SUDO_BIN service auditd start >/dev/null 2>&1 || $SUDO_BIN systemctl start auditd >/dev/null 2>&1
    fi
    if ! $SUDO_BIN pgrep -x auditd >/dev/null 2>&1; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Cannot start auditd (requires root), will not be able to trace SIGTERM source." | tee -a "$MAIN_LOG"
        return
    fi
    # Add rules: record kill/tkill/tgkill/rt_sigqueueinfo
    $SUDO_BIN auditctl -a always,exit -F arch=b64 -S kill -S tkill -S tgkill -S rt_sigqueueinfo -k sigtrace_tcp 2>>"$MAIN_LOG"
    $SUDO_BIN auditctl -a always,exit -F arch=b32 -S kill -S tkill -S tgkill -S rt_sigqueueinfo -k sigtrace_tcp 2>>"$MAIN_LOG"
    AUDIT_ENABLED=1
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): auditd rules enabled (key=sigtrace_tcp)" | tee -a "$MAIN_LOG"
}

dump_audit_sigtrace() {
    if [ "$AUDIT_ENABLED" -ne 1 ]; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): auditd not enabled, skipping signal source export" | tee -a "$MAIN_LOG"
        return
    fi
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Exporting SIGTERM(15) related audit records since ${SCRIPT_START_TIME}..." | tee -a "$MAIN_LOG"
    # Export raw records
    $SUDO_BIN ausearch -k sigtrace_tcp -ts "$SCRIPT_START_TIME" 2>&1 | tee "$AUDIT_RAW_LOG" >/dev/null
    # Generate summary: who sent SIGTERM to whom
    echo "==== SIGTERM Sending Summary ====" > "$AUDIT_SUMMARY_LOG"
    $SUDO_BIN ausearch -k sigtrace_tcp -ts "$SCRIPT_START_TIME" 2>/dev/null \
      | awk 'BEGIN{RS="--"} /syscall=(kill|tkill|tgkill|rt_sigqueueinfo)/{print $0"\n"}' \
      | sed -n 's/.*pid=\([0-9]\+\).*exe=\([^ ]\+\).*auid=.*/SENDER_PID=\1 SENDER_EXE=\2/p' >> "$AUDIT_SUMMARY_LOG"
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Audit raw output -> $AUDIT_RAW_LOG" | tee -a "$MAIN_LOG"
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Audit summary output -> $AUDIT_SUMMARY_LOG" | tee -a "$MAIN_LOG"
}

# bpftrace signal tracing (no restart needed; requires root and bpftrace installation)
enable_bpftrace_sigtrace() {
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Attempting to enable bpftrace signal tracing (alternative)" | tee -a "$MAIN_LOG"
    if ! command -v bpftrace >/dev/null 2>&1; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): bpftrace not found, skipping. Install with: yum/dnf/apt install bpftrace" | tee -a "$MAIN_LOG"
        return
    fi
    # Run bpftrace as root (if not currently root)
    BPF_CMD='bpftrace -e '\''tracepoint:signal:signal_generate /args.sig==15/ { printf("%s(%d) -> %d sig=%d\n", comm, pid, args.pid, args.sig); }'\'''
    if [ "$(id -u)" -ne 0 ]; then
        $SUDO_BIN bash -c "$BPF_CMD" >> "$BPFTRACE_LOG" 2>&1 &
    else
        bash -c "$BPF_CMD" >> "$BPFTRACE_LOG" 2>&1 &
    fi
    BPFTRACE_PID=$!
    if kill -0 "$BPFTRACE_PID" 2>/dev/null; then
        BPFTRACE_ENABLED=1
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): bpftrace started (recording SIGTERM): PID=$BPFTRACE_PID -> $BPFTRACE_LOG" | tee -a "$MAIN_LOG"
    else
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Failed to start bpftrace (may lack permissions or kernel support)" | tee -a "$MAIN_LOG"
    fi
}

# Create log directory
mkdir -p ${LOG_DIR}

# Record system information
echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting TCP receiver debug" | tee -a "$MAIN_LOG"
echo "System info:" | tee -a "$MAIN_LOG"
uname -a | tee -a "$MAIN_LOG"
echo "Network interfaces:" | tee -a "$MAIN_LOG"
ip a | grep -E "inet|state" | tee -a "$MAIN_LOG"

# Enable audit tracing (requires root privileges, otherwise skipped)
# enable_audit_sigtrace
# # Enable bpftrace tracing (no restart needed; record SIGTERM source if permissions available)
# enable_bpftrace_sigtrace

# Monitor network connections
monitor_network() {
    while true; do
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): TCP connection status" >> "$NETWORK_LOG"
        ss -tn 2>/dev/null | awk -v ts="$(date +'%Y-%m-%d %H:%M:%S.%3N')" '{print ts " ss: " $0}' | grep -E "8900|5555" >> "$NETWORK_LOG"
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Active connection details" >> "$NETWORK_LOG"
        netstat -antp 2>/dev/null | awk -v ts="$(date +'%Y-%m-%d %H:%M:%S.%3N')" '{print ts " netstat: " $0}' | grep -E "8900|5555" >> "$NETWORK_LOG"
        echo "---" >> "$NETWORK_LOG"
        sleep 1
    done
}

# Start network monitoring
monitor_network &
NETWORK_PID=$!

# Monitor Python processes
monitor_python() {
    while true; do
        PYTHON_PIDS=$(pgrep -f "python3.*recover_audio_streaming" 2>/dev/null)
        if [ -n "$PYTHON_PIDS" ]; then
            for pid in $PYTHON_PIDS; do
                echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Python process status PID=$pid" >> "$PYTHON_LOG"
                ps -o pid,ppid,stat,wchan:20,cmd -p $pid 2>/dev/null >> "$PYTHON_LOG"
                
                # Check file descriptors
                echo "File descriptors:" >> "$PYTHON_LOG"
                ls -l /proc/$pid/fd >> "$PYTHON_LOG" 2>&1
                
                # Check memory usage
                echo "Memory usage:" >> "$PYTHON_LOG"
                cat /proc/$pid/status 2>/dev/null | grep -E "VmRSS|VmSize" >> "$PYTHON_LOG"
                echo "---" >> "$PYTHON_LOG"
            done
        else
            echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): No Python processes found" >> "$PYTHON_LOG"
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

# Start a placeholder writer to keep FIFO open without writing data
start_fifo_keeper() {
    # Kill any existing FIFO keepers using a more specific pattern
    KEEPER_PIDS=$(pgrep -f "fifo_keeper_for_" 2>/dev/null)
    if [ -n "$KEEPER_PIDS" ]; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Killing existing FIFO keepers: $KEEPER_PIDS" | tee -a "$MAIN_LOG"
        kill $KEEPER_PIDS 2>/dev/null
        sleep 1
    fi
    
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting FIFO keeper (placeholder writer)" | tee -a "$MAIN_LOG"
    
    # Start a background process that keeps FIFO open for writing but doesn't write anything
    (
        # Set a unique process title for identification
        exec -a "fifo_keeper_for_${FIFO_PATH##*/}" bash -c '
            # Open FIFO for writing and keep it open indefinitely
            exec 3> "$1"
            
            # Just sleep forever while keeping the file descriptor open
            # This prevents EOF when socat disconnects
            while true; do
                sleep 3600
            done
            
            # Close the file descriptor when exiting (though this should never happen)
            exec 3>&-
        ' -- "$FIFO_PATH"
    ) &
    
    KEEPER_PID=$!
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): FIFO keeper PID: $KEEPER_PID (keeps FIFO open without writing)" | tee -a "$MAIN_LOG"
    
    # Verify the keeper started successfully
    sleep 1
    if kill -0 $KEEPER_PID 2>/dev/null; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): FIFO keeper started successfully" | tee -a "$MAIN_LOG"
    else
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): ERROR: FIFO keeper failed to start!" | tee -a "$MAIN_LOG"
    fi
}

# Start independent Python reader process (decoupled from socat)
start_python_reader() {
    # If a process reading the same path is already running, don't start another
    if pgrep -f "python3.*recover_audio_streaming_bak.py.*$FIFO_PATH" 2>/dev/null >/dev/null 2>&1; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Python reader process already running (reading $FIFO_PATH)" | tee -a "$MAIN_LOG"
        return
    fi
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting Python PCAP parser process ($FIFO_PATH)..." | tee -a "$MAIN_LOG"
    stdbuf -oL python3 \
        ./recover_audio_streaming_bak.py "$FIFO_PATH" \
        --zmq --zmq-endpoint 'tcp://127.0.0.1:5555' --chunk-seconds 2 \
        >> "$PYTHON_LOG" 2>&1 &
    PYTHON_PID=$!
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Python reader process PID: $PYTHON_PID" | tee -a "$MAIN_LOG"
}

# Cleanup function
cleanup() {
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Cleaning up monitoring processes..." | tee -a "$MAIN_LOG"
    kill $NETWORK_PID $PYTHON_PID 2>/dev/null
    
    # Kill all Python processes related to recover_audio_streaming
    PYTHON_PIDS=$(pgrep -f "python3.*recover_audio_streaming" 2>/dev/null)
    if [ -n "$PYTHON_PIDS" ]; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Terminating Python processes: $PYTHON_PIDS" | tee -a "$MAIN_LOG"
        kill $PYTHON_PIDS 2>/dev/null
        sleep 2
        # Force kill if still running
        kill -9 $PYTHON_PIDS 2>/dev/null
    fi
    
    # Kill FIFO keeper processes
    KEEPER_PIDS=$(pgrep -f "fifo_keeper_for_" 2>/dev/null)
    if [ -n "$KEEPER_PIDS" ]; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Terminating FIFO keeper processes: $KEEPER_PIDS" | tee -a "$MAIN_LOG"
        kill $KEEPER_PIDS 2>/dev/null
        sleep 1
    fi
    
    # Collect final status
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Final TCP status:" | tee -a "$MAIN_LOG"
    ss -tn 2>/dev/null | grep -E "8900|5555" | tee -a "$MAIN_LOG"
    
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Final process status:" | tee -a "$MAIN_LOG"
    ps aux 2>/dev/null | grep -E "socat|python3.*recover_audio_streaming|fifo_keeper_for_" | grep -v grep | tee -a "$MAIN_LOG"
    
    # Export audit logs to locate SIGTERM source
    dump_audit_sigtrace
    
    # Terminate bpftrace background task
    if [ "$BPFTRACE_ENABLED" -eq 1 ] && [ -n "$BPFTRACE_PID" ]; then
        kill "$BPFTRACE_PID" 2>/dev/null
        wait "$BPFTRACE_PID" 2>/dev/null
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Stopped bpftrace and wrote to -> $BPFTRACE_LOG" | tee -a "$MAIN_LOG"
    fi
    
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): TCP debug session ended" | tee -a "$MAIN_LOG"
}

# Set cleanup hook
trap cleanup EXIT

# Start decoupled mode: ensure FIFO and Python are persistent, then loop restart socat
ensure_fifo
start_fifo_keeper
start_python_reader

echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Entering TCP socat loop (pipe only, auto-restart)..." | tee -a "$MAIN_LOG"
while true; do
    # Check if socat parent process is already running before starting a new instance
    # Only check socat processes that are direct children of this script (not socat's own children)
    SOCAT_PIDS=$(pgrep -f "socat.*TCP-LISTEN:8900" 2>/dev/null | while read pid; do
        if [ "$(ps -o ppid= -p $pid)" -eq "$$" ]; then
            echo $pid
        fi
    done)
    
    if [ -n "$SOCAT_PIDS" ]; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): socat parent process already running (PIDs: $SOCAT_PIDS), waiting for it to exit..." | tee -a "$MAIN_LOG"
        # Wait a bit and check again
        sleep 0.5
        continue
    fi
    
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting socat listening TCP:8900 -> FIFO($FIFO_PATH)" | tee -a "$MAIN_LOG"
    
    socat -d -d -d -d TCP-LISTEN:8900,reuseaddr \
    SYSTEM:"stdbuf -oL cat > \"$FIFO_PATH\"" \
    2> >(stdbuf -oL -eL awk '{ cmd="date +\"%Y-%m-%d %H:%M:%S.%3N\""; if ((cmd | getline d) <= 0) { close(cmd); cmd="date +\"%Y-%m-%d %H:%M:%S\""; cmd | getline d; } close(cmd); print d, $0; fflush(); }' >> "$SOCAT_LOG")

    SOCAT_EXIT=$?
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): socat exited, return code: $SOCAT_EXIT; restarting in ${RESTART_INTERVAL} seconds" | tee -a "$MAIN_LOG"
    
    # 如果socat异常退出，清空FIFO中的残留数据
    if [ $SOCAT_EXIT -ne 0 ]; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): socat异常退出，清空FIFO中的残留数据..." | tee -a "$MAIN_LOG"
        # 清空FIFO，最多等待2秒
        timeout 2 cat "$FIFO_PATH" > /dev/null 2>&1 || true
    fi
    
    sleep $RESTART_INTERVAL
    
    # Ensure FIFO keeper is still running (critical - prevents EOF)
    if ! pgrep -f "fifo_keeper_for_" 2>/dev/null >/dev/null 2>&1; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): FIFO keeper not found, restarting..." | tee -a "$MAIN_LOG"
        start_fifo_keeper
    fi
    
    # If Python is not running, restart Python reader process
    start_python_reader
done

# Note: The above loop runs persistently; cleanup logs are printed in the cleanup function