#!/bin/bash

# Debug script to monitor socat and python process lifecycle
LOG_FILE="./socat_python_logs/socat_debug.log"
PYTHON_LOG="./socat_python_logs/python_debug.log"
SOCAT_LOG="./socat_python_logs/socat_process.log"
CONN_LOG="./socat_python_logs/connection.log"

# Create log directory
mkdir -p ./socat_python_logs

echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting debug socat receiver..." | tee -a "$LOG_FILE"
echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Monitoring socat fork behavior for Python process restart" | tee -a "$LOG_FILE"

# Start connection monitoring
(
    while true; do
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Current TCP connections to port 8900:" >> "$CONN_LOG"
        netstat -ant | grep ":8900" >> "$CONN_LOG"
        echo "---" >> "$CONN_LOG"
        sleep 2
    done
) &
NETSTAT_PID=$!

# Function to monitor Python processes
monitor_python_processes() {
    while true; do
        PYTHON_PIDS=$(pgrep -f "python3.*recover_audio_streaming")
        if [ -n "$PYTHON_PIDS" ]; then
            for pid in $PYTHON_PIDS; do
                # Check if this is a new process we haven't seen before
                if ! grep -q "Monitoring Python PID $pid" "$LOG_FILE" 2>/dev/null; then
                    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): NEW Python process started by socat - PID: $pid" | tee -a "$LOG_FILE"
                    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Monitoring Python PID $pid" | tee -a "$LOG_FILE"
                    
                    # Log open file descriptors for this process
                    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): File descriptors for PID $pid:" >> "$LOG_FILE"
                    ls -l /proc/$pid/fd >> "$LOG_FILE" 2>/dev/null || echo "  (process already gone)" >> "$LOG_FILE"
                fi
                
                # Check if process is still alive
                if ! kill -0 $pid 2>/dev/null; then
                    if ! grep -q "Python process $pid terminated" "$LOG_FILE" 2>/dev/null; then
                        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Python process $pid terminated" | tee -a "$LOG_FILE"
                    fi
                fi
            done
        else
            echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): No active Python processes found" | tee -a "$LOG_FILE"
        fi
        sleep 0.5
    done
}

# Start Python process monitoring in background
monitor_python_processes &
MONITOR_PID=$!

# Main socat process
(
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting socat with detailed logging (will show fork events)..." | tee -a "$LOG_FILE"
    
    # Kill any existing socat and python processes
    pkill -f "socat.*TCP-LISTEN:8900" 2>/dev/null
    pkill -f "python3.*recover_audio_streaming" 2>/dev/null
    sleep 1
    
    # Create lock directory if it doesn't exist
    mkdir -p /tmp/socat_locks
    
    # Start socat with maximum verbose logging and keep-alive option
    # Using simpler configuration first to debug the issue
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting socat..." | tee -a "$LOG_FILE"
    
    # Note: Using TCP-LISTEN instead of TCP4-LISTEN to be more compatible
    # Using -d for debug info but not -v to avoid showing packet contents
    socat -d -d -d TCP-LISTEN:8900,reuseaddr,fork \
    SYSTEM:"stdbuf -oL python3 /home/barryhuang/work/recover_audio_streaming.py /dev/stdin --zmq --zmq-endpoint 'tcp://127.0.0.1:5555' --chunk-seconds 2 2>> $PYTHON_LOG" \
    2>> "$SOCAT_LOG"
    
    SOCAT_START_RESULT=$?
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Socat start result: $SOCAT_START_RESULT" | tee -a "$LOG_FILE"
    
    # If socat failed to start, show the error log
    if [ $SOCAT_START_RESULT -ne 0 ]; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Socat failed to start. Last few lines of error log:" | tee -a "$LOG_FILE"
        tail -n 5 "$SOCAT_LOG" 2>/dev/null | tee -a "$LOG_FILE"
    fi
    
    SOCAT_EXIT=$?
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): MAIN socat process exited with code: $SOCAT_EXIT" | tee -a "$LOG_FILE"
    
    # Final check of Python processes
    PYTHON_PIDS=$(pgrep -f "python3.*recover_audio_streaming")
    if [ -n "$PYTHON_PIDS" ]; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Python processes still running after socat exit: $PYTHON_PIDS" | tee -a "$LOG_FILE"
    else
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): All Python processes have exited" | tee -a "$LOG_FILE"
    fi
) &

SOCAT_PID=$!
echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Main socat process started with PID: $SOCAT_PID" | tee -a "$LOG_FILE"

# Monitor main socat process
while true; do
    if ! kill -0 $SOCAT_PID 2>/dev/null; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Main socat process ($SOCAT_PID) has terminated" | tee -a "$LOG_FILE"
        break
    fi
    sleep 1
done

# Clean up
kill $MONITOR_PID $NETSTAT_PID 2>/dev/null

echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Debug monitoring completed" | tee -a "$LOG_FILE"
