#!/bin/bash

# Production socat receiver script
LOG_DIR="./log/pcap_recover"
MAIN_LOG="${LOG_DIR}/socat_main.log"
SOCAT_LOG="${LOG_DIR}/socat.log"
PYTHON_LOG="${LOG_DIR}/python.log"
FIFO_PATH="/tmp/pcap_stream.fifo"
RESTART_INTERVAL=0.1

# Create log directory
mkdir -p ${LOG_DIR}
chmod 755 ${LOG_DIR}

# Log startup information
echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting socat receiver service" | tee -a "$MAIN_LOG"


# Ensure FIFO exists
ensure_fifo() {
    if [ ! -p "$FIFO_PATH" ]; then
        rm -f "$FIFO_PATH" 2>/dev/null || true
        mkfifo "$FIFO_PATH"
        chmod 666 "$FIFO_PATH"
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Created FIFO: $FIFO_PATH" | tee -a "$MAIN_LOG"
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


# Start independent Python reader process
start_python_reader() {
    # Don't start duplicate process if one is already running
    if pgrep -f "python3.*recover_audio_streaming.py.*$FIFO_PATH" >/dev/null 2>&1; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Python reader process already running" | tee -a "$MAIN_LOG"
        return
    fi
    
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting Python reader process..." | tee -a "$MAIN_LOG"
    stdbuf -oL /home/barryhuang/miniconda3/envs/py310/bin/python3 \
        /home/barryhuang/work/recover_audio_streaming.py "$FIFO_PATH" \
        --zmq --zmq-endpoint 'tcp://127.0.0.1:5555' --chunk-seconds 2 \
        >> "$PYTHON_LOG" 2>&1 &
    PYTHON_READER_PID=$!
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Python reader process PID: $PYTHON_READER_PID" | tee -a "$MAIN_LOG"
}

# Cleanup function
cleanup() {
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Service stopping, cleaning up resources..." | tee -a "$MAIN_LOG"
    
    # Find and kill Python reader processes
    PYTHON_PIDS=$(pgrep -f "python3.*recover_audio_streaming.py.*$FIFO_PATH" 2>/dev/null)
    if [ -n "$PYTHON_PIDS" ]; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Terminating Python processes: $PYTHON_PIDS" | tee -a "$MAIN_LOG"
        kill $PYTHON_PIDS 2>/dev/null
    fi
    
    # Kill FIFO keeper processes
    KEEPER_PIDS=$(pgrep -f "fifo_keeper_for_" 2>/dev/null)
    if [ -n "$KEEPER_PIDS" ]; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Terminating FIFO keeper processes: $KEEPER_PIDS" | tee -a "$MAIN_LOG"
        kill $KEEPER_PIDS 2>/dev/null
    fi
    
    # Clean up temporary files (none needed now)
    
    # Record final status
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Final process status:" | tee -a "$MAIN_LOG"
    ps aux | grep -E "socat|python3.*recover_audio_streaming|fifo_keeper_for_" | grep -v grep | tee -a "$MAIN_LOG"
    
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Service stopped" | tee -a "$MAIN_LOG"
    
    # Exit explicitly
    exit 0
}

# Handle SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM EXIT

# Start decoupled mode: ensure FIFO and Python process first, then cycle socat
ensure_fifo

# Start the FIFO keeper first (most important - prevents EOF)
start_fifo_keeper

# Now start the Python reader
start_python_reader

echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Entering socat loop..." | tee -a "$MAIN_LOG"
while true; do
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting socat listening on 8900 -> FIFO" | tee -a "$MAIN_LOG"
    
    # Use fork option to allow multiple connections, write directly to main FIFO
    socat -d TCP-LISTEN:8900,reuseaddr,fork,so-keepalive=1,keepidle=15,keepintvl=5,keepcnt=6 \
    SYSTEM:"stdbuf -oL sh -c 'cat > \"$FIFO_PATH\"'" \
    2>> "$SOCAT_LOG"

    SOCAT_EXIT=$?
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): socat exited, return code: $SOCAT_EXIT" | tee -a "$MAIN_LOG"
    
    # If exit was due to SIGINT or SIGTERM, break the loop
    if [ $SOCAT_EXIT -eq 130 ] || [ $SOCAT_EXIT -eq 143 ]; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Received termination signal, stopping service" | tee -a "$MAIN_LOG"
        break
    fi
    
    # Ensure FIFO keeper is still running (critical for preventing EOF)
    if ! pgrep -f "fifo_keeper_for_" >/dev/null 2>&1; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): FIFO keeper not found, restarting..." | tee -a "$MAIN_LOG"
        start_fifo_keeper
    fi
    
    sleep $RESTART_INTERVAL
    
    # Ensure Python is still running (but don't restart it)
    if ! pgrep -f "python3.*recover_audio_streaming.py.*$FIFO_PATH" >/dev/null 2>&1; then
        echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Python process not found, starting..." | tee -a "$MAIN_LOG"
        start_python_reader
    fi
done

# Final cleanup will be handled by the trap