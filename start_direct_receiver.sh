#!/bin/bash

# Configuration
PORT="${PORT:-8900}"
OUTPUT_DIR="${OUTPUT_DIR:-extracted_audio}"
LOG_FILE="./logs/direct_receiver.log"
WHITELIST_IPS="${WHITELIST_IPS:-}" # Space-separated list of IPs
USE_WHITELIST="${USE_WHITELIST:-false}"

# Create directories
mkdir -p "$OUTPUT_DIR"
mkdir -p $(dirname "$LOG_FILE")

# Log start
echo "$(date): Starting direct UDP receiver on port $PORT" | tee -a "$LOG_FILE"
echo "Output directory: $OUTPUT_DIR" | tee -a "$LOG_FILE"
echo "Whitelist mode: $USE_WHITELIST" | tee -a "$LOG_FILE"
if [ "$USE_WHITELIST" = "true" ]; then
    echo "Whitelisted IPs: $WHITELIST_IPS" | tee -a "$LOG_FILE"
fi

# Construct command arguments
CMD="python3 direct_receiver.py --port $PORT --output-dir $OUTPUT_DIR"
if [ "$USE_WHITELIST" = "true" ]; then
    CMD="$CMD --use-whitelist"
    if [ -n "$WHITELIST_IPS" ]; then
        for ip in $WHITELIST_IPS; do
            CMD="$CMD --whitelist $ip"
        done
    fi
fi

# Make the receiver script executable
chmod +x direct_receiver.py

# Start the receiver in a loop to ensure it restarts if it crashes
while true; do
    echo "$(date): Starting direct receiver..." | tee -a "$LOG_FILE"
    $CMD
    
    # If we get here, the receiver has crashed
    echo "$(date): Direct receiver exited, restarting in 3 seconds..." | tee -a "$LOG_FILE"
    sleep 3
done
