#!/bin/bash

# Configuration
LISTEN_PORT="${LISTEN_PORT:-8900}"
OUTPUT_DIR="${OUTPUT_DIR:-extracted_audio}"
LOG_FILE="./logs/robust_receiver.log"
WHITELIST_IPS="${WHITELIST_IPS:-}" # Space-separated list of IPs
USE_WHITELIST="${USE_WHITELIST:-false}"

# Create directories
mkdir -p "$OUTPUT_DIR"
mkdir -p $(dirname "$LOG_FILE")

# Log start
echo "$(date): Starting robust UDP receiver on port $LISTEN_PORT" | tee -a "$LOG_FILE"
echo "Output directory: $OUTPUT_DIR" | tee -a "$LOG_FILE"
echo "Whitelist mode: $USE_WHITELIST" | tee -a "$LOG_FILE"
if [ "$USE_WHITELIST" = "true" ]; then
    echo "Whitelisted IPs: $WHITELIST_IPS" | tee -a "$LOG_FILE"
fi

# Construct Python arguments
PYTHON_ARGS="/dev/stdin $OUTPUT_DIR"
if [ "$USE_WHITELIST" = "true" ]; then
    PYTHON_ARGS+=" --use-whitelist"
    if [ -n "$WHITELIST_IPS" ]; then
        for ip in $WHITELIST_IPS; do
            PYTHON_ARGS+=" --whitelist $ip"
        done
    fi
fi

# Continuous processing loop
while true; do
    echo "$(date): Starting receiver pipeline..." | tee -a "$LOG_FILE"
    
    # Start the processing pipeline with basic options:
    # 1. nc listens for UDP packets
    # 2. tcpdump processes them with minimal options to avoid compatibility issues
    # 3. Python script processes the pcap data
    nc -u -l "$LISTEN_PORT" 2>>"$LOG_FILE" | \
    tcpdump -r - -w - 2>>"$LOG_FILE" | \
    python3 recover_audio_streaming.py $PYTHON_ARGS 2>>"$LOG_FILE"
    
    # If we get here, something broke the pipeline
    EXIT_CODE=$?
    echo "$(date): Pipeline exited with code $EXIT_CODE, restarting in 3 seconds..." | tee -a "$LOG_FILE"
    sleep 3
done