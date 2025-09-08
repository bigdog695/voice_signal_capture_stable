#!/bin/bash

# Fault-tolerant RTP Receiver Script with tcpdump preprocessing
# This script receives UDP data, preprocesses it with tcpdump, and processes it with the streaming script

# Configuration
LISTEN_PORT="${LISTEN_PORT:-8900}"
OUTPUT_DIR="${OUTPUT_DIR:-extracted_audio}"
WHITELIST_IPS="${WHITELIST_IPS:-192.168.10.22}"
LOG_FILE="/var/log/rtp_receiver.log"

# Create directories
mkdir -p $(dirname $LOG_FILE)
mkdir -p $OUTPUT_DIR

# Display configuration
echo "=== RTP Receiver Service (with tcpdump preprocessing) ==="
echo "Listen port: $LISTEN_PORT"
echo "Output directory: $OUTPUT_DIR"
echo "Whitelist IPs: $WHITELIST_IPS"
echo "Log file: $LOG_FILE"
echo

# Check dependencies
command -v nc >/dev/null 2>&1 || { 
    echo "Error: netcat (nc) is required"
    exit 1
}

command -v tcpdump >/dev/null 2>&1 || { 
    echo "Error: tcpdump is required"
    exit 1
}

command -v python3 >/dev/null 2>&1 || { 
    echo "Error: python3 is required"
    exit 1
}

# Check Python script
if [ ! -f "recover_audio_streaming.py" ]; then
    echo "Error: recover_audio_streaming.py not found"
    exit 1
}

echo "=== Starting Receiver Service ==="
echo "Starting... (Press Ctrl+C to stop)"

# Record startup
echo "$(date): Starting RTP receiver service" >> $LOG_FILE

# Capture exit signals
trap 'echo; echo "$(date): Safely stopping RTP receiver service" >> $LOG_FILE; echo "Stopped safely"; exit 0' SIGINT SIGTERM

# Build whitelist parameters
WHITELIST_ARGS=""
if [ -n "$WHITELIST_IPS" ]; then
    WHITELIST_ARGS="--use-whitelist --whitelist $WHITELIST_IPS"
fi

# Start receiver service with tcpdump preprocessing
echo "Command: nc -u -l $LISTEN_PORT | tcpdump -r - -w - | python3 recover_audio_streaming.py /dev/stdin $OUTPUT_DIR $WHITELIST_ARGS"

# Run the command
nc -u -l $LISTEN_PORT | tcpdump -r - -w - 2>>$LOG_FILE | \
    python3 recover_audio_streaming.py /dev/stdin $OUTPUT_DIR $WHITELIST_ARGS

# If we reach here, the service has stopped
echo "$(date): RTP receiver service stopped" >> $LOG_FILE
