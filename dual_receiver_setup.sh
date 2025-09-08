#!/bin/bash

# Dual Receiver Setup for RTP Traffic
# This script sets up two receivers:
# 1. A "keepalive" receiver that maintains a stable connection but discards data
# 2. A "processor" receiver that actually processes the audio data

# Configuration
LISTEN_PORT=8900
OUTPUT_DIR="extracted_audio"
LOG_DIR="/var/log"
WHITELIST_IPS="${WHITELIST_IPS:-}" # Space-separated list of IPs, e.g., "192.168.10.22 192.168.5.21"
USE_WHITELIST="${USE_WHITELIST:-false}" # Set to 'true' to enable whitelist mode

# Create log directories
mkdir -p "$LOG_DIR"
mkdir -p "$OUTPUT_DIR"

# Log files
KEEPALIVE_LOG="$LOG_DIR/rtp_keepalive.log"
PROCESSOR_LOG="$LOG_DIR/rtp_processor.log"

echo "=== Starting Dual Receiver Setup ==="
echo "Listen port: $LISTEN_PORT"
echo "Output directory: $OUTPUT_DIR"
echo "Whitelist mode: $USE_WHITELIST"
if [ "$USE_WHITELIST" = "true" ]; then
    echo "Whitelisted IPs: $WHITELIST_IPS"
fi
echo

# Start the keepalive receiver in background (discard data with /dev/null)
echo "Starting keepalive receiver..."
(nc -u -l "$LISTEN_PORT" > /dev/null 2>"$KEEPALIVE_LOG" &)
KEEPALIVE_PID=$!
echo "Keepalive receiver started with PID: $KEEPALIVE_PID"

# Wait a moment to ensure the keepalive receiver is ready
sleep 2

# Construct Python script arguments
PYTHON_ARGS="/dev/stdin $OUTPUT_DIR"
if [ "$USE_WHITELIST" = "true" ]; then
    PYTHON_ARGS+=" --use-whitelist"
    if [ -n "$WHITELIST_IPS" ]; then
        for ip in $WHITELIST_IPS; do
            PYTHON_ARGS+=" --whitelist $ip"
        done
    fi
fi

# Start the processor receiver
echo "Starting processor receiver..."
echo "$(date): Starting RTP processor" > "$PROCESSOR_LOG"
echo "Listening port: $LISTEN_PORT" >> "$PROCESSOR_LOG"
echo "Output directory: $OUTPUT_DIR" >> "$PROCESSOR_LOG"
echo "Python arguments: $PYTHON_ARGS" >> "$PROCESSOR_LOG"

# Use socat to duplicate the UDP stream to a second port for processing
# The second port is dynamically assigned
PROCESS_PORT=$((LISTEN_PORT + 1))
echo "Using processing port: $PROCESS_PORT"

# Start socat to duplicate traffic from the main port to the processing port
socat -u UDP-RECV:$LISTEN_PORT UDP-SENDTO:127.0.0.1:$PROCESS_PORT &
SOCAT_PID=$!
echo "Socat started with PID: $SOCAT_PID"

# Start the processor on the second port
nc -u -l $PROCESS_PORT 2>>"$PROCESSOR_LOG" | \
    tcpdump -r - -w - 2>>"$PROCESSOR_LOG" | \
    python3 recover_audio_streaming.py $PYTHON_ARGS 2>>"$PROCESSOR_LOG"

# If the processor exits, clean up
echo "Processor exited, cleaning up..."
kill $SOCAT_PID $KEEPALIVE_PID 2>/dev/null
echo "Done."
