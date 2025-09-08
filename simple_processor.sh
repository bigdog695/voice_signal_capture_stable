#!/bin/bash

# Configuration
LISTEN_PORT=8901  # Different port from keepalive
OUTPUT_DIR="${OUTPUT_DIR:-extracted_audio}"
WHITELIST_IPS="${WHITELIST_IPS:-}" # Space-separated list of IPs
USE_WHITELIST="${USE_WHITELIST:-false}"

# Create output directory
mkdir -p "$OUTPUT_DIR"

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

# Start processor on a different port
nc -u -l $LISTEN_PORT | tcpdump -r - -w - | python3 recover_audio_streaming.py $PYTHON_ARGS
