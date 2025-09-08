#!/bin/bash

# Auto-restarting RTP Traffic Sender
# This script captures RTP/SIP traffic and forwards it to an AI server
# It automatically restarts if the connection breaks

# Configuration
AI_SERVER_IP="${AI_SERVER_IP:-100.120.241.10}"
AI_PORT="${AI_PORT:-8900}"
LOG_FILE="./logs/sender.log"
BUFFER_SIZE=16384

# Create log directory
mkdir -p $(dirname "$LOG_FILE")

# Display configuration
echo "=== Auto-restarting RTP Traffic Sender ==="
echo "Target server: $AI_SERVER_IP:$AI_PORT"
echo "Buffer size: $BUFFER_SIZE KB"
echo "Log file: $LOG_FILE"
echo

# Record startup
echo "$(date): Starting auto-restarting sender" | tee -a "$LOG_FILE"

# Capture exit signals
trap 'echo "$(date): Received stop signal, exiting..." | tee -a "$LOG_FILE"; exit 0' SIGINT SIGTERM

# Run continuously, automatically restart after errors
while true; do
    echo "$(date): Starting tcpdump and socat" | tee -a "$LOG_FILE"
    
    # Use tcpdump to capture packets and socat to forward them
    # - tcpdump captures RTP/SIP traffic and outputs to stdout
    # - socat forwards the stream to the AI server using UDP with broadcast option
    (tcpdump -i any -w - -U -B "$BUFFER_SIZE" \
        'udp and (portrange 10000-20000 or port 5060)' 2>>"$LOG_FILE" || \
        echo "$(date): tcpdump exited with code: $?" | tee -a "$LOG_FILE") | \
    (socat - "UDP:$AI_SERVER_IP:$AI_PORT,broadcast" 2>>"$LOG_FILE" || \
        echo "$(date): socat exited with code: $?" | tee -a "$LOG_FILE")
    
    # If we reach here, the pipe has been broken
    echo "$(date): Connection broken, reconnecting in 5 seconds..." | tee -a "$LOG_FILE"
    sleep 5
done
