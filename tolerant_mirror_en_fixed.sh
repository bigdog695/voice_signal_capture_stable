#!/bin/bash

# Fault-tolerant RTP Traffic Mirroring Script
# This script captures RTP/SIP traffic and forwards it to an AI server
# It includes error handling for corrupt packets and automatic reconnection

# Configuration
AI_SERVER_IP="${AI_SERVER_IP:-100.120.241.10}"
AI_PORT="${AI_PORT:-8900}"
LOG_FILE="/var/log/tolerant_mirror.log"
MAX_SNAPLEN=65535  # Default snaplen value that works with most tcpdump versions
BUFFER_SIZE=16384  # Kernel buffer size for packet capture

# Create log directory
mkdir -p $(dirname $LOG_FILE)

# Display configuration
echo "=== Fault-tolerant RTP Traffic Mirroring ==="
echo "Target server: $AI_SERVER_IP:$AI_PORT"
echo "Max capture length: $MAX_SNAPLEN bytes"
echo "Log file: $LOG_FILE"
echo

# Capture exit signals
trap 'echo "$(date): Received stop signal, exiting..." >> $LOG_FILE; exit 0' SIGINT SIGTERM

# Record startup
echo "$(date): Starting fault-tolerant RTP traffic mirroring" > $LOG_FILE

# Run continuously, automatically restart after errors
while true; do
    echo "$(date): Starting tcpdump and nc" >> $LOG_FILE
    
    # Use direct pipe to connect tcpdump and nc, with fault-tolerant parameters
    # tcpdump parameters:
    # -K: Don't verify checksums, prevents errors with corrupt packets
    # -Q: Quiet mode, reduces error output
    # -V: Continue processing even with errors
    # -s $MAX_SNAPLEN: Use standard snaplen value
    tcpdump -i any -w - -U -B $BUFFER_SIZE -s $MAX_SNAPLEN \
        -K -Q \
        'udp and (portrange 10000-20000 or port 5060)' 2>>$LOG_FILE | \
    nc -u $AI_SERVER_IP $AI_PORT 2>>$LOG_FILE
    
    # If we reach here, the pipe has been broken
    EXIT_CODE=$?
    echo "$(date): Connection broken, exit code: $EXIT_CODE, reconnecting in 5 seconds..." >> $LOG_FILE
    sleep 5
done
