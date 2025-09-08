#!/bin/bash

# Configuration
AI_SERVER_IP="${AI_SERVER_IP:-100.120.241.10}"
AI_PORT="${AI_PORT:-8900}"
LOG_FILE="/var/log/persistent_sender.log"
BUFFER_SIZE=16384

# Create log directory
mkdir -p $(dirname $LOG_FILE)

echo "Starting persistent sender to $AI_SERVER_IP:$AI_PORT"
echo "$(date): Starting persistent sender" > $LOG_FILE

# Run continuously, automatically restart after errors
while true; do
    echo "$(date): Starting tcpdump and UDP forwarding" >> $LOG_FILE
    
    # Use UDP mode (-u) to avoid connection refusal issues
    # UDP is connectionless so it will send packets regardless of receiver state
    tcpdump -i any -w - -U -B $BUFFER_SIZE \
        udp and \(portrange 10000-20000 or port 5060\) 2>>$LOG_FILE | \
    nc -u $AI_SERVER_IP $AI_PORT 2>>$LOG_FILE
    
    # If we reach here, something broke the pipe
    EXIT_CODE=$?
    echo "$(date): Connection broken, exit code: $EXIT_CODE, reconnecting in 5 seconds..." >> $LOG_FILE
    sleep 5
done
