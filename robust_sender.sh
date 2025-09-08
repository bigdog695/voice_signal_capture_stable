#!/bin/bash

# Configuration
AI_SERVER_IP="${AI_SERVER_IP:-100.120.241.10}"
AI_PORT="${AI_PORT:-8900}"
LOG_FILE="/var/log/robust_sender.log"
BUFFER_SIZE=16384

# Create log directory
mkdir -p $(dirname $LOG_FILE)

echo "Starting robust UDP sender to $AI_SERVER_IP:$AI_PORT"
echo "$(date): Starting robust sender" > $LOG_FILE

# Run continuously, automatically restart after errors
while true; do
    echo "$(date): Starting tcpdump and socat forwarding" >> $LOG_FILE
    
    # Use socat with options to ignore errors:
    # - ignoreeof: Continue even if input closes
    # - forever: Retry indefinitely
    # - broadcast: Allow broadcast packets (also ignores some ICMP errors)
    # - ttl=10: Set Time-To-Live to prevent indefinite looping
    # - reuseaddr: Allow reuse of local addresses
    tcpdump -i any -w - -U -B $BUFFER_SIZE \
        'udp and (portrange 10000-20000 or port 5060)' 2>>$LOG_FILE | \
    socat -u - UDP-DATAGRAM:$AI_SERVER_IP:$AI_PORT,broadcast,forever,ignoreeof,reuseaddr,ttl=10 2>>$LOG_FILE
    
    # If we reach here, something broke the pipe
    EXIT_CODE=$?
    echo "$(date): Connection broken, exit code: $EXIT_CODE, reconnecting in 5 seconds..." >> $LOG_FILE
    sleep 5
done
