#!/bin/bash
set -o pipefail
LOG_FILE="./log/pcap_sender.log"
RESTART_INTERVAL=0.1

# Ensure log directory exists
mkdir -p $(dirname $LOG_FILE)
touch $LOG_FILE
chmod 666 $LOG_FILE

# Cleanup function
cleanup() {
  echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Service stopping, cleaning up resources..." >> $LOG_FILE
  
  # Find and kill any running tcpdump or socat processes started by this script
  CHILD_PIDS=$(ps -o pid= --ppid $$)
  if [ -n "$CHILD_PIDS" ]; then
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Terminating child processes: $CHILD_PIDS" >> $LOG_FILE
    kill $CHILD_PIDS 2>/dev/null
  fi
  
  echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Service stopped" >> $LOG_FILE
  exit 0
}

# Handle SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM EXIT

# Main loop
echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting sender service" >> $LOG_FILE
while true; do
  echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting new connection..." >> $LOG_FILE
  
  # Start tcpdump and socat, capture exit status
  (tcpdump -i any -w - -U -B 65536 'udp and portrange 10000-20000 and host 192.168.0.201' 2>tcpdump.err || \
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): tcpdump exited with code: $?" >> $LOG_FILE) | \
  (socat -d - TCP:100.120.241.10:8900,keepalive,keepidle=30,keepintvl=5,keepcnt=10 2>socat.err || \
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): socat exited with code: $?" >> $LOG_FILE)
  
  # Get pipe exit status
  TCPDUMP_EXIT=${PIPESTATUS[0]}
  SOCAT_EXIT=${PIPESTATUS[1]}
  
  # Log connection closure information
  echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Connection closed" >> $LOG_FILE
  echo "  tcpdump exit code: $TCPDUMP_EXIT" >> $LOG_FILE
  echo "  socat exit code: $SOCAT_EXIT" >> $LOG_FILE
  
  # Log error content
  if [ -s tcpdump.err ]; then
    echo "  tcpdump errors:" >> $LOG_FILE
    tail -3 tcpdump.err >> $LOG_FILE
  fi
  
  if [ -s socat.err ]; then
    echo "  socat errors:" >> $LOG_FILE
    tail -3 socat.err >> $LOG_FILE
  fi
  
  # Check network connection
  if ping -c 1 -W 1 100.120.241.10 &>/dev/null; then
    echo "  Network connection: OK" >> $LOG_FILE
  else
    echo "  Network connection: FAILED" >> $LOG_FILE
  fi
  
  # If exit was due to SIGINT or SIGTERM, break the loop
  if [ $SOCAT_EXIT -eq 130 ] || [ $SOCAT_EXIT -eq 143 ] || [ $TCPDUMP_EXIT -eq 130 ] || [ $TCPDUMP_EXIT -eq 143 ]; then
    echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Received termination signal, stopping service" >> $LOG_FILE
    break
  fi
  
  # Wait briefly before reconnecting
  echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Reconnecting in ${RESTART_INTERVAL} seconds..." >> $LOG_FILE
  sleep $RESTART_INTERVAL
done