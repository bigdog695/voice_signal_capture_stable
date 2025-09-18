#!/bin/bash
set -o pipefail
LOG_FILE="/var/log/tcpdump_socat.log"
restart_interval=0.1
touch $LOG_FILE
chmod 666 $LOG_FILE

while true; do
  echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Starting new connection..." >> $LOG_FILE
  
  # Start tcpdump and socat, capture their exit status
  (tcpdump -i any -w - -U -B 65536 'udp and (portrange 10000-20000 or port 5060) and host 192.168.0.201' 2>tcpdump.err || echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): tcpdump exited with code: $?" >> $LOG_FILE) | \
  (socat -d -d -ly - TCP:100.120.241.10:8900,keepalive,keepidle=30,keepintvl=5,keepcnt=10 \
     2> >(stdbuf -oL -eL tee socat.err | grep -aE 'socat\[[0-9]+\]|read *(\(.*\)= 0| -> 0)|is at EOF|shutdown\(|close\(|waitpid|child|exit' >> socat.ctrl.log) \
   || echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): socat exited with code: $?" >> $LOG_FILE)
  
  # Get the exit status of the pipe
  TCPDUMP_EXIT=${PIPESTATUS[0]}
  SOCAT_EXIT=${PIPESTATUS[1]}
  
  # Log detailed error information
  echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Connection closed" >> $LOG_FILE
  echo "  tcpdump exit code: $TCPDUMP_EXIT" >> $LOG_FILE
  echo "  socat exit code: $SOCAT_EXIT" >> $LOG_FILE
  
  # Log error content
  if [ -s tcpdump.err ]; then
    echo "  tcpdump error log:" >> $LOG_FILE
    tail -5 tcpdump.err >> $LOG_FILE
  fi
  
  if [ -s socat.err ]; then
    echo "  socat error log:" >> $LOG_FILE
    tail -5 socat.err >> $LOG_FILE
  fi
  
  if [ -s socat.ctrl.log ]; then
    echo "  socat control log:" >> $LOG_FILE
    tail -20 socat.ctrl.log >> $LOG_FILE
  fi
  
  # Check for network issues
  if ping -c 1 -W 1 100.120.241.10 &>/dev/null; then
    echo "  Network connection: OK" >> $LOG_FILE
  else
    echo "  Network connection: FAILED" >> $LOG_FILE
  fi
  
  # Wait briefly before reconnecting
  echo "$(date +%Y-%m-%d\ %H:%M:%S.%3N): Reconnecting in $restart_interval second..." >> $LOG_FILE
  sleep $restart_interval
  exit
done