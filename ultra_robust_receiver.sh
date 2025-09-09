#!/bin/bash

# Ultra Robust UDP Receiver
# This script receives UDP traffic and processes it with extreme fault tolerance
# Even if tcpdump crashes on corrupted packets, the receiver continues running

# Configuration
LISTEN_PORT="${LISTEN_PORT:-8900}"
OUTPUT_DIR="${OUTPUT_DIR:-extracted_audio}"
LOG_FILE="./logs/ultra_robust_receiver.log"
WHITELIST_IPS="${WHITELIST_IPS:-}" # Space-separated list of IPs
USE_WHITELIST="${USE_WHITELIST:-false}"
CHUNK_DIR="./chunks"
CHUNK_SIZE=10485760  # 10MB per chunk file
MAX_CHUNKS=10        # Keep 10 most recent chunks
MAX_SNAPLEN=65535    # Smaller snaplen to avoid crashes

# Create directories
mkdir -p "$OUTPUT_DIR"
mkdir -p $(dirname "$LOG_FILE")
mkdir -p "$CHUNK_DIR"

# Log start
echo "$(date): Starting ultra robust UDP receiver on port $LISTEN_PORT" | tee -a "$LOG_FILE"
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

# Cleanup function
cleanup() {
    echo "$(date): Shutting down..." | tee -a "$LOG_FILE"
    kill $(jobs -p) 2>/dev/null
    exit 0
}

# Trap signals for cleanup
trap cleanup SIGINT SIGTERM

# Start the dedicated UDP receiver that never stops
echo "$(date): Starting dedicated UDP receiver on port $LISTEN_PORT" | tee -a "$LOG_FILE"
(
    # This process only receives UDP data and writes to rotating chunk files
    # It never stops, even if downstream processing fails
    COUNTER=0
    while true; do
        CHUNK_FILE="$CHUNK_DIR/chunk_$(printf "%04d" $COUNTER).pcap"
        echo "$(date): Writing to chunk file $CHUNK_FILE" >> "$LOG_FILE"
        
        # Use timeout to rotate files every few minutes
        timeout 300s nc -u -l "$LISTEN_PORT" > "$CHUNK_FILE" 2>>"$LOG_FILE" || true
        
        # Increment counter and wrap around if needed
        COUNTER=$(( (COUNTER + 1) % MAX_CHUNKS ))
        
        # No delay - start next listener immediately
    done
) &
RECEIVER_PID=$!

# Start the processor in a separate loop
echo "$(date): Starting chunk processor" | tee -a "$LOG_FILE"
(
    LAST_PROCESSED=""
    while true; do
        # Find the newest non-empty chunk file that isn't the currently active one
        NEWEST_CHUNK=$(find "$CHUNK_DIR" -type f -name "chunk_*.pcap" -not -empty | sort | tail -n 2 | head -n 1)
        
        # Process the chunk if it exists and isn't the last one we processed
        if [[ -n "$NEWEST_CHUNK" && "$NEWEST_CHUNK" != "$LAST_PROCESSED" ]]; then
            echo "$(date): Processing chunk file $NEWEST_CHUNK" >> "$LOG_FILE"
            
            # Create a copy to process so the original isn't modified
            PROCESS_COPY="$CHUNK_DIR/processing_$(basename "$NEWEST_CHUNK")"
            cp "$NEWEST_CHUNK" "$PROCESS_COPY"
            
            # Process with tcpdump - if it fails, log but continue
            (tcpdump -r "$PROCESS_COPY" -w - -s "$MAX_SNAPLEN" 2>>"$LOG_FILE" | \
             python3 recover_audio_streaming.py $PYTHON_ARGS 2>>"$LOG_FILE") || \
             echo "$(date): Processing of $PROCESS_COPY failed, continuing with next chunk" >> "$LOG_FILE"
            
            # Clean up the processing copy
            rm -f "$PROCESS_COPY"
            
            # Remember this chunk as processed
            LAST_PROCESSED="$NEWEST_CHUNK"
        fi
        
        # Brief pause before checking again
        sleep 5
    done
) &
PROCESSOR_PID=$!

# Wait for any process to exit (should never happen unless killed)
wait -n

# If we get here, something went very wrong
echo "$(date): A critical process exited unexpectedly, restarting entire receiver..." | tee -a "$LOG_FILE"

# Clean up
kill $RECEIVER_PID $PROCESSOR_PID 2>/dev/null || true

# Restart the script
exec "$0" "$@"
