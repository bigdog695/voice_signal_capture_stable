import socket
import struct
import subprocess
import logging
import time
import fcntl
import array
import io
import binascii

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

UDP_PORT = 8900
BUFFER_SIZE = 65535
RECVBUF_SIZE = 4 * 1024 * 1024  # 4MB
LOG_INTERVAL = 30  # seconds
MAX_PACKET_SIZE = 65535  # Maximum reasonable packet size

# Start recover_audio_streaming.py subprocess
proc = subprocess.Popen(
    [
        "python3", "recover_audio_streaming.py", "/dev/stdin", "extracted_audio", "--zmq", "--zmq-endpoint", "tcp://127.0.0.1:5555", "--chunk-seconds", "2"
    ],
    stdin=subprocess.PIPE
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECVBUF_SIZE)
sock.bind(("0.0.0.0", UDP_PORT))
logger.info(f"Listening UDP on port {UDP_PORT}, receive buffer set to {RECVBUF_SIZE} bytes")

buffer = bytearray()
processed_packets = 0
corrupted_packets = 0
skipped_bytes = 0
pcap_header_written = False
last_log = time.time()

# Standard pcap file header (24 bytes, Ethernet type)
PCAP_HEADER = struct.pack('IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, MAX_PACKET_SIZE, 1)

# Write pcap file header
def write_pcap_header():
    proc.stdin.write(PCAP_HEADER)
    proc.stdin.flush()
    logger.info("Wrote pcap file header")

# Write pcap file header at start
write_pcap_header()
pcap_header_written = True

def log_udp_backlog(sock):
    try:
        SIOCINQ = 0x541B
        buf = array.array('i', [0])
        fcntl.ioctl(sock, SIOCINQ, buf, True)
        backlog = buf[0]
        logger.info(f"Current UDP receive buffer backlog: {backlog} bytes")
    except Exception as e:
        logger.warning(f"Could not get UDP buffer backlog: {e}")

def is_valid_packet_header(header_bytes):
    """Check if the 16-byte header looks like a valid pcap packet header"""
    if len(header_bytes) != 16:
        return False
    
    try:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', header_bytes)
        
        # tcpdump typically uses small packet sizes (usually < 2000 bytes for RTP)
        # Being more strict with validation to avoid false positives
        return (
            0 <= ts_sec <= int(time.time()) + 86400 and  # Reasonable timestamp (now + 1 day max)
            0 <= ts_usec <= 999999 and                   # Valid microseconds
            0 < incl_len <= 2000 and                     # Typical RTP packet size (<2KB)
            0 < orig_len <= 2000 and                     # Typical RTP packet size (<2KB)
            incl_len <= orig_len                         # Captured size <= original size
        )
    except:
        return False

def find_next_packet_header(data, start_pos=0):
    """Try to find the next valid packet header in the data stream"""
    # Look for potential pcap packet headers
    for i in range(start_pos, len(data) - 16, 4):  # Try 4-byte aligned positions first
        if is_valid_packet_header(data[i:i+16]):
            return i
    
    # If not found, try every position (slower but more thorough)
    for i in range(start_pos, len(data) - 16):
        if is_valid_packet_header(data[i:i+16]):
            return i
    
    return -1

def debug_buffer(buffer, max_bytes=64):
    """Return a debug representation of the buffer"""
    if len(buffer) == 0:
        return "empty"
    hex_repr = binascii.hexlify(buffer[:min(max_bytes, len(buffer))]).decode()
    if len(buffer) > max_bytes:
        hex_repr += f"... ({len(buffer)} bytes total)"
    return hex_repr

# Main processing loop
while True:
    try:
        # Receive UDP data
        data, _ = sock.recvfrom(BUFFER_SIZE)
        buffer.extend(data)
        
        # Process as many complete packets as possible
        packets_in_this_batch = 0
        while len(buffer) >= 16:  # Minimum size for packet header
            try:
                # Try to parse packet header
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', buffer[:16])
                
                # Sanity check packet size with stricter limits for RTP
                if not (0 < incl_len <= 2000 and 0 < orig_len <= 2000 and incl_len <= orig_len):
                    raise ValueError(f"Invalid packet sizes: incl_len={incl_len}, orig_len={orig_len}")
                
                # Check if we have the complete packet
                if len(buffer) < 16 + incl_len:
                    break  # Wait for more data
                
                # We have a complete packet - write it out
                packet = buffer[:16 + incl_len]
                proc.stdin.write(packet)
                proc.stdin.flush()
                
                # Remove processed packet from buffer
                buffer = buffer[16 + incl_len:]
                processed_packets += 1
                packets_in_this_batch += 1
                
            except Exception as e:
                # Corrupted packet - try to resync
                corrupted_packets += 1
                
                # Debug output for first few corrupted packets
                if corrupted_packets < 10:
                    logger.warning(f"Corrupted packet: {e}. Buffer starts with: {debug_buffer(buffer)}")
                
                # Find next potential packet header
                next_pos = find_next_packet_header(buffer, 1)
                if next_pos > 0:
                    skipped_bytes += next_pos
                    if corrupted_packets < 100:  # Limit excessive logging
                        logger.warning(f"Resyncing, skipped {next_pos} bytes to next potential packet header")
                    buffer = buffer[next_pos:]
                else:
                    # If buffer is too large and no valid header found, discard half of it
                    if len(buffer) > 10000:
                        discard_size = len(buffer) // 2
                        buffer = buffer[discard_size:]
                        skipped_bytes += discard_size
                        logger.warning(f"No valid packet header found in large buffer, discarded {discard_size} bytes")
                    else:
                        # No valid header found, skip one byte and try again later
                        buffer = buffer[1:]
                        skipped_bytes += 1
        
        # Log when we successfully process packets
        if packets_in_this_batch > 0:
            logger.debug(f"Processed {packets_in_this_batch} packets in this batch")
        
        # Periodic logging
        now = time.time()
        if now - last_log > LOG_INTERVAL:
            logger.info(f"Processed {processed_packets} pcap packets, skipped {corrupted_packets} corrupted packets, {skipped_bytes} bytes skipped")
            log_udp_backlog(sock)
            last_log = now
            
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, exiting...")
        break
    except Exception as e:
        logger.error(f"Main loop exception: {e}")
        time.sleep(1)
        continue

sock.close()
proc.stdin.close()
proc.wait()