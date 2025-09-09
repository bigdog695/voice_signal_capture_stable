#!/usr/bin/env python3

"""
Direct UDP Receiver for RTP Processing
This script directly receives UDP packets and processes them without using tcpdump
It's designed to be extremely fault-tolerant, handling corrupted packets gracefully
"""

import socket
import sys
import os
import time
import logging
import argparse
import subprocess
import signal
import struct
from io import BytesIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/direct_receiver.log")
    ]
)
logger = logging.getLogger(__name__)

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

class UdpReceiver:
    def __init__(self, port, output_dir, use_whitelist=False, whitelist_ips=None):
        self.port = port
        self.output_dir = output_dir
        self.use_whitelist = use_whitelist
        self.whitelist_ips = whitelist_ips or []
        self.buffer_size = 65535  # Max UDP packet size
        self.sock = None
        self.pcap_process = None
        self.running = False
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Prepare command arguments for the streaming processor
        self.cmd_args = [
            "python3", "recover_audio_streaming.py", 
            "/dev/stdin", output_dir
        ]
        
        if use_whitelist:
            self.cmd_args.append("--use-whitelist")
            for ip in self.whitelist_ips:
                self.cmd_args.extend(["--whitelist", ip])
        
        logger.info(f"Initialized UDP receiver on port {port}")
        logger.info(f"Output directory: {output_dir}")
        logger.info(f"Whitelist mode: {use_whitelist}")
        if use_whitelist:
            logger.info(f"Whitelisted IPs: {whitelist_ips}")
    
    def start(self):
        """Start the UDP receiver and processor"""
        self.running = True
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            # Create UDP socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('0.0.0.0', self.port))
            
            # Start the processor subprocess
            self.start_processor()
            
            logger.info(f"Listening for UDP packets on port {self.port}")
            
            # Create a simple pcap header for the processor
            self.write_pcap_header()
            
            # Main receive loop
            while self.running:
                try:
                    # Receive data with timeout to allow checking running flag
                    self.sock.settimeout(1.0)
                    data, addr = self.sock.recvfrom(self.buffer_size)
                    
                    # Write packet to processor
                    self.write_packet(data)
                    
                except socket.timeout:
                    # This is expected, just continue
                    continue
                except Exception as e:
                    logger.error(f"Error receiving data: {e}")
                    # Continue running despite errors
                    time.sleep(1)
        
        except Exception as e:
            logger.error(f"Fatal error in receiver: {e}")
        
        finally:
            self.cleanup()
    
    def start_processor(self):
        """Start the audio processing subprocess"""
        try:
            logger.info(f"Starting processor: {' '.join(self.cmd_args)}")
            self.pcap_process = subprocess.Popen(
                self.cmd_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0  # Unbuffered
            )
        except Exception as e:
            logger.error(f"Failed to start processor: {e}")
            self.running = False
    
    def write_pcap_header(self):
        """Write a standard pcap file header to the processor"""
        if not self.pcap_process:
            return
            
        try:
            # Standard libpcap file header
            # Magic number, version, timezone, accuracy, snaplen, network type (1 for Ethernet)
            header = struct.pack('IHHiIII', 
                0xa1b2c3d4,  # Magic number
                2, 4,         # Version
                0, 0,         # Timezone, accuracy
                65535,        # Snaplen
                1             # Network type (1 for Ethernet)
            )
            
            self.pcap_process.stdin.write(header)
            self.pcap_process.stdin.flush()
            
        except Exception as e:
            logger.error(f"Error writing pcap header: {e}")
            self.restart_processor()
    
    def write_packet(self, data):
        """Write a packet to the processor with proper pcap encapsulation"""
        if not self.pcap_process:
            return
            
        try:
            # Current time
            now = time.time()
            seconds = int(now)
            microseconds = int((now - seconds) * 1000000)
            
            # Packet header (timestamp seconds, microseconds, captured length, actual length)
            packet_header = struct.pack('IIII', 
                seconds, microseconds, 
                len(data), len(data)
            )
            
            # Create a fake Ethernet header (14 bytes)
            # Destination MAC, Source MAC, EtherType (0x0800 for IPv4)
            eth_header = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00'
            
            # Write packet header and data
            self.pcap_process.stdin.write(packet_header)
            self.pcap_process.stdin.write(eth_header)
            self.pcap_process.stdin.write(data)
            self.pcap_process.stdin.flush()
            
        except BrokenPipeError:
            logger.error("Broken pipe to processor")
            self.restart_processor()
        except Exception as e:
            logger.error(f"Error writing packet: {e}")
            # Continue despite errors
    
    def restart_processor(self):
        """Restart the processing subprocess if it fails"""
        logger.info("Restarting processor...")
        
        if self.pcap_process:
            try:
                self.pcap_process.terminate()
            except:
                pass
                
            try:
                self.pcap_process.wait(timeout=5)
            except:
                try:
                    self.pcap_process.kill()
                except:
                    pass
        
        self.start_processor()
        self.write_pcap_header()
    
    def signal_handler(self, sig, frame):
        """Handle termination signals"""
        logger.info(f"Received signal {sig}, shutting down...")
        self.running = False
    
    def cleanup(self):
        """Clean up resources"""
        logger.info("Cleaning up resources...")
        
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        
        if self.pcap_process:
            try:
                self.pcap_process.stdin.close()
                self.pcap_process.terminate()
                self.pcap_process.wait(timeout=5)
            except:
                try:
                    self.pcap_process.kill()
                except:
                    pass

def main():
    parser = argparse.ArgumentParser(description="Direct UDP Receiver for RTP Processing")
    parser.add_argument("--port", type=int, default=8900, help="UDP port to listen on")
    parser.add_argument("--output-dir", default="extracted_audio", help="Output directory for audio files")
    parser.add_argument("--use-whitelist", action="store_true", help="Enable IP whitelist mode")
    parser.add_argument("--whitelist", nargs="+", help="List of IPs to whitelist")
    
    args = parser.parse_args()
    
    receiver = UdpReceiver(
        port=args.port,
        output_dir=args.output_dir,
        use_whitelist=args.use_whitelist,
        whitelist_ips=args.whitelist
    )
    
    try:
        receiver.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user, shutting down...")
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        
    logger.info("Receiver shutdown complete")

if __name__ == "__main__":
    main()
