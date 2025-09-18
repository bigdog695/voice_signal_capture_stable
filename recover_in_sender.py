#!/usr/bin/env python3

import subprocess
import struct
import audioop
import logging
import time
import socket
import json
from pathlib import Path
from collections import defaultdict
import dpkt
import zmq
import threading
import os

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ProcessMonitor:
    """Monitor tcpdump process and restart it if it crashes"""
    
    def __init__(self, recovery_instance):
        self.recovery = recovery_instance
        self.tcpdump_process = None
        self.monitor_thread = None
        self.running = False
        self.process_restarted = False # Flag to indicate if the process was restarted
        
    def start_monitoring(self, process):
        """Start monitoring the tcpdump process"""
        self.tcpdump_process = process
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_process, daemon=True)
        self.monitor_thread.start()
        
    def _monitor_process(self):
        """Monitor the tcpdump process and restart if it crashes"""
        while self.running:
            if self.tcpdump_process and self.tcpdump_process.poll() is not None:
                # Process has exited
                exit_code = self.tcpdump_process.poll()
                logger.warning(f"tcpdump process (PID: {self.tcpdump_process.pid}) exited with code {exit_code}, restarting...")
                
                # Set flag to indicate process restart
                self.process_restarted = True
                
                # Restart tcpdump
                self._restart_tcpdump()
                
            time.sleep(1)  # Check every second
            
    def _restart_tcpdump(self):
        """Restart the tcpdump process"""
        # Clean up old process
        if self.tcpdump_process:
            try:
                self.tcpdump_process.terminate()
                self.tcpdump_process.wait(timeout=5)
            except:
                pass
        
        # Start new tcpdump process
        cmd = [
            'voice_capture', '-i', 'any', '-w', '-', '-U', '-B', '65536',
            'udp and portrange 10000-20000 and host 192.168.0.201'
        ]
        
        new_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Restarted tcpdump process with PID: {new_process.pid}")
        
        # Update the process reference
        self.tcpdump_process = new_process
        
        # Notify the main processing loop about the new process
        self.recovery._update_tcpdump_process(new_process)
        
        # Clear the flag after successful restart
        self.process_restarted = False
        
    def stop(self):
        """Stop monitoring and clean up"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        if self.tcpdump_process:
            try:
                self.tcpdump_process.terminate()
                self.tcpdump_process.wait(timeout=5)
            except:
                pass

class SenderAudioRecovery:
    def __init__(self, zmq_endpoint="tcp://100.120.241.10:5556", chunk_seconds=2.0):
        self.hotline_server_ip = "192.168.0.201"
        self.blacklisted_ips = {"192.168.0.118", "192.168.0.119", "192.168.0.121"}
        
        # Audio processing settings
        self.chunk_seconds = float(chunk_seconds)
        self.sample_rate = 8000
        self.sample_width_bytes = 2  # s16le
        self.channels = 1
        self.chunk_bytes = int(self.sample_rate * self.sample_width_bytes * self.chunk_seconds)
        
        # ZMQ setup
        self.zmq_ctx = zmq.Context()
        self.zmq_sock = self.zmq_ctx.socket(zmq.PUSH)
        self.zmq_sock.connect(zmq_endpoint)
        logger.info(f"Connected to ZMQ endpoint: {zmq_endpoint}")
        
        # Session management
        self.active_sessions = {}  # session_key -> Session object
        self.stream_to_session = {}  # stream_id -> session_key mapping
        self.session_counter = 1
        
        # Process monitor
        self.process_monitor = ProcessMonitor(self)
        
        logger.info(f"Sender audio recovery initialized - chunk: {self.chunk_seconds}s, bytes: {self.chunk_bytes}")

    def is_ip_blacklisted(self, ip):
        """Check if IP is blacklisted"""
        return ip in self.blacklisted_ips

    def should_process_ip(self, src_ip, dst_ip):
        """Determine if this IP pair should be processed"""
        # Check blacklist first
        if self.is_ip_blacklisted(src_ip) or self.is_ip_blacklisted(dst_ip):
            return False
        return True

    def get_stream_id(self, ssrc, src_ip, src_port, dst_ip, dst_port):
        """Generate unique RTP stream identifier (5-tuple)"""
        try:
            # Ensure ssrc is integer
            if isinstance(ssrc, str):
                if ssrc.startswith('0x'):
                    ssrc = int(ssrc, 16)
                else:
                    try:
                        ssrc = int(ssrc, 16)
                    except ValueError:
                        ssrc = int(ssrc)
            
            # Format SSRC as 8-digit hex
            return f"{ssrc & 0xFFFFFFFF:08x}_{src_ip}_{src_port}_{dst_ip}_{dst_port}"
        except (ValueError, TypeError) as e:
            logger.error(f"Error generating stream_id for SSRC {ssrc}: {e}")
            clean_ssrc = str(ssrc).split('_')[0] if '_' in str(ssrc) else str(ssrc)
            return f"{clean_ssrc}_{src_ip}_{src_port}_{dst_ip}_{dst_port}"

    def parse_rtp_packet(self, payload_bytes):
        """Parse RTP packet from raw bytes"""
        try:
            if len(payload_bytes) < 12:
                return None
                
            byte0 = payload_bytes[0]
            version = (byte0 >> 6) & 0x3
            padding = (byte0 >> 5) & 0x1
            extension = (byte0 >> 4) & 0x1
            cc = byte0 & 0xF
            
            byte1 = payload_bytes[1]
            marker = (byte1 >> 7) & 0x1
            payload_type = byte1 & 0x7F
            
            if version != 2 or payload_type not in [0, 8]:
                return None
                
            sequence = struct.unpack('!H', payload_bytes[2:4])[0]
            timestamp = struct.unpack('!I', payload_bytes[4:8])[0]
            ssrc = struct.unpack('!I', payload_bytes[8:12])[0]
            
            header_length = 12 + cc * 4
            if extension:
                if len(payload_bytes) < header_length + 4:
                    return None
                ext_length = struct.unpack('!H', payload_bytes[header_length + 2:header_length + 4])[0]
                header_length += 4 + ext_length * 4
            
            if len(payload_bytes) <= header_length:
                return None
                
            audio_data = payload_bytes[header_length:]
            if padding:
                padding_length = audio_data[-1] if audio_data else 0
                audio_data = audio_data[:-padding_length] if padding_length < len(audio_data) else b''
            
            codec = "PCMU" if payload_type == 0 else "PCMA"
            
            return {
                'ssrc': ssrc,
                'sequence': sequence,
                'timestamp': timestamp,
                'audio_data': audio_data,
                'codec': codec
            }
        except Exception as e:
            logger.debug(f"RTP parsing error: {e}")
            return None

    def parse_rtcp_packet(self, payload_bytes):
        """Parse RTCP packet, focus on BYE packets"""
        try:
            if len(payload_bytes) < 8:
                return None
            
            offset = 0
            bye_ssrcs = []
            
            # Parse compound RTCP packets
            while offset < len(payload_bytes):
                if offset + 4 > len(payload_bytes):
                    break
                    
                byte0 = payload_bytes[offset]
                version = (byte0 >> 6) & 0x3
                padding = (byte0 >> 5) & 0x1
                rc = byte0 & 0x1F
                
                packet_type = payload_bytes[offset + 1]
                length = struct.unpack('!H', payload_bytes[offset + 2:offset + 4])[0]
                packet_length = (length + 1) * 4
                
                if version != 2 or packet_length == 0:
                    break
                
                # Detect BYE packet (Packet Type 203)
                if packet_type == 203 and offset + 8 <= len(payload_bytes):
                    ssrc = struct.unpack('!I', payload_bytes[offset + 4:offset + 8])[0]
                    bye_ssrcs.append(ssrc)
                    logger.info(f"Detected RTCP BYE: SSRC {ssrc:08x}")
                
                offset += packet_length
                if offset >= len(payload_bytes):
                    break
            
            return bye_ssrcs if bye_ssrcs else None
            
        except Exception as e:
            logger.debug(f"RTCP parsing error: {e}")
            return None

    def create_or_update_session(self, ssrc, src_ip, dst_ip, src_port, dst_port, direction, codec):
        """Create or update session"""
        # Filter out self-call packets
        if src_ip == self.hotline_server_ip and dst_ip == self.hotline_server_ip:
            return None
        
        # Determine operator IP
        peer_ip = dst_ip if src_ip == self.hotline_server_ip else src_ip
        
        # Generate current stream unique identifier
        if isinstance(ssrc, str):
            try:
                if ssrc.startswith('0x'):
                    ssrc_int = int(ssrc, 16)
                else:
                    try:
                        ssrc_int = int(ssrc, 16)
                    except ValueError:
                        ssrc_int = int(ssrc)
                ssrc_hex = f"{ssrc_int & 0xFFFFFFFF:08x}"
            except (ValueError, TypeError):
                ssrc_hex = ssrc.split('_')[0] if '_' in ssrc else ssrc
        else:
            ssrc_hex = f"{ssrc & 0xFFFFFFFF:08x}"
            
        stream_id = f"{ssrc_hex}_{src_ip}_{src_port}_{dst_ip}_{dst_port}"
        
        # Check if this stream already has a session
        if stream_id in self.stream_to_session:
            session_key = self.stream_to_session[stream_id]
            session = self.active_sessions[session_key]
            return session
        
        # Look for possible paired session (bidirectional streams: IP and port swapped)
        matching_session = None
        
        for session_key, session in self.active_sessions.items():
            if session.peer_ip == peer_ip and session.can_pair_with_connection(src_ip, dst_ip, src_port, dst_port, direction):
                matching_session = session
                break
        
        if matching_session:
            # Found pairing, add to existing session
            matching_session.add_stream(stream_id, ssrc, direction, src_ip, dst_ip, src_port, dst_port, codec)
            self.stream_to_session[stream_id] = matching_session.session_key
            logger.info(f"Stream {stream_id} paired with session {matching_session.session_key}")
            return matching_session
        else:
            # Create new session
            session_key = f"{peer_ip.replace('.', '_')}_{self.session_counter}"
            self.session_counter += 1
            
            session = Session(session_key, peer_ip, publisher=self._publish_zmq, chunk_bytes=self.chunk_bytes)
            session.add_stream(stream_id, ssrc, direction, src_ip, dst_ip, src_port, dst_port, codec)
            
            self.active_sessions[session_key] = session
            self.stream_to_session[stream_id] = session_key
            
            logger.info(f"Created new session {session_key}: stream {stream_id} ({direction})")
            return session

    def finalize_session(self, session_key):
        """Finalize session and generate audio files"""
        if session_key not in self.active_sessions:
            return
            
        session = self.active_sessions[session_key]
        logger.info(f"Finalizing session {session_key}")
        
        # Send remaining unfilled chunk data
        session.flush_pending_chunks()
        
        # Clean up session
        for stream_id in session.get_all_stream_ids():
            if stream_id in self.stream_to_session:
                del self.stream_to_session[stream_id]
        
        del self.active_sessions[session_key]
        logger.info(f"Session {session_key} cleaned up")

    def _publish_zmq(self, peer_ip, source, pcm_bytes, start_ts, end_ts, is_finished):
        """Publish audio chunk to ZMQ"""
        if not self.zmq_sock or not pcm_bytes:
            return
        
        # Metadata in agreed structure
        meta = {
            'peer_ip': peer_ip,
            'source': source,
            'start_ts': float(start_ts) if start_ts is not None else None,
            'end_ts': float(end_ts) if end_ts is not None else None,
            'IsFinished': bool(is_finished)
        }
        
        try:
            # Calculate current message size
            meta_bytes = json.dumps(meta, ensure_ascii=False).encode('utf-8')
            
            # Use non-blocking send, drop old data when queue is full
            self.zmq_sock.send_multipart([
                meta_bytes,
                pcm_bytes
            ], zmq.NOBLOCK)
            
            logger.debug(f"Published ZMQ chunk: {len(pcm_bytes)} bytes, source: {source}")
            
        except zmq.Again:
            # Queue is full, message dropped
            logger.warning(f"ZMQ queue full, message dropped: peer_ip={peer_ip}, source={source}, size={len(pcm_bytes)} bytes")
        except Exception as e:
            logger.error(f"ZMQ send failed: {e}")

    def process_pcap_streaming(self):
        """Process PCAP stream from tcpdump with robust process monitoring"""
        logger.info("Starting PCAP stream processing from tcpdump with robust process monitoring...")
        
        # Start tcpdump process
        cmd = [
            'voice_capture', '-i', 'any', '-w', '-', '-U', '-B', '65536',
            'udp and portrange 10000-20000 and host 192.168.0.201'
        ]
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Started tcpdump process with PID: {process.pid}")
        
        # Start process monitoring
        self.process_monitor.start_monitoring(process)
        
        try:
            processed_packets = 0
            last_activity_time = time.time()
            
            logger.info("Started continuous data stream monitoring...")
            
            # Continuously read packets with process restart handling
            while True:
                # Get current process from monitor
                current_process = self.process_monitor.tcpdump_process
                
                # Debug: log current process state
                logger.debug(f"Current process PID: {current_process.pid if current_process else 'None'}, status: {current_process.poll() if current_process else 'N/A'}")
                logger.debug(f"Process restart flag: {self.process_monitor.process_restarted}")
                
                # Create pcap reader from current process output
                try:
                    pcap_reader = dpkt.pcap.Reader(current_process.stdout)
                    logger.debug(f"Created pcap reader for process PID: {current_process.pid}")
                    
                    # Read packets from current process
                    while True:
                        try:
                            ts, buf = next(pcap_reader)
                            
                            # Parse Ethernet frame
                            try:
                                # Handle different datalink types
                                if pcap_reader.datalink() == dpkt.pcap.DLT_EN10MB:
                                    eth = dpkt.ethernet.Ethernet(buf)
                                    if not isinstance(eth.data, dpkt.ip.IP):
                                        continue
                                    ip = eth.data
                                elif pcap_reader.datalink() == dpkt.pcap.DLT_LINUX_SLL:
                                    sll = dpkt.sll.SLL(buf)
                                    if not isinstance(sll.data, dpkt.ip.IP):
                                        continue
                                    ip = sll.data
                                elif pcap_reader.datalink() == dpkt.pcap.DLT_RAW or pcap_reader.datalink() == 101:
                                    ip = dpkt.ip.IP(buf)
                                else:
                                    logger.warning(f"Unsupported datalink type: {pcap_reader.datalink()}")
                                    continue
                                
                                # Extract IP addresses
                                src_ip = socket.inet_ntoa(ip.src)
                                dst_ip = socket.inet_ntoa(ip.dst)
                                
                                # Filter packets not containing hotline server IP
                                if self.hotline_server_ip not in [src_ip, dst_ip]:
                                    continue
                                
                                # IP filtering (blacklist)
                                if not self.should_process_ip(src_ip, dst_ip):
                                    continue
                                
                                # Check if it's UDP
                                if not isinstance(ip.data, dpkt.udp.UDP):
                                    continue
                                
                                udp = ip.data
                                src_port = udp.sport
                                dst_port = udp.dport
                                payload_bytes = udp.data
                                
                                # Try to parse as RTP packet
                                rtp_info = self.parse_rtp_packet(payload_bytes)
                                if rtp_info:
                                    ssrc = rtp_info['ssrc']
                                    stream_id = self.get_stream_id(ssrc, src_ip, src_port, dst_ip, dst_port)
                                    
                                    # Filter out self-calls
                                    if src_ip == dst_ip == self.hotline_server_ip:
                                        continue
                                    
                                    # Create or update session
                                    direction = "citizen" if src_ip == self.hotline_server_ip else "hotline"
                                    session = self.create_or_update_session(ssrc, src_ip, dst_ip, 
                                                        src_port, dst_port, direction, rtp_info['codec'])
                                    
                                    # Add RTP packet to session
                                    if session:
                                        # Add pcap capture timestamp
                                        rtp_info['pcap_ts'] = ts
                                        session.add_rtp_packet(stream_id, rtp_info)
                                        
                                    processed_packets += 1
                                    last_activity_time = time.time()
                                    
                                    if processed_packets % 100 == 0:
                                        logger.debug(f"Processed {processed_packets} RTP packets")
                                
                                # Try to parse as RTCP packet
                                bye_ssrcs = self.parse_rtcp_packet(payload_bytes)
                                if bye_ssrcs:
                                    for bye_ssrc in bye_ssrcs:
                                        try:
                                            # Ensure bye_ssrc is integer
                                            if isinstance(bye_ssrc, str):
                                                bye_ssrc = int(bye_ssrc, 16) if bye_ssrc.startswith('0x') else int(bye_ssrc)
                                            
                                            # Find all streams containing this SSRC
                                            sessions_to_finalize = set()
                                            bye_ssrc_hex = f"{bye_ssrc:08x}"
                                            
                                            # Calculate corresponding RTP port (RTCP port - 1)
                                            rtp_src_port = src_port - 1 if src_port % 2 == 1 else src_port
                                            rtp_dst_port = dst_port - 1 if dst_port % 2 == 1 else dst_port
                                            
                                            # Use 5-tuple matching (SSRC + src_ip + RTP src_port + dst_ip + RTP dst_port)
                                            for stream_id, session_key in self.stream_to_session.items():
                                                # Check SSRC match
                                                if stream_id.startswith(f"{bye_ssrc_hex}_"):
                                                    # Check if other parts of 5-tuple match
                                                    stream_parts = stream_id.split('_')
                                                    if len(stream_parts) >= 5:
                                                        stream_src_ip = stream_parts[1]
                                                        stream_src_port = int(stream_parts[2])
                                                        stream_dst_ip = stream_parts[3]
                                                        stream_dst_port = int(stream_parts[4])
                                                        
                                                        # Check IP match and port match (consider RTCP port is RTP port + 1)
                                                        if (stream_src_ip == src_ip and stream_dst_ip == dst_ip and 
                                                            (stream_src_port == rtp_src_port) and 
                                                            (stream_dst_port == rtp_dst_port)):
                                                            sessions_to_finalize.add(session_key)
                                                            logger.info(f"RTCP BYE matched RTP stream: {stream_id}")
                                        
                                            # Finalize related sessions
                                            for session_key in sessions_to_finalize:
                                                logger.info(f"Received SSRC {bye_ssrc_hex} BYE signal, finalizing session {session_key}")
                                                self.finalize_session(session_key)
                                                
                                        except (ValueError, TypeError) as e:
                                            logger.error(f"Error processing RTCP BYE SSRC: {bye_ssrc}, error: {e}")
                                            continue
                                        
                            except Exception as e:
                                logger.error(f"Error processing packet: {e}")
                                continue
                            
                        except StopIteration:
                            # End of current stream, check if process was restarted
                            if self.process_monitor.process_restarted:
                                logger.info("Process was restarted, switching to new process...")
                                self.process_monitor.process_restarted = False
                                break  # Break inner loop to get new process
                            else:
                                # Normal end of stream, wait briefly
                                logger.info("Current data stream finished, waiting for new data...")
                                time.sleep(1)
                                
                        except KeyboardInterrupt:
                            logger.info("Received interrupt signal, stopping...")
                            break
                        except Exception as e:
                            logger.error(f"Error reading packet: {e}")
                            time.sleep(1)
                            
                except Exception as e:
                    logger.error(f"Error creating pcap reader: {e}")
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, stopping...")
        except Exception as e:
            logger.error(f"Error processing pcap file: {e}")
            raise
        finally:
            # Clean up
            self.process_monitor.stop()

    def _update_tcpdump_process(self, new_process):
        """Update the tcpdump process reference in the monitor"""
        if self.process_monitor.tcpdump_process and self.process_monitor.tcpdump_process.poll() is not None:
            logger.info(f"Tcpdump process (PID: {self.process_monitor.tcpdump_process.pid}) exited, restarting...")
            self.process_monitor.start_monitoring(new_process)
        else:
            logger.info(f"Tcpdump process (PID: {new_process.pid}) is already running.")


class Session:
    def __init__(self, session_key, peer_ip, *, publisher=None, chunk_bytes=8000):
        self.session_key = session_key
        self.peer_ip = peer_ip
        self.streams = {}  # stream_id -> {'ssrc', 'direction', 'packets', 'codec', 'connection_info'}
        self.last_activity = time.time()  # Record last activity time
        
        # ZMQ publishing related
        self.publisher = publisher  # callable(peer_ip, direction, pcm_bytes, start_ts, end_ts)
        self.chunk_bytes = int(chunk_bytes)
        # One segment buffer queue per direction: [{ 'ts': float, 'pcm': bytes }]
        self.direction_segments = {
            'citizen': [],
            'hotline': []
        }
        self.published_any = {
            'citizen': False,
            'hotline': False
        }
        
    def add_stream(self, stream_id, ssrc, direction, src_ip, dst_ip, src_port, dst_port, codec):
        """Add stream to session"""
        self.streams[stream_id] = {
            'ssrc': ssrc,
            'direction': direction,
            'packets': [],
            'codec': codec,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port
        }
    
    def can_pair_with_connection(self, src_ip, dst_ip, src_port, dst_port, direction):
        """Check if can pair with given connection (bidirectional streams: IP and port swapped)"""
        current_time = time.time()
        
        for stream_id, stream_info in self.streams.items():
            # Check if it's bidirectional connection (IP and port swapped, different direction)
            if (stream_info['src_ip'] == dst_ip and stream_info['dst_ip'] == src_ip and
                stream_info['src_port'] == dst_port and stream_info['dst_port'] == src_port and
                stream_info['direction'] != direction):
                
                # Check time window - only pair streams within last 30 seconds
                if 'last_packet_time' not in stream_info or (current_time - stream_info['last_packet_time']) < 30:
                    logger.debug(f"Found paired stream: {stream_id}, direction: {stream_info['direction']}")
                    return True
                else:
                    logger.debug(f"Stream {stream_id} exceeded time window ({current_time - stream_info['last_packet_time']:.2f}s), not pairing")
        return False
    
    def add_rtp_packet(self, stream_id, rtp_info):
        """Add RTP packet to specified stream"""
        if stream_id in self.streams:
            self.streams[stream_id]['packets'].append(rtp_info)
            self.streams[stream_id]['last_packet_time'] = time.time()  # Record last packet time
            self.last_activity = time.time()  # Update last activity time
            # Real-time chunking and publish to ZMQ (if enabled)
            if self.publisher:
                self._ingest_and_maybe_publish(self.streams[stream_id]['direction'], self.streams[stream_id]['codec'], rtp_info)

    def _ingest_and_maybe_publish(self, direction, codec, rtp_info):
        """Decode single RTP packet and add to direction segment queue, publish when chunk size is met"""
        audio_bytes = rtp_info.get('audio_data', b'')
        if not audio_bytes:
            return
        # G711 decode to s16le
        if codec == "PCMU":
            try:
                pcm = audioop.ulaw2lin(audio_bytes, 2)
            except Exception:
                pcm = b''
        elif codec == "PCMA":
            try:
                pcm = audioop.alaw2lin(audio_bytes, 2)
            except Exception:
                pcm = b''
        else:
            pcm = audio_bytes
        if not pcm:
            return
        # Add to segment queue
        seg_list = self.direction_segments.get(direction)
        if seg_list is None:
            return
        seg_list.append({'ts': rtp_info.get('pcap_ts', time.time()), 'pcm': pcm})
        # Try to publish as many complete chunks as possible
        self._drain_full_chunks(direction)

    def _drain_full_chunks(self, direction):
        seg_list = self.direction_segments.get(direction)
        if not seg_list:
            return
        total_bytes = sum(len(seg['pcm']) for seg in seg_list)
        while total_bytes >= self.chunk_bytes:
            # Assemble a chunk
            chunk_parts = []
            consumed = 0
            start_ts = seg_list[0]['ts']
            end_ts = start_ts
            # Pop segments from left to right
            while seg_list and consumed + len(seg_list[0]['pcm']) <= self.chunk_bytes:
                seg = seg_list.pop(0)
                chunk_parts.append(seg['pcm'])
                consumed += len(seg['pcm'])
                end_ts = seg['ts']
            if consumed < self.chunk_bytes and seg_list:
                # Need to cut part from next segment
                seg = seg_list[0]
                need = self.chunk_bytes - consumed
                take = seg['pcm'][:need]
                remain = seg['pcm'][need:]
                chunk_parts.append(take)
                consumed += len(take)
                end_ts = seg['ts']
                # Update remaining segment
                seg_list[0] = {'ts': seg['ts'], 'pcm': remain}
            # Publish
            chunk_pcm = b''.join(chunk_parts)
            self._publish_chunk(direction, chunk_pcm, start_ts, end_ts, is_finished=False)
            total_bytes -= self.chunk_bytes

    def _publish_chunk(self, direction, pcm_bytes, start_ts, end_ts, is_finished):
        if not self.publisher or not pcm_bytes:
            return
        # Direction mapping to required string
        source = 'citizen' if direction == 'citizen' else 'hot-line'
        self.publisher(self.peer_ip, source, pcm_bytes, start_ts, end_ts, is_finished)
        # Mark this direction has published data
        self.published_any[direction] = True

    def flush_pending_chunks(self):
        """At session end, publish remaining audio less than one chunk (if any)"""
        if not self.publisher:
            # No need to publish
            self.direction_segments['citizen'].clear()
            self.direction_segments['hotline'].clear()
            return
        for direction in ['citizen', 'hotline']:
            seg_list = self.direction_segments.get(direction, [])
            if seg_list:
                # Assemble all remaining segments
                start_ts = seg_list[0]['ts']
                end_ts = seg_list[-1]['ts']
                chunk_pcm = b''.join(seg['pcm'] for seg in seg_list)
                if chunk_pcm:
                    self._publish_chunk(direction, chunk_pcm, start_ts, end_ts, is_finished=True)
                seg_list.clear()
            else:
                # If exactly on chunk boundary, ensure end marker is sent
                if self.published_any.get(direction, False):
                    now_ts = time.time()
                    self._publish_chunk(direction, b'', now_ts, now_ts, is_finished=True)
    
    def get_all_stream_ids(self):
        """Get all stream IDs in session"""
        return list(self.streams.keys())


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Sender-side audio recovery from RTP stream')
    parser.add_argument('--zmq-endpoint', default='tcp://100.120.241.10:5556', help='ZMQ endpoint (default: tcp://100.120.241.10:5556)')
    parser.add_argument('--chunk-seconds', type=float, default=2.0, help='Audio chunk duration in seconds (default: 2.0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    recovery = SenderAudioRecovery(
        zmq_endpoint=args.zmq_endpoint,
        chunk_seconds=args.chunk_seconds
    )
    recovery.process_pcap_streaming()


if __name__ == "__main__":
    main()
