#!/usr/bin/env python3

import subprocess
import struct
import audioop
import logging
from pathlib import Path
from collections import defaultdict
from pydub import AudioSegment

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class StreamingAudioRecovery:
    def __init__(self, pcap_file, output_dir="extracted_audio"):
        self.pcap_file = pcap_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.hotline_server_ip = "192.168.0.201"
        self.blacklisted_ips = {"192.168.0.118", "192.168.0.119", "192.168.0.121"}
        
        # 活跃会话管理
        self.active_sessions = {}  # session_key -> Session对象
        self.stream_to_session = {}  # stream_id -> session_key的映射
        
        self.session_counter = 1
    
    def is_ip_blacklisted(self, ip):
        """检查IP是否在黑名单中"""
        return ip in self.blacklisted_ips
    
    def get_stream_id(self, ssrc, src_ip, src_port, dst_ip, dst_port):
        """生成RTP流的唯一标识符（五元组）"""
        return f"{ssrc:08x}_{src_ip}_{src_port}_{dst_ip}_{dst_port}"

    def parse_rtp_packet(self, payload_hex):
        """解析RTP包"""
        try:
            payload_bytes = bytes.fromhex(payload_hex.replace(':', ''))
            
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
        except Exception:
            return None

    def parse_rtcp_packet(self, payload_hex):
        """解析RTCP包，重点检测BYE包"""
        try:
            payload_bytes = bytes.fromhex(payload_hex.replace(':', ''))
            if len(payload_bytes) < 8:
                return None
            
            offset = 0
            bye_ssrcs = []
            
            # 解析复合RTCP包
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
                
                # 检测BYE包 (Packet Type 203)
                if packet_type == 203 and offset + 8 <= len(payload_bytes):
                    ssrc = struct.unpack('!I', payload_bytes[offset + 4:offset + 8])[0]
                    bye_ssrcs.append(ssrc)
                    logger.debug(f"检测到RTCP BYE: SSRC {ssrc:08x}")
                
                offset += packet_length
                if offset >= len(payload_bytes):
                    break
            
            return bye_ssrcs if bye_ssrcs else None
            
        except Exception:
            return None

    def create_or_update_session(self, ssrc, src_ip, dst_ip, src_port, dst_port, direction, codec):
        """创建或更新会话"""
        # 过滤掉热线服务器自通话的包
        if src_ip == self.hotline_server_ip and dst_ip == self.hotline_server_ip:
            return None
        
        # 确定接线员IP
        peer_ip = dst_ip if src_ip == self.hotline_server_ip else src_ip
        
        # 生成当前流的唯一标识
        stream_id = self.get_stream_id(ssrc, src_ip, src_port, dst_ip, dst_port)
        
        # 检查是否已经有这个流的会话
        if stream_id in self.stream_to_session:
            session_key = self.stream_to_session[stream_id]
            session = self.active_sessions[session_key]
            return session
        
        # 查找可能的配对会话（双向流：IP和端口互换）
        matching_session = None
        
        for session_key, session in self.active_sessions.items():
            if session.peer_ip == peer_ip and session.can_pair_with_connection(src_ip, dst_ip, src_port, dst_port, direction):
                matching_session = session
                break
        
        if matching_session:
            # 找到配对，添加到现有会话
            matching_session.add_stream(stream_id, ssrc, direction, src_ip, dst_ip, src_port, dst_port, codec)
            self.stream_to_session[stream_id] = matching_session.session_key
            logger.info(f"流 {stream_id} 配对到会话 {matching_session.session_key}")
            return matching_session
        else:
            # 创建新会话
            session_key = f"{peer_ip.replace('.', '_')}_{self.session_counter}"
            self.session_counter += 1
            
            session = Session(session_key, peer_ip)
            session.add_stream(stream_id, ssrc, direction, src_ip, dst_ip, src_port, dst_port, codec)
            
            self.active_sessions[session_key] = session
            self.stream_to_session[stream_id] = session_key
            
            logger.info(f"创建新会话 {session_key}: 流 {stream_id} ({direction})")
            return session

    def finalize_session(self, session_key):
        """完成会话并生成音频文件"""
        if session_key not in self.active_sessions:
            return
            
        session = self.active_sessions[session_key]
        logger.info(f"完成会话 {session_key}")
        
        # 生成音频文件
        session.save_audio_files(self.output_dir)
        
        # 清理会话
        for stream_id in session.get_all_stream_ids():
            if stream_id in self.stream_to_session:
                del self.stream_to_session[stream_id]
        
        del self.active_sessions[session_key]
        logger.info(f"会话 {session_key} 已清理")

    def process_pcap_streaming(self):
        """流式处理PCAP文件或stdin"""
        if self.pcap_file == '/dev/stdin':
            logger.info("开始流式处理stdin数据")
            cmd = [
                'tshark', '-r', '-',  # 从stdin读取pcap数据
                '-Y', f'udp and (ip.src == {self.hotline_server_ip} or ip.dst == {self.hotline_server_ip})',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'ip.src',
                '-e', 'ip.dst', 
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-e', 'udp.payload',
                '-E', 'header=y',
                '-E', 'separator=|'
            ]
        else:
            logger.info(f"开始流式处理PCAP文件: {self.pcap_file}")
            cmd = [
                'tshark', '-r', self.pcap_file,
                '-Y', f'udp and (ip.src == {self.hotline_server_ip} or ip.dst == {self.hotline_server_ip})',
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'ip.src',
                '-e', 'ip.dst', 
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-e', 'udp.payload',
                '-E', 'header=y',
                '-E', 'separator=|'
            ]
        
        try:
            # 使用Popen进行真正的流式处理
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                     text=True, bufsize=1, universal_newlines=True)
            
            logger.info("开始实时处理数据流...")
            
            # 跳过标题行
            header_line = process.stdout.readline()
            if not header_line:
                logger.warning("未收到数据")
                return
                
            # 实时处理每一行
            processed_packets = 0
            
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                    
                fields = line.split('|')
                if len(fields) >= 6:
                    frame_num, src_ip, dst_ip, src_port, dst_port, payload = fields[:6]
                    
                    # IP黑名单过滤
                    if self.is_ip_blacklisted(src_ip) or self.is_ip_blacklisted(dst_ip):
                        continue
                    
                    # 过滤掉不包含热线服务器IP的包
                    if self.hotline_server_ip not in [src_ip, dst_ip]:
                        continue
                    
                    # 尝试解析为RTP包
                    rtp_info = self.parse_rtp_packet(payload)
                    if rtp_info:
                        ssrc = rtp_info['ssrc']
                        
                        # 确定方向
                        direction = "citizen" if src_ip == self.hotline_server_ip else "hotline"
                        
                        # 创建或更新会话
                        session = self.create_or_update_session(
                            ssrc, src_ip, dst_ip, int(src_port), int(dst_port), 
                            direction, rtp_info['codec']
                        )
                        
                        # 如果是自通话包，跳过处理
                        if session is None:
                            continue
                        
                        # 添加RTP包到会话
                        stream_id = self.get_stream_id(ssrc, src_ip, int(src_port), dst_ip, int(dst_port))
                        session.add_rtp_packet(stream_id, rtp_info)
                        processed_packets += 1
                        
                        if processed_packets % 10000 == 0:
                            logger.info(f"已处理 {processed_packets} 个RTP包")
                    
                    # 尝试解析为RTCP包
                    bye_ssrcs = self.parse_rtcp_packet(payload)
                    if bye_ssrcs:
                        for bye_ssrc in bye_ssrcs:
                            # 查找包含这个SSRC的所有流
                            sessions_to_finalize = set()
                            for stream_id, session_key in self.stream_to_session.items():
                                if stream_id.startswith(f"{bye_ssrc:08x}_"):
                                    sessions_to_finalize.add(session_key)
                            
                            # 完成相关会话
                            for session_key in sessions_to_finalize:
                                logger.info(f"收到SSRC {bye_ssrc:08x} 的BYE信号，完成会话 {session_key}")
                                self.finalize_session(session_key)
            
            # 等待tshark进程结束
            process.wait()
            
            # 处理剩余的活跃会话
            remaining_sessions = list(self.active_sessions.keys())
            for session_key in remaining_sessions:
                logger.info(f"处理剩余会话 {session_key}")
                self.finalize_session(session_key)
            
            logger.info(f"流式处理完成！总共处理了 {processed_packets} 个RTP包")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"tshark执行失败: {e}")
            raise

class Session:
    def __init__(self, session_key, peer_ip):
        self.session_key = session_key
        self.peer_ip = peer_ip
        self.streams = {}  # stream_id -> {'ssrc', 'direction', 'packets', 'codec', 'connection_info'}
        
    def add_stream(self, stream_id, ssrc, direction, src_ip, dst_ip, src_port, dst_port, codec):
        """添加流到会话"""
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
        """检查是否可以与给定的连接配对（双向流：IP和端口互换）"""
        for stream_id, stream_info in self.streams.items():
            # 检查是否是双向连接（IP和端口互换，方向不同）
            if (stream_info['src_ip'] == dst_ip and stream_info['dst_ip'] == src_ip and
                stream_info['src_port'] == dst_port and stream_info['dst_port'] == src_port and
                stream_info['direction'] != direction):
                return True
        return False
    
    def add_rtp_packet(self, stream_id, rtp_info):
        """添加RTP包到指定流"""
        if stream_id in self.streams:
            self.streams[stream_id]['packets'].append(rtp_info)
    
    def get_all_stream_ids(self):
        """获取会话中的所有流ID"""
        return list(self.streams.keys())
    
    def save_audio_files(self, output_dir):
        """保存会话的音频文件"""
        if not self.streams:
            return
        
        # 创建会话文件夹
        ssrc_list = sorted(set(stream_info['ssrc'] for stream_info in self.streams.values()))
        ssrc_hex_list = [f"{ssrc:08x}" for ssrc in ssrc_list]
        
        # 获取接线员IP和端口信息
        operator_ip = self.peer_ip  # 接线员IP（非热线服务器的IP）
        citizen_port = None  # 市民声音流的端口
        hotline_port = None  # 接线员声音流的端口
        
        for stream_info in self.streams.values():
            if stream_info['direction'] == 'citizen':
                # citizen方向：热线服务器发出的包，dst_port是接线员端口
                citizen_port = stream_info['dst_port']  # 接线员接收市民声音的端口
            elif stream_info['direction'] == 'hotline':
                # hotline方向：接线员发给热线服务器的包，dst_port是热线服务器端口
                hotline_port = stream_info['dst_port']  # 接线员发送声音到热线服务器的端口
        
        # 构建文件夹名称：{接线员IP}_{citizen_port}_{hotline_port}_{SSRC1}_{SSRC2}
        if citizen_port and hotline_port and len(ssrc_hex_list) > 0:
            # 双向配对的情况
            operator_ip_clean = operator_ip.replace('.', '_')
            folder_name = f"{operator_ip_clean}_{citizen_port}_{hotline_port}_{'_'.join(ssrc_hex_list)}"
        else:
            # 单向流的情况，使用原来的命名方式
            folder_name = f"{self.peer_ip.replace('.', '_')}_{'_'.join(ssrc_hex_list)}"
        
        session_dir = output_dir / folder_name
        session_dir.mkdir(exist_ok=True)
        
        # 按方向分组流
        direction_streams = {'citizen': [], 'hotline': []}
        for stream_id, stream_info in self.streams.items():
            direction = stream_info['direction']
            if direction in direction_streams:
                direction_streams[direction].append(stream_info)
        
        # 分别保存citizen和hotline音频
        for direction, stream_list in direction_streams.items():
            if not stream_list:
                continue
            
            # 合并同方向的所有流的包
            all_packets = []
            codec = None
            for stream_info in stream_list:
                all_packets.extend(stream_info['packets'])
                if codec is None:
                    codec = stream_info['codec']
            
            if not all_packets:
                continue
            
            # 按序列号排序
            all_packets.sort(key=lambda p: p['sequence'])
            
            # 合并音频数据
            audio_data = b''.join(p['audio_data'] for p in all_packets)
            
            # G711解码
            if codec == "PCMU":
                decoded_audio = audioop.ulaw2lin(audio_data, 2)
            elif codec == "PCMA":
                decoded_audio = audioop.alaw2lin(audio_data, 2)
            else:
                decoded_audio = audio_data
            
            # 创建AudioSegment
            audio_segment = AudioSegment(
                decoded_audio,
                frame_rate=8000,
                sample_width=2,
                channels=1
            )
            
            # 保存文件
            filename = f"{direction}.wav"
            filepath = session_dir / filename
            audio_segment.export(str(filepath), format="wav")
            
            duration = len(all_packets) * 0.02  # 假设20ms每包
            logger.info(f"保存{direction}音频: {filepath}")
            logger.info(f"  - 流数: {len(stream_list)}")
            logger.info(f"  - 编码: {codec}")
            logger.info(f"  - 包数: {len(all_packets)}")
            logger.info(f"  - 时长: {duration:.2f}秒")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='从PCAP文件中流式恢复音频')
    parser.add_argument('pcap_file', help='输入的PCAP文件路径（使用/dev/stdin从管道读取）')
    parser.add_argument('output_dir', nargs='?', default='extracted_audio', help='输出目录 (默认: extracted_audio)')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    recovery = StreamingAudioRecovery(args.pcap_file, args.output_dir)
    recovery.process_pcap_streaming()

if __name__ == "__main__":
    main()
