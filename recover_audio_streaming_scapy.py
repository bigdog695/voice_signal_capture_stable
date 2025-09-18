#!/usr/bin/env python3
"""
音频恢复流式处理脚本 - 使用scapy版本
从PCAP文件或stdin流式处理RTP包，恢复音频会话
"""

import argparse
import time
import select
import socket
import logging
import sys
import io
import json
from pathlib import Path
from collections import defaultdict
from pydub import AudioSegment
from scapy.all import *
from scapy.utils import rdpcap
import io

# 设置日志
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 导入ZMQ（如果可用）
try:
    import zmq
    ZMQ_AVAILABLE = True
    logger.info("ZMQ支持已启用")
except ImportError:
    ZMQ_AVAILABLE = False
    logger.warning("ZMQ不可用，将禁用实时推送功能")

class Session:
    """表示一个通话会话"""
    
    def __init__(self, session_key, src_ip, dst_ip, direction):
        self.session_key = session_key
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.direction = direction  # "citizen" 或 "hotline"
        self.streams = {}  # stream_id -> stream_data
        self.start_time = time.time()
        self.last_activity = time.time()
        self.processed = False
        
        logger.info(f"创建新会话: {session_key} ({direction})")
    
    def add_rtp_packet(self, stream_id, rtp_info):
        """添加RTP包到相应的流"""
        if stream_id not in self.streams:
            self.streams[stream_id] = {
                'codec': rtp_info['codec'],
                'packets': [],
                'src_ip': rtp_info.get('src_ip'),
                'dst_ip': rtp_info.get('dst_ip'),
                'src_port': rtp_info.get('src_port'),
                'dst_port': rtp_info.get('dst_port')
            }
            logger.debug(f"新流: {stream_id} (编解码器: {rtp_info['codec']})")
        
        self.streams[stream_id]['packets'].append(rtp_info)
        self.last_activity = time.time()
    
    def get_all_stream_ids(self):
        """获取会话中所有流的ID"""
        return list(self.streams.keys())
    
    def get_total_packets(self):
        """获取会话中总包数"""
        return sum(len(stream['packets']) for stream in self.streams.values())


class AudioRecovery:
    """音频恢复主类"""
    
    def __init__(self, pcap_file, output_dir="./extracted_audio", 
                 zmq_enabled=False, zmq_endpoint="tcp://127.0.0.1:5555",
                 hotline_server_ip="192.168.0.201", chunk_seconds=5):
        self.pcap_file = pcap_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.hotline_server_ip = hotline_server_ip
        self.chunk_seconds = chunk_seconds
        
        # 会话管理
        self.active_sessions = {}  # session_key -> Session
        self.stream_to_session = {}  # stream_id -> session_key
        
        # IP过滤配置
        self.ip_blacklist = set()
        self.ip_whitelist = set()
        
        # ZMQ配置
        self.zmq_enabled = zmq_enabled and ZMQ_AVAILABLE
        self.zmq_endpoint = zmq_endpoint
        self.zmq_context = None
        self.zmq_socket = None
        
        if self.zmq_enabled:
            self._setup_zmq()
    
    def _setup_zmq(self):
        """设置ZMQ连接"""
        try:
            self.zmq_context = zmq.Context()
            self.zmq_socket = self.zmq_context.socket(zmq.PUB)
            self.zmq_socket.setsockopt(zmq.CONFLATE, 1)
            self.zmq_socket.setsockopt(zmq.SNDHWM, 1)
            self.zmq_socket.setsockopt(zmq.LINGER, 0)
            self.zmq_socket.bind(self.zmq_endpoint)
            logger.info(f"ZMQ发布者绑定到: {self.zmq_endpoint}")
        except Exception as e:
            logger.error(f"ZMQ设置失败: {e}")
            self.zmq_enabled = False
    
    def should_process_ip(self, src_ip, dst_ip):
        """检查IP是否应该被处理"""
        # 如果有白名单，只处理白名单中的IP
        if self.ip_whitelist:
            if src_ip not in self.ip_whitelist and dst_ip not in self.ip_whitelist:
                return False
        
        # 检查黑名单
        if src_ip in self.ip_blacklist or dst_ip in self.ip_blacklist:
            return False
        
        return True
    
    def parse_rtp_packet(self, payload_hex):
        """解析RTP包"""
        try:
            if len(payload_hex) < 24:  # RTP头最小长度
                return None
            
            # 解析RTP头
            version = int(payload_hex[0], 16) >> 2
            if version != 2:
                return None
            
            payload_type = int(payload_hex[2:4], 16) & 0x7F
            sequence = int(payload_hex[4:8], 16)
            timestamp = int(payload_hex[8:16], 16)
            ssrc = payload_hex[16:24]
            
            # 确定编解码器
            codec_map = {
                0: 'PCMU', 8: 'PCMA', 18: 'G729'
            }
            codec = codec_map.get(payload_type, f'Unknown({payload_type})')
            
            return {
                'payload_type': payload_type,
                'sequence': sequence,
                'timestamp': timestamp,
                'ssrc': ssrc,
                'codec': codec,
                'payload_hex': payload_hex[24:] if len(payload_hex) > 24 else ""
            }
        except Exception as e:
            logger.debug(f"RTP解析错误: {e}")
            return None
    
    def parse_rtcp_packet(self, payload_hex):
        """解析RTCP包，查找BYE包"""
        try:
            if len(payload_hex) < 8:
                return []
            
            # 检查RTCP版本
            version = int(payload_hex[0], 16) >> 2
            if version != 2:
                return []
            
            packet_type = int(payload_hex[2:4], 16)
            if packet_type == 203:  # BYE包
                # 解析SSRC列表
                ssrc_count = int(payload_hex[0], 16) & 0x1F
                ssrcs = []
                for i in range(ssrc_count):
                    start = 8 + i * 8
                    if start + 8 <= len(payload_hex):
                        ssrc = payload_hex[start:start+8]
                        ssrcs.append(ssrc)
                return ssrcs
        except Exception as e:
            logger.debug(f"RTCP解析错误: {e}")
        
        return []
    
    def get_stream_id(self, ssrc, src_ip, src_port, dst_ip, dst_port):
        """生成流ID"""
        return f"{ssrc}_{src_ip}_{src_port}_{dst_ip}_{dst_port}"
    
    def create_or_update_session(self, ssrc, src_ip, dst_ip, src_port, dst_port, direction, codec):
        """创建或更新会话"""
        # 生成会话键
        if direction == "citizen":
            session_key = f"{dst_ip}_{src_ip}"
        else:
            session_key = f"{src_ip}_{dst_ip}"
        
        # 创建或获取会话
        if session_key not in self.active_sessions:
            session = Session(session_key, src_ip, dst_ip, direction)
            self.active_sessions[session_key] = session
        else:
            session = self.active_sessions[session_key]
            session.last_activity = time.time()
        
        # 记录流到会话的映射
        stream_id = self.get_stream_id(ssrc, src_ip, src_port, dst_ip, dst_port)
        self.stream_to_session[stream_id] = session_key
        
        return session
    
    def finalize_session(self, session_key):
        """完成并保存会话"""
        if session_key not in self.active_sessions:
            return
        
        session = self.active_sessions[session_key]
        if session.processed:
            logger.debug(f"会话 {session_key} 已处理过，跳过")
            return
        
        logger.info(f"完成会话 {session_key}")
        session.processed = True
        
        # 处理会话中的所有流
        total_packets = session.get_total_packets()
        if total_packets > 0:
            logger.info(f"会话 {session_key} 包含 {len(session.streams)} 个流，总计 {total_packets} 个包")
            
            # 这里可以添加音频重建和保存逻辑
            # 目前只是记录会话信息
            session_info = {
                'session_key': session_key,
                'direction': session.direction,
                'src_ip': session.src_ip,
                'dst_ip': session.dst_ip,
                'duration': time.time() - session.start_time,
                'total_packets': total_packets,
                'streams': len(session.streams)
            }
            
            if self.zmq_enabled and self.zmq_socket:
                try:
                    message = json.dumps(session_info)
                    self.zmq_socket.send_string(message, zmq.NOBLOCK)
                    logger.debug(f"会话信息已发送到ZMQ: {session_key}")
                except Exception as e:
                    logger.error(f"ZMQ发送失败: {e}")
        
        # 清理会话
        for stream_id in session.get_all_stream_ids():
            if stream_id in self.stream_to_session:
                del self.stream_to_session[stream_id]
        
        del self.active_sessions[session_key]
        logger.info(f"会话 {session_key} 已清理")

    def _process_scapy_packet(self, pkt):
        """使用scapy处理单个数据包"""
        try:
            # 检查是否是UDP包
            if not pkt.haslayer(UDP):
                return
            
            # 提取IP和UDP信息
            ip_layer = pkt[IP]
            udp_layer = pkt[UDP]
            
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            
            # 过滤掉不包含热线服务器IP的包
            if self.hotline_server_ip not in [src_ip, dst_ip]:
                return
            
            # IP过滤（黑名单 + 白名单）
            if not self.should_process_ip(src_ip, dst_ip):
                return
            
            # 获取UDP载荷
            payload_bytes = bytes(udp_layer.payload)
            if not payload_bytes:
                return
            
            # 将payload_bytes转换为十六进制字符串，以便使用现有的解析函数
            payload_hex = ''.join(f'{b:02x}' for b in payload_bytes)
            
            # 获取时间戳
            ts = float(pkt.time) if hasattr(pkt, 'time') else time.time()
            
            # 尝试解析为RTP包
            rtp_info = self.parse_rtp_packet(payload_hex)
            if rtp_info:
                ssrc = rtp_info['ssrc']
                stream_id = self.get_stream_id(ssrc, src_ip, src_port, dst_ip, dst_port)
                
                # 过滤掉自通话
                if src_ip == dst_ip == self.hotline_server_ip:
                    return
                
                # 创建或更新会话
                direction = "citizen" if src_ip == self.hotline_server_ip else "hotline"
                session = self.create_or_update_session(ssrc, src_ip, dst_ip, 
                                            src_port, dst_port, direction, rtp_info['codec'])
                
                # 将RTP数据包添加到会话中
                if session:
                    # 附加pcap捕获时间戳
                    rtp_info['pcap_ts'] = ts
                    rtp_info['src_ip'] = src_ip
                    rtp_info['dst_ip'] = dst_ip
                    rtp_info['src_port'] = src_port
                    rtp_info['dst_port'] = dst_port
                    session.add_rtp_packet(stream_id, rtp_info)
            
            # 尝试解析为RTCP包
            bye_ssrcs = self.parse_rtcp_packet(payload_hex)
            if bye_ssrcs:
                for bye_ssrc in bye_ssrcs:
                    try:
                        # 确保bye_ssrc是整数
                        if isinstance(bye_ssrc, str):
                            bye_ssrc = int(bye_ssrc, 16) if bye_ssrc.startswith('0x') else int(bye_ssrc)
                        
                        # 查找包含这个SSRC的所有流
                        sessions_to_finalize = set()
                        bye_ssrc_hex = f"{bye_ssrc:08x}"
                        
                        # 计算对应的RTP端口（RTCP端口-1）
                        rtp_src_port = src_port - 1 if src_port % 2 == 1 else src_port
                        rtp_dst_port = dst_port - 1 if dst_port % 2 == 1 else dst_port
                        
                        # 使用五元组匹配
                        for stream_id, session_key in self.stream_to_session.items():
                            if stream_id.startswith(f"{bye_ssrc_hex}_"):
                                stream_parts = stream_id.split('_')
                                if len(stream_parts) >= 5:
                                    stream_src_ip = stream_parts[1]
                                    stream_src_port = int(stream_parts[2])
                                    stream_dst_ip = stream_parts[3]
                                    stream_dst_port = int(stream_parts[4])
                                    
                                    if (stream_src_ip == src_ip and stream_dst_ip == dst_ip and 
                                        (stream_src_port == rtp_src_port) and 
                                        (stream_dst_port == rtp_dst_port)):
                                        sessions_to_finalize.add(session_key)
                                        logger.info(f"RTCP BYE匹配RTP流: {stream_id}")
                        
                        # 完成相关会话
                        for session_key in sessions_to_finalize:
                            logger.info(f"收到SSRC {bye_ssrc_hex} 的BYE信号，完成会话 {session_key}")
                            self.finalize_session(session_key)
                            
                    except (ValueError, TypeError) as e:
                        logger.error(f"处理RTCP BYE SSRC时出错: {bye_ssrc}, 错误: {e}")
                        continue
                        
        except Exception as e:
            logger.debug(f"处理scapy数据包时出错: {e}")
            return

    def process_pcap_streaming(self):
        """流式处理PCAP文件或stdin，使用scapy库替代dpkt"""
        # 打开pcap文件或stdin
        if self.pcap_file == '/dev/stdin':
            logger.info("开始流式处理stdin数据")
            input_stream = sys.stdin.buffer  # 二进制模式读取stdin
        else:
            logger.info(f"开始流式处理PCAP文件: {self.pcap_file}")
            input_stream = open(self.pcap_file, 'rb')
        
        try:
            logger.info("开始实时处理数据流...")
            processed_packets = 0
            last_activity_time = time.time()
            
            logger.info("开始持续监听数据流...")
            
            # 使用scapy进行流式处理
            buffer = b""
            
            # 持续读取数据包
            while True:
                try:
                    logger.debug("=== 开始新的循环迭代 ===")
                    
                    # 使用select检查数据可用性（仅对stdin）
                    if self.pcap_file == '/dev/stdin':
                        ready = select.select([input_stream], [], [], 1.0)[0]
                        if not ready:
                            # 检查超时和会话状态
                            current_time = time.time()
                            if current_time - last_activity_time > 30:
                                active_count = len(self.active_sessions)
                                if active_count > 0:
                                    logger.info(f"等待数据中... (活跃会话: {active_count}, 已处理: {processed_packets} 包)")
                                    # 检查会话超时
                                    timeout_sessions = []
                                    for session_key, session in self.active_sessions.items():
                                        if current_time - session.last_activity > 120:
                                            timeout_sessions.append(session_key)
                                    
                                    if timeout_sessions:
                                        logger.info(f"检测到 {len(timeout_sessions)} 个会话超时，手动结束")
                                        for session_key in timeout_sessions:
                                            logger.info(f"手动结束会话 {session_key} (超时)")
                                            self.finalize_session(session_key)
                                        last_activity_time = current_time
                                else:
                                    logger.info(f"等待新通话中... (已处理: {processed_packets} 包)")
                                last_activity_time = current_time
                            continue
                    
                    # 读取数据到缓冲区
                    try:
                        chunk = input_stream.read(8192)  # 读取8KB数据
                        if not chunk:
                            logger.debug("没有读取到数据，等待...")
                            time.sleep(0.1)
                            continue
                        
                        buffer += chunk
                        logger.debug(f"读取了 {len(chunk)} 字节，缓冲区总大小: {len(buffer)}")
                        
                    except Exception as e:
                        logger.error(f"读取数据流出错: {e}")
                        buffer = b""  # 清空缓冲区
                        time.sleep(1)
                        continue
                    
                    # 尝试从缓冲区解析数据包
                    try:
                        # 如果缓冲区太小，继续读取
                        if len(buffer) < 100:  # 至少需要基本的PCAP头和包数据
                            continue
                        
                        # 创建临时流用于scapy解析
                        temp_stream = io.BytesIO(buffer)
                        
                        try:
                            # 尝试批量读取数据包
                            packets = rdpcap(temp_stream, count=100)  # 最多读取100个包
                            logger.debug(f"✓ 成功解析 {len(packets)} 个数据包")
                            
                            # 处理解析到的数据包
                            for pkt in packets:
                                try:
                                    self._process_scapy_packet(pkt)
                                    processed_packets += 1
                                    last_activity_time = time.time()
                                    
                                    if processed_packets % 100 == 0:
                                        logger.debug(f"已处理 {processed_packets} 个数据包")
                                        
                                except Exception as pkt_error:
                                    logger.debug(f"处理单个数据包出错: {pkt_error}")
                                    continue
                            
                            # 成功处理后清空缓冲区
                            buffer = b""
                            
                        except Exception as parse_error:
                            logger.debug(f"scapy解析出错: {parse_error}")
                            
                            # 解析失败，可能是数据不完整或损坏
                            if len(buffer) > 16384:  # 如果缓冲区超过16KB
                                # 保留后半部分，丢弃前半部分可能损坏的数据
                                buffer = buffer[8192:]
                                logger.debug("缓冲区过大，保留后半部分数据")
                            elif len(buffer) > 65536:  # 如果超过64KB，完全清空
                                logger.warning("缓冲区过大且无法解析，清空重新开始")
                                buffer = b""
                            
                            continue
                            
                    except Exception as e:
                        logger.error(f"处理缓冲区数据时出错: {e}")
                        buffer = b""  # 清空缓冲区重新开始
                        time.sleep(1)
                        continue
                        
                except KeyboardInterrupt:
                    logger.info("收到中断信号，正在停止...")
                    break
                except Exception as e:
                    logger.error(f"处理数据时出错: {e}")
                    continue
            
            # 处理剩余的活跃会话
            remaining_sessions = list(self.active_sessions.keys())
            for session_key in remaining_sessions:
                logger.info(f"处理剩余会话 {session_key}")
                self.finalize_session(session_key)
            
            logger.info(f"流式处理完成！总共处理了 {processed_packets} 个数据包")
            
        except Exception as e:
            logger.error(f"处理pcap文件出错: {e}")
            raise
        finally:
            # 关闭文件（如果不是stdin）
            if self.pcap_file != '/dev/stdin' and input_stream:
                input_stream.close()
            
            # 清理ZMQ资源
            if self.zmq_enabled:
                if self.zmq_socket:
                    self.zmq_socket.close()
                if self.zmq_context:
                    self.zmq_context.term()


def main():
    parser = argparse.ArgumentParser(description='从PCAP流式恢复音频会话 - Scapy版本')
    parser.add_argument('pcap_file', nargs='?', default='/dev/stdin',
                       help='PCAP文件路径或/dev/stdin (默认: /dev/stdin)')
    parser.add_argument('--output-dir', default='./extracted_audio',
                       help='输出目录 (默认: ./extracted_audio)')
    parser.add_argument('--hotline-server-ip', default='192.168.0.201',
                       help='热线服务器IP (默认: 192.168.0.201)')
    parser.add_argument('--chunk-seconds', type=int, default=5,
                       help='音频块长度(秒) (默认: 5)')
    parser.add_argument('--zmq', action='store_true',
                       help='启用ZMQ实时推送')
    parser.add_argument('--zmq-endpoint', default='tcp://127.0.0.1:5555',
                       help='ZMQ端点 (默认: tcp://127.0.0.1:5555)')
    
    args = parser.parse_args()
    
    # 创建音频恢复实例
    recovery = AudioRecovery(
        pcap_file=args.pcap_file,
        output_dir=args.output_dir,
        hotline_server_ip=args.hotline_server_ip,
        chunk_seconds=args.chunk_seconds,
        zmq_enabled=args.zmq,
        zmq_endpoint=args.zmq_endpoint
    )
    
    try:
        # 开始处理
        recovery.process_pcap_streaming()
    except KeyboardInterrupt:
        logger.info("用户中断")
    except Exception as e:
        logger.error(f"处理失败: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
