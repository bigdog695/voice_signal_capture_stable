#!/usr/bin/env python3

import subprocess
import struct
import audioop
import logging
import time
import select
import socket
import sys
import io
import json
from pathlib import Path
from collections import defaultdict
from pydub import AudioSegment
import dpkt

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class StreamingAudioRecovery:
    def __init__(self, pcap_file, output_dir="extracted_audio", use_whitelist=False, whitelist_ips=None, debug_mode=False, zmq_enabled=False, zmq_endpoint="tcp://127.0.0.1:5555", chunk_seconds=0.5):
        self.pcap_file = pcap_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.hotline_server_ip = "192.168.0.201"
        self.blacklisted_ips = {"192.168.0.118", "192.168.0.119", "192.168.0.121"}
        
        # IP白名单机制
        self.use_whitelist = use_whitelist
        self.whitelisted_ips = set(whitelist_ips) if whitelist_ips else set()
        
        # 调试与ZMQ设置
        self.debug_mode = debug_mode
        self.zmq_enabled = zmq_enabled
        self.zmq_endpoint = zmq_endpoint
        self.chunk_seconds = float(chunk_seconds) if chunk_seconds and float(chunk_seconds) > 0 else 0.5
        self.sample_rate = 8000
        self.sample_width_bytes = 2  # s16le
        self.channels = 1
        self.chunk_bytes = int(self.sample_rate * self.sample_width_bytes * self.chunk_seconds)
        
        self.zmq_ctx = None
        self.zmq_sock = None
        if self.zmq_enabled:
            try:
                import zmq  # 延迟导入
                self.zmq_ctx = zmq.Context.instance()
                # 使用PUSH以便下游用PULL形成队列
                self.zmq_sock = self.zmq_ctx.socket(zmq.PUSH)
                self.zmq_sock.connect(self.zmq_endpoint)
                logger.info(f"已连接ZMQ队列: {self.zmq_endpoint}, chunk时长: {self.chunk_seconds}s, chunk字节: {self.chunk_bytes}")
            except Exception as e:
                logger.error(f"初始化ZMQ失败: {e}")
                self.zmq_enabled = False
        # 发布函数
        self.publisher = self._publish_zmq if self.zmq_enabled else None
        
        # 活跃会话管理
        self.active_sessions = {}  # session_key -> Session对象
        self.stream_to_session = {}  # stream_id -> session_key的映射
        
        self.session_counter = 1
        
        # 记录配置信息
        logger.info(f"IP过滤配置:")
        logger.info(f"  黑名单: {self.blacklisted_ips}")
        if self.use_whitelist:
            logger.info(f"  白名单模式: 启用")
            logger.info(f"  白名单: {self.whitelisted_ips}")
        else:
            logger.info(f"  白名单模式: 禁用")
        logger.info(f"  调试模式: {'启用' if self.debug_mode else '禁用'}")
        if self.zmq_enabled:
            logger.info(f"  ZMQ输出: 启用 -> {self.zmq_endpoint}")
        else:
            logger.info(f"  ZMQ输出: 禁用")

    def _publish_zmq(self, peer_ip, source, pcm_bytes, start_ts, end_ts, is_finished):
        if not self.zmq_sock:
            return
        # 元数据按约定结构
        meta = {
            'peer_ip': peer_ip,
            'source': source,
            'start_ts': float(start_ts) if start_ts is not None else None,
            'end_ts': float(end_ts) if end_ts is not None else None,
            'IsFinished': bool(is_finished)
        }
        try:
            self.zmq_sock.send_multipart([
                json.dumps(meta, ensure_ascii=False).encode('utf-8'),
                pcm_bytes
            ])
        except Exception as e:
            logger.error(f"ZMQ发送失败: {e}")
    
    def is_ip_blacklisted(self, ip):
        """检查IP是否在黑名单中"""
        return ip in self.blacklisted_ips
    
    def is_ip_whitelisted(self, ip):
        """检查IP是否在白名单中"""
        return ip in self.whitelisted_ips
    
    def should_process_ip(self, src_ip, dst_ip):
        """判断是否应该处理这个IP对"""
        # 首先检查黑名单
        if self.is_ip_blacklisted(src_ip) or self.is_ip_blacklisted(dst_ip):
            return False
        
        # 如果启用白名单模式
        if self.use_whitelist:
            # 获取接线员IP（非热线服务器的IP）
            operator_ip = src_ip if src_ip != self.hotline_server_ip else dst_ip
            
            # 检查接线员IP是否在白名单中
            if not self.is_ip_whitelisted(operator_ip):
                return False
        
        return True
    
    def get_stream_id(self, ssrc, src_ip, src_port, dst_ip, dst_port):
        """生成RTP流的唯一标识符（五元组）"""
        try:
            # 检查是否已经是stream_id格式
            if isinstance(ssrc, str) and '_' in ssrc:
                # 可能已经是stream_id，返回原始值
                logger.warning(f"可能收到了stream_id而不是SSRC: {ssrc}")
                return ssrc
                
            # 确保ssrc是整数
            if isinstance(ssrc, str):
                if ssrc.startswith('0x'):
                    ssrc = int(ssrc, 16)
                else:
                    # 尝试十六进制解析
                    try:
                        ssrc = int(ssrc, 16)
                    except ValueError:
                        # 尝试十进制解析
                        ssrc = int(ssrc)
                        
            # 格式化SSRC为8位十六进制
            return f"{ssrc & 0xFFFFFFFF:08x}_{src_ip}_{src_port}_{dst_ip}_{dst_port}"
        except (ValueError, TypeError) as e:
            logger.error(f"生成stream_id时SSRC格式错误: {ssrc}, 错误: {e}")
            # 确保返回有效的stream_id
            if isinstance(ssrc, str):
                clean_ssrc = ssrc.split('_')[0] if '_' in ssrc else ssrc
            else:
                clean_ssrc = str(ssrc)
            return f"{clean_ssrc}_{src_ip}_{src_port}_{dst_ip}_{dst_port}"

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
                    logger.info(f"检测到RTCP BYE: SSRC {ssrc:08x}")  # 保持提高的日志级别
                
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
        # 确保ssrc是整数
        if isinstance(ssrc, str):
            try:
                if ssrc.startswith('0x'):
                    ssrc_int = int(ssrc, 16)
                else:
                    # 尝试十六进制解析
                    try:
                        ssrc_int = int(ssrc, 16)
                    except ValueError:
                        # 尝试十进制解析
                        ssrc_int = int(ssrc)
                ssrc_hex = f"{ssrc_int & 0xFFFFFFFF:08x}"
            except (ValueError, TypeError):
                ssrc_hex = ssrc.split('_')[0] if '_' in ssrc else ssrc
        else:
            ssrc_hex = f"{ssrc & 0xFFFFFFFF:08x}"
            
        stream_id = f"{ssrc_hex}_{src_ip}_{src_port}_{dst_ip}_{dst_port}"
        
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
            logger.debug(f"  配对会话中已有流: {list(matching_session.streams.keys())}")
            return matching_session
        else:
            # 创建新会话
            session_key = f"{peer_ip.replace('.', '_')}_{self.session_counter}"
            self.session_counter += 1
            
            session = Session(session_key, peer_ip, publisher=self.publisher, chunk_bytes=self.chunk_bytes)
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
        
        # 记录会话中的所有流信息
        for stream_id, stream_info in session.streams.items():
            logger.info(f"  流 {stream_id}: SSRC={stream_info['ssrc']}, 方向={stream_info['direction']}, 包数={len(stream_info['packets'])}")
        
        # 发送剩余未满chunk的数据
        session.flush_pending_chunks()
        
        # 生成音频文件（仅调试模式）
        if self.debug_mode:
            session.save_audio_files(self.output_dir)
        
        # 清理会话
        for stream_id in session.get_all_stream_ids():
            if stream_id in self.stream_to_session:
                del self.stream_to_session[stream_id]
        
        del self.active_sessions[session_key]
        logger.info(f"会话 {session_key} 已清理")

    def process_pcap_streaming(self):
        """流式处理PCAP文件或stdin，使用dpkt库替代tshark"""
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
            
            # 创建pcap读取器
            try:
                pcap_reader = dpkt.pcap.Reader(input_stream)
            except Exception as e:
                logger.error(f"创建pcap读取器失败: {e}")
                return
            
            # 持续读取数据包
            while True:
                try:
                    # 非阻塞读取，使用select模拟
                    if self.pcap_file == '/dev/stdin':
                        if not select.select([input_stream], [], [], 1.0)[0]:
                            # 检查超时
                            current_time = time.time()
                            if current_time - last_activity_time > 30:
                                active_count = len(self.active_sessions)
                                if active_count > 0:
                                    logger.info(f"等待数据中... (活跃会话: {active_count}, 已处理: {processed_packets} 包)")
                                    
                                    # 检查各个会话是否超时（2分钟无活动）
                                    timeout_sessions = []
                                    for session_key, session in self.active_sessions.items():
                                        if current_time - session.last_activity > 120:  # 2分钟无活动
                                            timeout_sessions.append(session_key)
                                    
                                    if timeout_sessions:
                                        logger.info(f"检测到 {len(timeout_sessions)} 个会话超时，手动结束")
                                        for session_key in timeout_sessions:
                                            logger.info(f"手动结束会话 {session_key} (超时)")
                                            self.finalize_session(session_key)
                                        last_activity_time = current_time  # 重置全局活动时间
                                else:
                                    logger.info(f"等待新通话中... (已处理: {processed_packets} 包)")
                                last_activity_time = current_time
                            continue
                    
                    # 读取下一个数据包
                    try:
                        ts, buf = next(pcap_reader)
                    except StopIteration:
                        logger.info("数据流结束")
                        break
                    except Exception as e:
                        logger.error(f"读取数据包出错: {e}")
                        continue
                    
                    last_activity_time = time.time()
                    
                    # 解析以太网帧
                    try:
                        # 根据pcap文件类型处理
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
                        elif pcap_reader.datalink() == dpkt.pcap.DLT_RAW or pcap_reader.datalink() == 101:  # RAW IP
                            ip = dpkt.ip.IP(buf)
                        else:
                            logger.warning(f"不支持的数据链路类型: {pcap_reader.datalink()}")
                            continue
                        
                        # 提取IP地址
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                        
                        # 过滤掉不包含热线服务器IP的包
                        if self.hotline_server_ip not in [src_ip, dst_ip]:
                            continue
                        
                        # IP过滤（黑名单 + 白名单）
                        if not self.should_process_ip(src_ip, dst_ip):
                            continue
                        
                        # 检查是否为UDP
                        if not isinstance(ip.data, dpkt.udp.UDP):
                            continue
                        
                        udp = ip.data
                        src_port = udp.sport
                        dst_port = udp.dport
                        payload_bytes = udp.data
                        
                        # 将payload_bytes转换为十六进制字符串，以便使用现有的解析函数
                        payload_hex = ''.join(f'{b:02x}' for b in payload_bytes)
                        
                        # 尝试解析为RTP包
                        rtp_info = self.parse_rtp_packet(payload_hex)
                        if rtp_info:
                            ssrc = rtp_info['ssrc']
                            stream_id = self.get_stream_id(ssrc, src_ip, src_port, dst_ip, dst_port)
                            
                            # 过滤掉自通话
                            if src_ip == dst_ip == self.hotline_server_ip:
                                continue
                            
                            # 创建或更新会话
                            direction = "citizen" if src_ip == self.hotline_server_ip else "hotline"
                            session = self.create_or_update_session(ssrc, src_ip, dst_ip, 
                                                        src_port, dst_port, direction, rtp_info['codec'])
                            
                            # 将RTP数据包添加到会话中
                            if session:
                                # 附加pcap捕获时间戳
                                rtp_info['pcap_ts'] = ts
                                session.add_rtp_packet(stream_id, rtp_info)
                                
                            processed_packets += 1
                            
                            if processed_packets % 100 == 0:
                                logger.debug(f"已处理 {processed_packets} 个RTP包")
                        
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
                                    
                                    # 使用五元组匹配（SSRC + src_ip + RTP src_port + dst_ip + RTP dst_port）
                                    for stream_id, session_key in self.stream_to_session.items():
                                        # 检查SSRC匹配
                                        if stream_id.startswith(f"{bye_ssrc_hex}_"):
                                            # 检查五元组的其他部分是否匹配
                                            stream_parts = stream_id.split('_')
                                            if len(stream_parts) >= 5:
                                                stream_src_ip = stream_parts[1]
                                                stream_src_port = int(stream_parts[2])
                                                stream_dst_ip = stream_parts[3]
                                                stream_dst_port = int(stream_parts[4])
                                                
                                                # 检查IP匹配和端口匹配（考虑RTCP端口比RTP端口大1）
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
                        logger.error(f"处理数据包时出错: {e}")
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
            
            logger.info(f"流式处理完成！总共处理了 {processed_packets} 个RTP包")
            
        except Exception as e:
            logger.error(f"处理pcap文件出错: {e}")
            raise
        finally:
            # 关闭文件（如果不是stdin）
            if self.pcap_file != '/dev/stdin' and input_stream:
                input_stream.close()
    

class Session:
    def __init__(self, session_key, peer_ip, *, publisher=None, chunk_bytes=8000):
        self.session_key = session_key
        self.peer_ip = peer_ip
        self.streams = {}  # stream_id -> {'ssrc', 'direction', 'packets', 'codec', 'connection_info'}
        self.last_activity = time.time()  # 记录最后活动时间
        
        # ZMQ发布相关
        self.publisher = publisher  # callable(peer_ip, direction, pcm_bytes, start_ts, end_ts)
        self.chunk_bytes = int(chunk_bytes)
        # 每个方向一个段缓冲队列：[{ 'ts': float, 'pcm': bytes }]
        self.direction_segments = {
            'citizen': [],
            'hotline': []
        }
        self.published_any = {
            'citizen': False,
            'hotline': False
        }
        
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
        current_time = time.time()
        
        for stream_id, stream_info in self.streams.items():
            # 检查是否是双向连接（IP和端口互换，方向不同）
            if (stream_info['src_ip'] == dst_ip and stream_info['dst_ip'] == src_ip and
                stream_info['src_port'] == dst_port and stream_info['dst_port'] == src_port and
                stream_info['direction'] != direction):
                
                # 检查时间窗口 - 只配对最近30秒内的流
                if 'last_packet_time' not in stream_info or (current_time - stream_info['last_packet_time']) < 30:
                    logger.debug(f"找到配对流: {stream_id}, 方向: {stream_info['direction']}")
                    return True
                else:
                    logger.debug(f"流 {stream_id} 超过时间窗口 ({current_time - stream_info['last_packet_time']:.2f}秒), 不配对")
        return False
    
    def add_rtp_packet(self, stream_id, rtp_info):
        """添加RTP包到指定流"""
        if stream_id in self.streams:
            self.streams[stream_id]['packets'].append(rtp_info)
            self.streams[stream_id]['last_packet_time'] = time.time()  # 记录最后包的时间
            self.last_activity = time.time()  # 更新最后活动时间
            # 实时分片并发布到ZMQ（如启用）
            if self.publisher:
                self._ingest_and_maybe_publish(self.streams[stream_id]['direction'], self.streams[stream_id]['codec'], rtp_info)

    def _ingest_and_maybe_publish(self, direction, codec, rtp_info):
        """将单个RTP包解码并加入方向段队列，满足chunk大小则发布"""
        audio_bytes = rtp_info.get('audio_data', b'')
        if not audio_bytes:
            return
        # G711解码为s16le
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
        # 加入段队列
        seg_list = self.direction_segments.get(direction)
        if seg_list is None:
            return
        seg_list.append({'ts': rtp_info.get('pcap_ts', time.time()), 'pcm': pcm})
        # 尝试发布尽可能多的完整chunk
        self._drain_full_chunks(direction)

    def _drain_full_chunks(self, direction):
        seg_list = self.direction_segments.get(direction)
        if not seg_list:
            return
        total_bytes = sum(len(seg['pcm']) for seg in seg_list)
        while total_bytes >= self.chunk_bytes:
            # 组装一个chunk
            chunk_parts = []
            consumed = 0
            start_ts = seg_list[0]['ts']
            end_ts = start_ts
            # 从左到右弹出段
            while seg_list and consumed + len(seg_list[0]['pcm']) <= self.chunk_bytes:
                seg = seg_list.pop(0)
                chunk_parts.append(seg['pcm'])
                consumed += len(seg['pcm'])
                end_ts = seg['ts']
            if consumed < self.chunk_bytes and seg_list:
                # 需要从下一个段切一部分
                seg = seg_list[0]
                need = self.chunk_bytes - consumed
                take = seg['pcm'][:need]
                remain = seg['pcm'][need:]
                chunk_parts.append(take)
                consumed += len(take)
                end_ts = seg['ts']
                # 更新剩余段
                seg_list[0] = {'ts': seg['ts'], 'pcm': remain}
            # 发布
            chunk_pcm = b''.join(chunk_parts)
            self._publish_chunk(direction, chunk_pcm, start_ts, end_ts, is_finished=False)
            total_bytes -= self.chunk_bytes

    def _publish_chunk(self, direction, pcm_bytes, start_ts, end_ts, is_finished):
        if not self.publisher or not pcm_bytes:
            return
        # 方向映射到所需字符串
        source = 'citizen' if direction == 'citizen' else 'hot-line'
        self.publisher(self.peer_ip, source, pcm_bytes, start_ts, end_ts, is_finished)
        # 标记该方向已发布过数据
        self.published_any[direction] = True

    def flush_pending_chunks(self):
        """在会话结束时，发布剩余不足一个chunk的音频（如果有）"""
        if not self.publisher:
            # 无需发布
            self.direction_segments['citizen'].clear()
            self.direction_segments['hotline'].clear()
            return
        for direction in ['citizen', 'hotline']:
            seg_list = self.direction_segments.get(direction, [])
            if seg_list:
                # 组装所有剩余段
                start_ts = seg_list[0]['ts']
                end_ts = seg_list[-1]['ts']
                chunk_pcm = b''.join(seg['pcm'] for seg in seg_list)
                if chunk_pcm:
                    self._publish_chunk(direction, chunk_pcm, start_ts, end_ts, is_finished=True)
                seg_list.clear()
            else:
                # 如果恰好落在chunk边界，确保发出结束标记
                if self.published_any.get(direction, False):
                    now_ts = time.time()
                    self._publish_chunk(direction, b'', now_ts, now_ts, is_finished=True)
    
    def get_all_stream_ids(self):
        """获取会话中的所有流ID"""
        return list(self.streams.keys())
    
    def save_audio_files(self, output_dir):
        """保存会话的音频文件"""
        if not self.streams:
            return
        
        # 创建会话文件夹
        ssrc_list = sorted(set(stream_info['ssrc'] for stream_info in self.streams.values()))
        ssrc_hex_list = []
        for ssrc in ssrc_list:
            try:
                if isinstance(ssrc, str):
                    ssrc = int(ssrc, 16) if ssrc.startswith('0x') else int(ssrc)
                ssrc_hex_list.append(f"{ssrc:08x}")
            except (ValueError, TypeError) as e:
                logger.error(f"格式化SSRC时出错: {ssrc}, 错误: {e}")
                ssrc_hex_list.append(str(ssrc))
        
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
            # 注意：RTP序列号是16位无符号整数，可能会溢出循环
            # 使用时间戳更可靠，或者考虑序列号循环
            all_packets.sort(key=lambda p: p['timestamp'])
            
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
            
            # 为每个流单独保存一个音频文件，方便对比和调试
            for i, stream_info in enumerate(stream_list):
                stream_packets = stream_info['packets']
                if not stream_packets:
                    continue
                    
                # 按时间戳排序，而不是序列号
                stream_packets.sort(key=lambda p: p['timestamp'])
                
                # 合并音频数据
                stream_audio_data = b''.join(p['audio_data'] for p in stream_packets)
                
                # G711解码
                stream_codec = stream_info['codec']
                if stream_codec == "PCMU":
                    stream_decoded_audio = audioop.ulaw2lin(stream_audio_data, 2)
                elif stream_codec == "PCMA":
                    stream_decoded_audio = audioop.alaw2lin(stream_audio_data, 2)
                else:
                    stream_decoded_audio = stream_audio_data
                
                # 创建AudioSegment
                stream_audio_segment = AudioSegment(
                    stream_decoded_audio,
                    frame_rate=8000,
                    sample_width=2,
                    channels=1
                )
                
                # 保存单独的流文件
                ssrc_hex = f"{stream_info['ssrc']:08x}" if isinstance(stream_info['ssrc'], int) else stream_info['ssrc']
                debug_filename = f"{direction}_{ssrc_hex}.wav"
                debug_filepath = session_dir / debug_filename
                stream_audio_segment.export(str(debug_filepath), format="wav")
                logger.debug(f"  - 保存单独流音频: {debug_filepath}, 包数: {len(stream_packets)}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='从PCAP文件中流式恢复音频')
    parser.add_argument('pcap_file', help='输入的PCAP文件路径（使用/dev/stdin从管道读取）')
    parser.add_argument('output_dir', nargs='?', default='extracted_audio', help='输出目录 (默认: extracted_audio)')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    parser.add_argument('--use-whitelist', action='store_true', help='启用IP白名单模式')
    parser.add_argument('--whitelist', nargs='+', help='IP白名单列表，例如: --whitelist 192.168.10.91 192.168.5.21')
    parser.add_argument('--debug', action='store_true', help='启用调试模式，记录更详细的日志，并保存完整音频文件')
    # ZMQ相关
    parser.add_argument('--zmq', action='store_true', help='启用ZMQ输出（PUSH模式）')
    parser.add_argument('--zmq-endpoint', default='tcp://127.0.0.1:5555', help='ZMQ端点（默认: tcp://127.0.0.1:5555）')
    parser.add_argument('--chunk-seconds', type=float, default=0.5, help='每条消息的音频时长（秒），默认0.5s')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        # 添加文件日志处理器
        file_handler = logging.FileHandler('audio_recovery_debug.log')
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)
    
    # 验证白名单参数
    if args.use_whitelist and not args.whitelist:
        parser.error("启用白名单模式时必须提供 --whitelist 参数")
    
    recovery = StreamingAudioRecovery(
        args.pcap_file,
        args.output_dir,
        use_whitelist=args.use_whitelist,
        whitelist_ips=args.whitelist,
        debug_mode=args.debug,
        zmq_enabled=args.zmq,
        zmq_endpoint=args.zmq_endpoint,
        chunk_seconds=args.chunk_seconds
    )
    recovery.process_pcap_streaming()

if __name__ == "__main__":
    main()
