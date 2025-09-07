#!/usr/bin/env python3
"""
热线平台PCAP文件音频恢复脚本 - 双向会话版本
按会话配对RTP/RTCP流并恢复G711音频数据
"""

import os
import sys
import subprocess
import json
import struct
import wave
import audioop
from pathlib import Path
from collections import defaultdict
import argparse
import logging
import binascii

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AudioRecovery:
    def __init__(self, pcap_file, output_dir="./extracted_audio"):
        self.pcap_file = pcap_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.hotline_server_ip = "192.168.0.201"
        self.ssrc_streams = defaultdict(list)  # 按SSRC聚类
        self.ssrc_info = {}  # 存储每个SSRC的基本信息
        self.ended_calls = set()  # 存储已结束的通话SSRC
        self.call_sessions = {}  # 存储通话会话 {session_id: {'citizen_ssrc': xxx, 'hotline_ssrc': xxx, 'operator_ip': xxx, 'ended': False}}
        
        # 硬编码的IP黑名单
        self.blacklisted_ips = [
            '192.168.0.118',
            '192.168.0.119', 
            '192.168.0.121'
        ]
        
    def parse_rtp_packet(self, payload_hex):
        """解析RTP包"""
        if not payload_hex or len(payload_hex) < 24:  # RTP头至少12字节
            return None
            
        try:
            payload_bytes = bytes.fromhex(payload_hex.replace(':', ''))
            
            if len(payload_bytes) < 12:
                return None
                
            # RTP头格式
            # 字节0: V(2位) + P(1位) + X(1位) + CC(4位)
            # 字节1: M(1位) + PT(7位)
            # 字节2-3: Sequence Number
            # 字节4-7: Timestamp
            # 字节8-11: SSRC
            
            version = (payload_bytes[0] >> 6) & 0x3
            payload_type = payload_bytes[1] & 0x7F
            sequence = struct.unpack('!H', payload_bytes[2:4])[0]
            timestamp = struct.unpack('!I', payload_bytes[4:8])[0]
            ssrc = struct.unpack('!I', payload_bytes[8:12])[0]
            
            # 检查是否是有效的RTP包
            if version != 2 or payload_type not in [0, 8]:  # G711U(0) 或 G711A(8)
                return None
                
            # 提取音频数据（跳过RTP头）
            audio_data = payload_bytes[12:]
            
            return {
                'type': 'RTP',
                'version': version,
                'payload_type': payload_type,
                'sequence': sequence,
                'timestamp': timestamp,
                'ssrc': ssrc,
                'audio_data': audio_data,
                'codec': 'PCMU' if payload_type == 0 else 'PCMA'
            }
            
        except Exception as e:
            logger.debug(f"解析RTP包失败: {e}")
            
        return None
        
    def parse_rtcp_packet(self, payload_hex):
        """解析RTCP包，支持复合RTCP包，主要检测BYE包"""
        if not payload_hex or len(payload_hex) < 8:
            return None
            
        try:
            payload_bytes = bytes.fromhex(payload_hex.replace(':', ''))
            
            if len(payload_bytes) < 8:
                return None
                
            # 解析复合RTCP包，查找BYE包
            bye_packets = []
            other_packets = []
            
            offset = 0
            while offset < len(payload_bytes):
                if offset + 4 > len(payload_bytes):
                    break
                    
                # 解析RTCP头
                byte0 = payload_bytes[offset]
                version = (byte0 >> 6) & 0x3
                packet_type = payload_bytes[offset + 1]
                length = struct.unpack('!H', payload_bytes[offset + 2:offset + 4])[0]
                packet_length = (length + 1) * 4
                
                if version != 2 or packet_length <= 0 or offset + packet_length > len(payload_bytes):
                    break
                
                # 提取SSRC
                ssrc = None
                if offset + 8 <= len(payload_bytes):
                    ssrc = struct.unpack('!I', payload_bytes[offset + 4:offset + 8])[0]
                
                rtcp_info = {
                    'type': 'RTCP',
                    'version': version,
                    'packet_type': packet_type,
                    'ssrc': ssrc,
                    'offset': offset,
                    'length': packet_length
                }
                
                # 检查包类型
                if packet_type == 203:  # BYE
                    rtcp_info['packet_name'] = 'BYE'
                    rtcp_info['is_goodbye'] = True
                    bye_packets.append(rtcp_info)
                elif packet_type in [200, 201, 202, 204]:  # SR/RR/SDES/APP
                    type_names = {200: 'SR', 201: 'RR', 202: 'SDES', 204: 'APP'}
                    rtcp_info['packet_name'] = type_names[packet_type]
                    other_packets.append(rtcp_info)
                
                offset += packet_length
                
                # 安全检查
                if offset >= len(payload_bytes) or len(bye_packets) + len(other_packets) > 10:
                    break
            
            # 优先返回BYE包
            if bye_packets:
                return bye_packets[0]  # 返回第一个BYE包
            elif other_packets:
                return other_packets[0]  # 返回第一个其他包
                    
        except Exception as e:
            logger.debug(f"解析RTCP包失败: {e}")
            
        return None
    
    def is_ip_blacklisted(self, ip):
        """检查IP是否在黑名单中"""
        if not ip:
            return False
        
        # 直接检查完整IP地址
        if ip in self.blacklisted_ips:
            return True
            
        return False

    def extract_rtp_rtcp_streams(self):
        """提取RTP/RTCP流信息"""
        logger.info("正在提取RTP/RTCP流信息...")
        
        # 使用tshark提取UDP包
        cmd = [
            'tshark', '-r', self.pcap_file,
            '-Y', 'udp and (ip.src == 192.168.0.201 or ip.dst == 192.168.0.201)',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst', 
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'udp.payload',
            '-E', 'header=y',
            '-E', 'separator=|'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            
            if len(lines) <= 1:
                logger.error("未找到符合条件的UDP包")
                return
                
            rtp_count = 0
            rtcp_count = 0
            
            for line in lines[1:]:  # 跳过标题行
                if not line.strip():
                    continue
                    
                fields = line.split('|')
                if len(fields) >= 5:
                    src_ip, dst_ip, src_port, dst_port, payload = fields[:5]
                    
                    # 检查是否包含热线服务器IP
                    if self.hotline_server_ip not in [src_ip, dst_ip]:
                        continue
                    
                    # IP黑名单过滤
                    if self.is_ip_blacklisted(src_ip) or self.is_ip_blacklisted(dst_ip):
                        continue
                    
                    # 尝试解析为RTP包
                    rtp_info = self.parse_rtp_packet(payload)
                    if rtp_info:
                        ssrc = rtp_info['ssrc']
                        
                        # 确定方向
                        if src_ip == self.hotline_server_ip:
                            direction = "citizen"  # 热线服务器发出，是市民声音
                            peer_ip = dst_ip
                        else:
                            direction = "hotline"  # 发给热线服务器，是接线员声音
                            peer_ip = src_ip
                        
                        # 存储SSRC信息 - 处理SSRC重用的情况
                        connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                        
                        if ssrc not in self.ssrc_info:
                            self.ssrc_info[ssrc] = {
                                'connections': {},  # 存储所有连接信息
                                'primary_connection': None,  # 主要连接（包数最多的）
                                'direction': direction,
                                'peer_ip': peer_ip,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_port': int(src_port) if src_port.isdigit() else 0,
                                'dst_port': int(dst_port) if dst_port.isdigit() else 0,
                                'rtp_port': int(src_port) if src_port.isdigit() else 0,
                                'codec': rtp_info['codec']
                            }
                        
                        # 记录连接信息
                        if connection_key not in self.ssrc_info[ssrc]['connections']:
                            self.ssrc_info[ssrc]['connections'][connection_key] = {
                                'count': 0,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_port': int(src_port) if src_port.isdigit() else 0,
                                'dst_port': int(dst_port) if dst_port.isdigit() else 0,
                                'direction': direction,
                                'peer_ip': peer_ip
                            }
                        
                        self.ssrc_info[ssrc]['connections'][connection_key]['count'] += 1
                        
                        
                        # 添加包信息
                        packet_info = {
                            'sequence': rtp_info['sequence'],
                            'timestamp': rtp_info['timestamp'],
                            'audio_data': rtp_info['audio_data'],
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port
                        }
                        
                        self.ssrc_streams[ssrc].append(packet_info)
                        rtp_count += 1
                        continue
                    
                    # 尝试解析为RTCP包
                    rtcp_info = self.parse_rtcp_packet(payload)
                    if rtcp_info and 'ssrc' in rtcp_info:
                        ssrc = rtcp_info['ssrc']
                        
                        # 检查端口是否符合RTCP规则（RTP端口+1）
                        src_port_int = int(src_port) if src_port.isdigit() else 0
                        dst_port_int = int(dst_port) if dst_port.isdigit() else 0
                        
                        # 对于已知的SSRC，检查端口是否匹配
                        is_valid_rtcp = False
                        if ssrc in self.ssrc_info:
                            expected_rtcp_port = self.ssrc_info[ssrc]['rtp_port'] + 1
                            if src_port_int == expected_rtcp_port or dst_port_int == expected_rtcp_port:
                                is_valid_rtcp = True
                        else:
                            # 对于未知SSRC，如果是BYE包，也认为是有效的
                            if rtcp_info.get('is_goodbye'):
                                is_valid_rtcp = True
                        
                        if is_valid_rtcp:
                            # 处理BYE包
                            if rtcp_info.get('is_goodbye'):
                                self.ended_calls.add(ssrc)
                                logger.info(f"检测到SSRC {ssrc} 的通话结束 (RTCP BYE)")
                            
                            rtcp_count += 1
                        
            logger.info(f"找到 {rtp_count} 个RTP包，{rtcp_count} 个RTCP包")
            logger.info(f"识别出 {len(self.ssrc_streams)} 个SSRC流")
            logger.info(f"检测到 {len(self.ended_calls)} 个已结束的通话")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"tshark执行失败: {e}")
            raise

    def find_bidirectional_pairs(self):
        """查找双向RTP流配对"""
        logger.info("正在查找双向RTP流配对...")
        
        # 收集所有SSRC信息
        all_ssrcs = {}
        for ssrc, info in self.ssrc_info.items():
            if len(self.ssrc_streams[ssrc]) == 0:  # 跳过没有数据包的SSRC
                continue
            all_ssrcs[ssrc] = info
        
        # 按接线员IP分组SSRC
        operator_groups = defaultdict(list)
        
        for ssrc, info in all_ssrcs.items():
            peer_ip = info['peer_ip']
            if peer_ip != self.hotline_server_ip:  # 接线员IP
                operator_groups[peer_ip].append(ssrc)
        
        # 已配对的SSRC集合
        paired_ssrcs = set()
        
        # 为每个接线员IP的SSRC进行配对
        session_id = 1
        for operator_ip, ssrcs in operator_groups.items():
            citizen_ssrcs = [s for s in ssrcs if self.ssrc_info[s]['direction'] == 'citizen' and s not in paired_ssrcs]
            hotline_ssrcs = [s for s in ssrcs if self.ssrc_info[s]['direction'] == 'hotline' and s not in paired_ssrcs]
            
            # 智能配对策略：首先尝试真正的双向连接配对
            paired_in_this_ip = set()
            
            for citizen_ssrc in citizen_ssrcs[:]:
                if citizen_ssrc in paired_in_this_ip:
                    continue
                    
                citizen_info = self.ssrc_info[citizen_ssrc]
                
                # 寻找真正的反向流（IP和端口互换）
                perfect_match = None
                for hotline_ssrc in hotline_ssrcs:
                    if hotline_ssrc in paired_in_this_ip:
                        continue
                        
                    hotline_info = self.ssrc_info[hotline_ssrc]
                    
                    # 检查是否是真正的双向连接（IP和端口完全互换）
                    if (citizen_info['src_ip'] == hotline_info['dst_ip'] and
                        citizen_info['dst_ip'] == hotline_info['src_ip'] and
                        citizen_info['src_port'] == hotline_info['dst_port'] and
                        citizen_info['dst_port'] == hotline_info['src_port']):
                        perfect_match = hotline_ssrc
                        break
                
                if perfect_match:
                    # 找到完美配对
                    ssrcs_for_id = sorted([citizen_ssrc, perfect_match])
                    session_key = f"{operator_ip}_{'_'.join(f'{s:08x}' for s in ssrcs_for_id)}"
                    
                    # 检查是否结束（任一SSRC收到BYE信号）
                    ended = any(s in self.ended_calls for s in [citizen_ssrc, perfect_match])
                    
                    self.call_sessions[session_key] = {
                        'operator_ip': operator_ip,
                        'citizen_ssrc': citizen_ssrc,
                        'hotline_ssrc': perfect_match,
                        'ended': ended,
                        'session_id': session_id
                    }
                    session_id += 1
                    
                    paired_in_this_ip.add(citizen_ssrc)
                    paired_in_this_ip.add(perfect_match)
                    paired_ssrcs.add(citizen_ssrc)
                    paired_ssrcs.add(perfect_match)
                    
                    logger.info(f"创建双向会话 {session_key}: citizen_ssrc={citizen_ssrc:08x}, hotline_ssrc={perfect_match:08x}, ended={ended}")
                else:
                    # 如果没有完美配对，尝试基于端口相近性的配对
                    best_match = None
                    best_score = -1
                    citizen_port = citizen_info['rtp_port']
                    
                    for hotline_ssrc in hotline_ssrcs:
                        if hotline_ssrc in paired_in_this_ip:
                            continue
                            
                        hotline_info = self.ssrc_info[hotline_ssrc]
                        hotline_port = hotline_info['rtp_port']
                        
                        # 计算匹配分数（端口接近度）
                        port_diff = abs(citizen_port - hotline_port)
                        score = 1000 - port_diff  # 端口越接近分数越高
                        
                        if score > best_score:
                            best_score = score
                            best_match = hotline_ssrc
                    
                    if best_match:
                        # 找到基于端口相近性的配对
                        ssrcs_for_id = sorted([citizen_ssrc, best_match])
                        session_key = f"{operator_ip}_{'_'.join(f'{s:08x}' for s in ssrcs_for_id)}"
                        
                        # 检查是否结束（任一SSRC收到BYE信号）
                        ended = any(s in self.ended_calls for s in [citizen_ssrc, best_match])
                        
                        self.call_sessions[session_key] = {
                            'operator_ip': operator_ip,
                            'citizen_ssrc': citizen_ssrc,
                            'hotline_ssrc': best_match,
                            'ended': ended,
                            'session_id': session_id
                        }
                        session_id += 1
                        
                        paired_in_this_ip.add(citizen_ssrc)
                        paired_in_this_ip.add(best_match)
                        paired_ssrcs.add(citizen_ssrc)
                        paired_ssrcs.add(best_match)
                        
                        logger.info(f"创建双向会话 {session_key} (端口相近): citizen_ssrc={citizen_ssrc:08x}, hotline_ssrc={best_match:08x}, ended={ended}")
            
            # 处理未配对的SSRC（单向流）
            remaining_ssrcs = [s for s in ssrcs if s not in paired_ssrcs]
            for ssrc in remaining_ssrcs:
                info = self.ssrc_info[ssrc]
                direction = info['direction']
                
                session_key = f"{operator_ip}_{ssrc:08x}"
                self.call_sessions[session_key] = {
                    'operator_ip': operator_ip,
                    'citizen_ssrc': ssrc if direction == 'citizen' else None,
                    'hotline_ssrc': ssrc if direction == 'hotline' else None,
                    'ended': ssrc in self.ended_calls,
                    'session_id': session_id
                }
                session_id += 1
                paired_ssrcs.add(ssrc)
                
                logger.info(f"创建单向会话 {session_key}: {direction} 方向，SSRC {ssrc:08x}")
        
        # 跨IP配对：寻找可能的跨接线员IP的配对
        self.find_cross_ip_pairs(session_id, paired_ssrcs)
        
        logger.info(f"总共创建了 {len(self.call_sessions)} 个会话")

    def apply_goodbye_to_sessions(self):
        """将RTCP Goodbye信号应用到相关会话"""
        logger.info("正在应用RTCP Goodbye信号到相关会话...")
        
        for bye_ssrc in self.ended_calls:
            # 找到包含此SSRC的所有会话
            for session_key, session in self.call_sessions.items():
                if bye_ssrc in [session.get('citizen_ssrc'), session.get('hotline_ssrc')]:
                    if not session['ended']:
                        session['ended'] = True
                        logger.info(f"会话 {session_key} 因SSRC {bye_ssrc} 的BYE信号被标记为结束")

    def decode_g711(self, audio_data, codec):
        """解码G711音频数据"""
        if codec == 'PCMU':
            # G711 μ-law解码
            return audioop.ulaw2lin(audio_data, 2)
        elif codec == 'PCMA':
            # G711 A-law解码
            return audioop.alaw2lin(audio_data, 2)
        else:
            return audio_data

    def save_session_audio(self, session_key, session):
        """保存会话音频文件"""
        operator_ip = session['operator_ip']
        citizen_ssrc = session.get('citizen_ssrc')
        hotline_ssrc = session.get('hotline_ssrc')
        
        # 创建会话文件夹（使用16进制SSRC）
        operator_ip_clean = operator_ip.replace('.', '_')
        ssrcs = [s for s in [citizen_ssrc, hotline_ssrc] if s is not None]
        ssrcs.sort()  # 排序确保一致性
        ssrcs_str = '_'.join(f'{s:08x}' for s in ssrcs)
        
        session_dir = self.output_dir / f"{operator_ip_clean}_{ssrcs_str}"
        session_dir.mkdir(exist_ok=True)
        
        # 保存市民音频（citizen.wav）
        if citizen_ssrc and citizen_ssrc in self.ssrc_streams:
            citizen_packets = self.ssrc_streams[citizen_ssrc]
            citizen_codec = self.ssrc_info[citizen_ssrc]['codec']
            citizen_file = session_dir / "citizen.wav"
            
            if citizen_packets:
                self._save_audio_to_file(citizen_packets, citizen_codec, citizen_file)
                logger.info(f"保存市民音频: {citizen_file}")
                logger.info(f"  - SSRC: {citizen_ssrc}")
                logger.info(f"  - 编码: {citizen_codec}")
                logger.info(f"  - 包数: {len(citizen_packets)}")
                logger.info(f"  - 时长: {len(citizen_packets) * 0.02:.2f}秒")
        
        # 保存接线员音频（hot-line.wav）
        if hotline_ssrc and hotline_ssrc in self.ssrc_streams:
            hotline_packets = self.ssrc_streams[hotline_ssrc]
            hotline_codec = self.ssrc_info[hotline_ssrc]['codec']
            hotline_file = session_dir / "hot-line.wav"
            
            if hotline_packets:
                self._save_audio_to_file(hotline_packets, hotline_codec, hotline_file)
                logger.info(f"保存接线员音频: {hotline_file}")
                logger.info(f"  - SSRC: {hotline_ssrc}")
                logger.info(f"  - 编码: {hotline_codec}")
                logger.info(f"  - 包数: {len(hotline_packets)}")
                logger.info(f"  - 时长: {len(hotline_packets) * 0.02:.2f}秒")
        
        # 保存会话状态
        status = "已结束" if session['ended'] else "进行中"
        logger.info(f"会话 {session_key} 状态: {status}")

    def _save_audio_to_file(self, packets, codec, output_file):
        """将音频包保存为WAV文件"""
        # 按序列号排序
        packets.sort(key=lambda x: x['sequence'])
        
        # 提取音频数据
        audio_data = b''
        for packet in packets:
            audio_data += packet['audio_data']
        
        # 解码G711
        pcm_data = self.decode_g711(audio_data, codec)
        
        # 保存为WAV文件
        with wave.open(str(output_file), 'wb') as wav_file:
            wav_file.setnchannels(1)  # 单声道
            wav_file.setsampwidth(2)  # 16位
            wav_file.setframerate(8000)  # 8kHz采样率
            wav_file.writeframes(pcm_data)

    def process_pcap(self):
        """处理PCAP文件"""
        logger.info(f"开始处理PCAP文件: {self.pcap_file}")
        
        # 步骤1: 提取RTP/RTCP流
        self.extract_rtp_rtcp_streams()
        
        # 步骤2: 查找双向配对
        self.find_bidirectional_pairs()
        
        # 步骤3: 应用Goodbye信号
        self.apply_goodbye_to_sessions()
        
        # 步骤4: 保存会话音频
        logger.info("正在保存会话音频...")
        for session_key, session in self.call_sessions.items():
            self.save_session_audio(session_key, session)
        
        logger.info("音频提取完成!")

def check_tshark():
    """检查tshark是否可用"""
    try:
        subprocess.run(['tshark', '-v'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def main():
    parser = argparse.ArgumentParser(description='从PCAP文件中按会话恢复热线平台音频')
    parser.add_argument('pcap_file', help='输入的PCAP文件路径')
    parser.add_argument('-o', '--output', default='./extracted_audio', 
                       help='输出目录 (默认: ./extracted_audio)')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 检查PCAP文件是否存在
    if not os.path.exists(args.pcap_file):
        logger.error(f"PCAP文件不存在: {args.pcap_file}")
        sys.exit(1)
    
    # 检查tshark是否可用
    if not check_tshark():
        logger.error("tshark未找到，请安装Wireshark或确保tshark在PATH中")
        sys.exit(1)
    
    # 开始处理
    recovery = AudioRecovery(args.pcap_file, args.output)
    recovery.process_pcap()

if __name__ == "__main__":
    main()
