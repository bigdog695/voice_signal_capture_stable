#!/usr/bin/env python3
"""
热线平台PCAP文件音频恢复脚本
按SSRC聚类RTP/RTCP流并恢复G711音频数据
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
    def __init__(self, pcap_file, output_dir="./extracted_audio", ip_blacklist=None):
        self.pcap_file = pcap_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.hotline_server_ip = "192.168.0.201"
        self.ssrc_streams = defaultdict(list)  # 按SSRC聚类
        self.ssrc_info = {}  # 存储每个SSRC的基本信息
        self.ended_calls = set()  # 存储已结束的通话SSRC
        
        # 设置IP黑名单，默认屏蔽118、119、121结尾的IP
        if ip_blacklist is None:
            self.ip_blacklist = ['118', '119', '121']
        else:
            self.ip_blacklist = ip_blacklist
        
    def parse_rtp_packet(self, payload_hex):
        """解析RTP包"""
        if not payload_hex or len(payload_hex) < 24:  # RTP头至少12字节
            return None
            
        try:
            payload_bytes = bytes.fromhex(payload_hex.replace(':', ''))
            
            if len(payload_bytes) < 12:
                return None
                
            # 解析RTP头
            # 字节0: V(2位) + P(1位) + X(1位) + CC(4位)
            # 字节1: M(1位) + PT(7位)
            # 字节2-3: 序列号
            # 字节4-7: 时间戳
            # 字节8-11: SSRC
            
            version = (payload_bytes[0] >> 6) & 0x3
            padding = (payload_bytes[0] >> 5) & 0x1
            extension = (payload_bytes[0] >> 4) & 0x1
            cc = payload_bytes[0] & 0x0F
            
            marker = (payload_bytes[1] >> 7) & 0x1
            payload_type = payload_bytes[1] & 0x7F
            
            sequence = struct.unpack('!H', payload_bytes[2:4])[0]
            timestamp = struct.unpack('!I', payload_bytes[4:8])[0]
            ssrc = struct.unpack('!I', payload_bytes[8:12])[0]
            
            # 检查RTP版本和payload type
            if version == 2 and payload_type in [0, 8]:  # G711U或G711A
                return {
                    'type': 'RTP',
                    'version': version,
                    'padding': padding,
                    'extension': extension,
                    'cc': cc,
                    'marker': marker,
                    'payload_type': payload_type,
                    'sequence': sequence,
                    'timestamp': timestamp,
                    'ssrc': ssrc,
                    'payload_bytes': payload_bytes
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
        
        # 硬编码的IP黑名单
        blacklisted_ips = [
            '192.168.0.118',
            '192.168.0.119', 
            '192.168.0.121'
        ]
        
        # 直接检查完整IP地址
        if ip in blacklisted_ips:
            return True
 
        return False
        
    def extract_rtp_rtcp_streams(self):
        """提取RTP/RTCP流信息"""
        logger.info("正在提取RTP/RTCP流信息...")
        
        # 使用tshark提取UDP包
        cmd = [
            'tshark', '-r', self.pcap_file,
            '-Y', f'udp and (ip.src == {self.hotline_server_ip} or ip.dst == {self.hotline_server_ip})',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time_epoch',
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
                logger.warning("未找到UDP包")
                return
                
            rtp_count = 0
            rtcp_count = 0
            
            for line in lines[1:]:  # 跳过标题行
                if not line.strip():
                    continue
                    
                fields = line.split('|')
                if len(fields) >= 7:
                    (frame_num, timestamp, src_ip, dst_ip, src_port, dst_port, payload) = fields[:7]
                    
                    # 过滤掉无效的包
                    if (src_ip == self.hotline_server_ip and dst_ip == self.hotline_server_ip) or \
                       (src_ip != self.hotline_server_ip and dst_ip != self.hotline_server_ip):
                        continue
                    
                    # IP黑名单过滤
                    if self.is_ip_blacklisted(src_ip) or self.is_ip_blacklisted(dst_ip):
                        continue
                    
                    # 尝试解析为RTP包
                    rtp_info = self.parse_rtp_packet(payload)
                    if rtp_info:
                        ssrc = rtp_info['ssrc']
                        
                        # 确定音频方向
                        direction = "citizen" if src_ip == self.hotline_server_ip else "hotline"
                        peer_ip = dst_ip if src_ip == self.hotline_server_ip else src_ip
                        
                        packet_info = {
                            'frame': int(frame_num) if frame_num.isdigit() else 0,
                            'timestamp': float(timestamp) if timestamp else 0,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': int(src_port) if src_port.isdigit() else 0,
                            'dst_port': int(dst_port) if dst_port.isdigit() else 0,
                            'direction': direction,
                            'peer_ip': peer_ip,
                            'rtp_info': rtp_info
                        }
                        
                        self.ssrc_streams[ssrc].append(packet_info)
                        
                        # 记录SSRC基本信息
                        if ssrc not in self.ssrc_info:
                            self.ssrc_info[ssrc] = {
                                'direction': direction,
                                'peer_ip': peer_ip,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'payload_type': rtp_info['payload_type'],
                                'rtp_port': packet_info['src_port'] if direction == "citizen" else packet_info['dst_port']
                            }
                            
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
            logger.error(f"提取RTP/RTCP流失败: {e}")
            
    def extract_rtp_payload(self, rtp_info):
        """从RTP包中提取音频负载"""
        try:
            payload_bytes = rtp_info['payload_bytes']
            
            if len(payload_bytes) < 12:
                return b''
                
            # 计算RTP头长度
            cc = rtp_info['cc']
            header_length = 12 + (cc * 4)  # 基本头12字节 + CSRC
            
            # 检查扩展头
            if rtp_info['extension']:
                if len(payload_bytes) < header_length + 4:
                    return b''
                ext_length = struct.unpack('!H', payload_bytes[header_length+2:header_length+4])[0]
                header_length += 4 + (ext_length * 4)
                
            # 提取音频负载
            if len(payload_bytes) > header_length:
                return payload_bytes[header_length:]
                
        except Exception as e:
            logger.debug(f"提取RTP负载失败: {e}")
            
        return b''
        
    def decode_g711_payload(self, payload_bytes, codec_type):
        """解码G711音频负载"""
        if not payload_bytes:
            return b''
            
        try:
            if codec_type == 0:  # G711U (μ-law/PCMU)
                return audioop.ulaw2lin(payload_bytes, 2)
            elif codec_type == 8:  # G711A (A-law/PCMA)
                return audioop.alaw2lin(payload_bytes, 2)
            else:
                logger.warning(f"不支持的编码类型: {codec_type}")
                return b''
                
        except Exception as e:
            logger.error(f"解码音频负载失败: {e}")
            return b''
            
    def save_audio_stream(self, ssrc, stream_packets, output_file, sample_rate=8000):
        """保存音频流为WAV文件"""
        if not stream_packets:
            return
            
        # 按序列号排序RTP包
        rtp_packets = [p for p in stream_packets if 'rtp_info' in p]
        rtp_packets.sort(key=lambda x: x['rtp_info']['sequence'])
        
        if not rtp_packets:
            logger.warning(f"SSRC {ssrc} 没有有效的RTP包")
            return
            
        audio_data = b''
        payload_type = rtp_packets[0]['rtp_info']['payload_type']
        
        for packet in rtp_packets:
            # 提取RTP负载
            payload_bytes = self.extract_rtp_payload(packet['rtp_info'])
            
            if payload_bytes:
                # 解码音频
                decoded = self.decode_g711_payload(payload_bytes, payload_type)
                audio_data += decoded
                
        if not audio_data:
            logger.warning(f"SSRC {ssrc} 没有有效的音频数据")
            return
            
        try:
            with wave.open(str(output_file), 'wb') as wav_file:
                wav_file.setnchannels(1)  # 单声道
                wav_file.setsampwidth(2)  # 16位
                wav_file.setframerate(sample_rate)  # 8kHz采样率
                wav_file.writeframes(audio_data)
                
            duration = len(audio_data) / (2 * sample_rate)  # 计算时长（秒）
            codec_name = "PCMU" if payload_type == 0 else "PCMA"
            call_status = "已结束" if ssrc in self.ended_calls else "进行中"
            
            logger.info(f"已保存音频文件: {output_file}")
            logger.info(f"  - SSRC: {ssrc}")
            logger.info(f"  - 编码: {codec_name}")
            logger.info(f"  - 时长: {duration:.2f}秒")
            logger.info(f"  - 大小: {len(audio_data)} 字节")
            logger.info(f"  - RTP包数: {len(rtp_packets)}")
            logger.info(f"  - 状态: {call_status}")
            
        except Exception as e:
            logger.error(f"保存音频文件失败 {output_file}: {e}")
            
    def process_pcap(self):
        """处理PCAP文件的主函数"""
        logger.info(f"开始处理PCAP文件: {self.pcap_file}")
        
        # 提取RTP/RTCP流
        self.extract_rtp_rtcp_streams()
        
        if not self.ssrc_streams:
            logger.error("未找到有效的RTP流")
            return
            
        # 按SSRC处理音频流
        for ssrc, packets in self.ssrc_streams.items():
            if not packets:
                continue
                
            ssrc_info = self.ssrc_info.get(ssrc, {})
            direction = ssrc_info.get('direction', 'unknown')
            peer_ip = ssrc_info.get('peer_ip', 'unknown')
            src_ip = ssrc_info.get('src_ip', 'unknown')
            dst_ip = ssrc_info.get('dst_ip', 'unknown')
            
            # 创建包含IP信息的输出目录名
            src_ip_clean = src_ip.replace('.', '_')
            dst_ip_clean = dst_ip.replace('.', '_')
            ssrc_dir = self.output_dir / f"ssrc_{ssrc}_{src_ip_clean}_to_{dst_ip_clean}"
            ssrc_dir.mkdir(exist_ok=True)
            
            # 生成文件名
            direction_name = "citizen" if direction == "citizen" else "hotline"
            audio_file = ssrc_dir / f"{direction_name}.wav"
            
            logger.info(f"处理SSRC {ssrc}: {direction} ({src_ip} -> {dst_ip}) ({len(packets)} 包)")
            self.save_audio_stream(ssrc, packets, audio_file)
                
        logger.info("音频提取完成!")

def main():
    parser = argparse.ArgumentParser(description='从PCAP文件中按SSRC恢复热线平台音频')
    parser.add_argument('pcap_file', help='输入的PCAP文件路径')
    parser.add_argument('-o', '--output', default='./extracted_audio', 
                       help='输出目录 (默认: ./extracted_audio)')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    parser.add_argument('--ip-blacklist', nargs='*', default=['118', '119', '121'],
                       help='IP黑名单后缀 (默认: 118 119 121)')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    if not os.path.exists(args.pcap_file):
        logger.error(f"PCAP文件不存在: {args.pcap_file}")
        sys.exit(1)
        
    # 检查tshark是否可用
    try:
        subprocess.run(['tshark', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("tshark未安装或不可用，请安装Wireshark")
        sys.exit(1)
        
    recovery = AudioRecovery(args.pcap_file, args.output, args.ip_blacklist)
    recovery.process_pcap()

if __name__ == "__main__":
    main()