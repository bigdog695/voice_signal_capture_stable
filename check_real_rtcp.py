#!/usr/bin/env python3
"""
真正的RTCP包检查工具
查找真正的RTCP包（通常在RTP端口+1上，且包长度较小）
"""

import subprocess
import struct
import sys
import argparse
from collections import defaultdict

def is_likely_rtp_packet(payload_hex, udp_length):
    """判断是否可能是RTP包（而不是RTCP包）"""
    # RTP包特征：
    # 1. 通常长度较长（包含音频数据）
    # 2. payload type通常是0-127范围内的音频编码
    
    if not payload_hex or len(payload_hex) < 8:
        return False
        
    try:
        payload_bytes = bytes.fromhex(payload_hex.replace(':', '')[:8])  # 只看前4字节
        if len(payload_bytes) < 4:
            return False
            
        # 检查RTP头
        version = (payload_bytes[0] >> 6) & 0x3
        payload_type = payload_bytes[1] & 0x7F
        
        # RTP特征：版本2，payload type是音频编码（0, 8等），包长度较大
        if version == 2 and payload_type in [0, 8] and int(udp_length) > 100:
            return True
            
    except:
        pass
        
    return False

def parse_rtcp_packet_careful(payload_hex):
    """仔细解析RTCP包，排除RTP包"""
    if not payload_hex:
        return None
        
    try:
        payload_bytes = bytes.fromhex(payload_hex.replace(':', ''))
        
        if len(payload_bytes) < 8:  # RTCP包至少需要8字节
            return None
            
        # RTCP头格式
        byte0 = payload_bytes[0]
        version = (byte0 >> 6) & 0x3
        padding = (byte0 >> 5) & 0x1
        rc = byte0 & 0x0F
        
        packet_type = payload_bytes[1]
        length = struct.unpack('!H', payload_bytes[2:4])[0]
        
        # RTCP包类型检查：只接受已知的RTCP包类型
        valid_rtcp_types = [200, 201, 202, 203, 204]  # SR, RR, SDES, BYE, APP
        
        if version != 2 or packet_type not in valid_rtcp_types:
            return None
            
        # 长度合理性检查：RTCP包长度通常较小
        expected_length = (length + 1) * 4  # RTCP长度字段 * 4字节
        if expected_length > 1000 or expected_length < 8:  # 合理的RTCP包大小
            return None
            
        result = {
            'version': version,
            'padding': padding,
            'rc': rc,
            'packet_type': packet_type,
            'length': length,
            'expected_bytes': expected_length,
            'actual_bytes': len(payload_bytes),
            'raw_hex': payload_hex[:200]  # 显示更多hex数据
        }
        
        # 根据包类型解析SSRC
        if len(payload_bytes) >= 8:
            ssrc = struct.unpack('!I', payload_bytes[4:8])[0]
            result['ssrc'] = ssrc
            
        # 包类型名称
        type_names = {
            200: 'SR (Sender Report)',
            201: 'RR (Receiver Report)',
            202: 'SDES (Source Description)',
            203: 'BYE (Goodbye)',
            204: 'APP (Application Defined)'
        }
        result['type_name'] = type_names.get(packet_type, f'Unknown ({packet_type})')
        
        if packet_type == 203:
            result['is_bye'] = True
            
        return result
        
    except Exception as e:
        return None

def check_real_rtcp_packets(pcap_file):
    """检查pcap文件中的真正RTCP包"""
    print(f"检查PCAP文件中的真正RTCP包: {pcap_file}")
    print("=" * 80)
    
    # 使用tshark提取所有UDP包
    cmd = [
        'tshark', '-r', pcap_file,
        '-Y', 'udp and (ip.src == 192.168.0.201 or ip.dst == 192.168.0.201)',
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-e', 'udp.length',
        '-e', 'udp.payload',
        '-E', 'header=y',
        '-E', 'separator=|'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split('\n')
        
        if len(lines) <= 1:
            print("未找到UDP包")
            return
            
        rtcp_stats = defaultdict(int)
        bye_packets = []
        real_rtcp_packets = []
        rtp_packets = 0
        total_udp = 0
        
        for line in lines[1:]:  # 跳过标题行
            if not line.strip():
                continue
                
            fields = line.split('|')
            if len(fields) >= 7:
                frame_num, src_ip, dst_ip, src_port, dst_port, udp_len, payload = fields[:7]
                total_udp += 1
                
                if payload:
                    # 先检查是否是RTP包
                    if is_likely_rtp_packet(payload, udp_len):
                        rtp_packets += 1
                        continue
                    
                    # 尝试解析为RTCP
                    rtcp_info = parse_rtcp_packet_careful(payload)
                    
                    if rtcp_info:
                        real_rtcp_packets.append({
                            'frame': frame_num,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'udp_len': udp_len,
                            'rtcp_info': rtcp_info
                        })
                        
                        rtcp_stats[rtcp_info['packet_type']] += 1
                        
                        # 特别关注BYE包
                        if rtcp_info.get('is_bye'):
                            bye_packets.append({
                                'frame': frame_num,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'ssrc': rtcp_info.get('ssrc'),
                                'rtcp_info': rtcp_info
                            })
        
        print(f"总UDP包数: {total_udp}")
        print(f"RTP包数: {rtp_packets}")
        print(f"真正的RTCP包数: {len(real_rtcp_packets)}")
        print()
        
        if rtcp_stats:
            print("真正的RTCP包类型统计:")
            print("-" * 40)
            for ptype, count in sorted(rtcp_stats.items()):
                type_name = {
                    200: 'SR (Sender Report)',
                    201: 'RR (Receiver Report)', 
                    202: 'SDES (Source Description)',
                    203: 'BYE (Goodbye)',
                    204: 'APP (Application Defined)'
                }.get(ptype, f'Unknown ({ptype})')
                print(f"  {type_name}: {count}")
        else:
            print("未找到真正的RTCP包")
        
        print()
        print(f"BYE包数量: {len(bye_packets)}")
        
        if bye_packets:
            print("\nBYE包详情:")
            print("-" * 80)
            for i, bye in enumerate(bye_packets):
                print(f"BYE包 #{i+1}:")
                print(f"  帧号: {bye['frame']}")
                print(f"  源IP:端口: {bye['src_ip']}:{bye['src_port']}")
                print(f"  目标IP:端口: {bye['dst_ip']}:{bye['dst_port']}")
                print(f"  SSRC: {bye['ssrc']}")
                print(f"  原始数据: {bye['rtcp_info']['raw_hex']}")
                print()
        
        # 显示一些真正RTCP包的详情
        if real_rtcp_packets:
            print(f"\n所有真正RTCP包详情:")
            print("-" * 80)
            for i, pkt in enumerate(real_rtcp_packets):
                rtcp = pkt['rtcp_info']
                print(f"RTCP包 #{i+1}:")
                print(f"  帧号: {pkt['frame']}")
                print(f"  源IP:端口: {pkt['src_ip']}:{pkt['src_port']}")
                print(f"  目标IP:端口: {pkt['dst_ip']}:{pkt['dst_port']}")
                print(f"  UDP长度: {pkt['udp_len']}")
                print(f"  包类型: {rtcp.get('type_name', 'Unknown')}")
                print(f"  版本: {rtcp.get('version')}")
                print(f"  长度: {rtcp.get('length')} (声明) -> {rtcp.get('expected_bytes')} 字节")
                print(f"  实际长度: {rtcp.get('actual_bytes')} 字节")
                if 'ssrc' in rtcp:
                    print(f"  SSRC: {rtcp['ssrc']}")
                print(f"  原始数据: {rtcp['raw_hex']}")
                print()
            
    except subprocess.CalledProcessError as e:
        print(f"tshark执行失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检查PCAP文件中的真正RTCP包')
    parser.add_argument('pcap_file', help='输入的PCAP文件路径')
    
    args = parser.parse_args()
    
    if not args.pcap_file:
        print("请指定PCAP文件路径")
        sys.exit(1)
        
    check_real_rtcp_packets(args.pcap_file)

if __name__ == "__main__":
    main()
