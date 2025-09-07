#!/usr/bin/env python3
"""
RTCP包检查工具
专门检查pcap文件中的RTCP包，特别是BYE包（Packet Type=203）
"""

import subprocess
import struct
import sys
import argparse
from collections import defaultdict

def parse_rtcp_packet_detailed(payload_hex):
    """详细解析RTCP包"""
    if not payload_hex:
        return None
        
    try:
        payload_bytes = bytes.fromhex(payload_hex.replace(':', ''))
        
        if len(payload_bytes) < 4:
            return None
            
        # RTCP头格式详细解析
        # 字节0: V(2位) + P(1位) + X(1位) + RC/SC(4位)
        # 字节1: PT(8位) - Packet Type
        # 字节2-3: Length
        
        byte0 = payload_bytes[0]
        version = (byte0 >> 6) & 0x3
        padding = (byte0 >> 5) & 0x1
        extension = (byte0 >> 4) & 0x1
        rc = byte0 & 0x0F
        
        packet_type = payload_bytes[1]
        length = struct.unpack('!H', payload_bytes[2:4])[0]
        
        result = {
            'version': version,
            'padding': padding,
            'extension': extension,
            'rc': rc,
            'packet_type': packet_type,
            'length': length,
            'raw_length': len(payload_bytes),
            'raw_hex': payload_hex[:100] + ('...' if len(payload_hex) > 100 else '')  # 显示前50字节的hex
        }
        
        # 根据包类型解析
        if packet_type == 200:  # SR
            result['type_name'] = 'SR (Sender Report)'
            if len(payload_bytes) >= 8:
                ssrc = struct.unpack('!I', payload_bytes[4:8])[0]
                result['ssrc'] = ssrc
        elif packet_type == 201:  # RR
            result['type_name'] = 'RR (Receiver Report)'
            if len(payload_bytes) >= 8:
                ssrc = struct.unpack('!I', payload_bytes[4:8])[0]
                result['ssrc'] = ssrc
        elif packet_type == 202:  # SDES
            result['type_name'] = 'SDES (Source Description)'
            if len(payload_bytes) >= 8:
                ssrc = struct.unpack('!I', payload_bytes[4:8])[0]
                result['ssrc'] = ssrc
        elif packet_type == 203:  # BYE
            result['type_name'] = 'BYE (Goodbye)'
            if len(payload_bytes) >= 8:
                ssrc = struct.unpack('!I', payload_bytes[4:8])[0]
                result['ssrc'] = ssrc
                result['is_bye'] = True
        elif packet_type == 204:  # APP
            result['type_name'] = 'APP (Application Defined)'
            if len(payload_bytes) >= 8:
                ssrc = struct.unpack('!I', payload_bytes[4:8])[0]
                result['ssrc'] = ssrc
        else:
            result['type_name'] = f'Unknown ({packet_type})'
            
        return result
        
    except Exception as e:
        return {'error': str(e), 'raw_hex': payload_hex[:100]}

def check_rtcp_packets(pcap_file):
    """检查pcap文件中的RTCP包"""
    print(f"检查PCAP文件中的RTCP包: {pcap_file}")
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
        potential_rtcp = []
        total_udp = 0
        
        for line in lines[1:]:  # 跳过标题行
            if not line.strip():
                continue
                
            fields = line.split('|')
            if len(fields) >= 7:
                frame_num, src_ip, dst_ip, src_port, dst_port, udp_len, payload = fields[:7]
                total_udp += 1
                
                if payload:
                    # 尝试解析为RTCP
                    rtcp_info = parse_rtcp_packet_detailed(payload)
                    
                    if rtcp_info and not rtcp_info.get('error'):
                        # 检查是否是有效的RTCP包（版本=2）
                        if rtcp_info.get('version') == 2:
                            potential_rtcp.append({
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
        print(f"潜在RTCP包数: {len(potential_rtcp)}")
        print()
        
        print("RTCP包类型统计:")
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
        
        print()
        print(f"BYE包数量: {len(bye_packets)}")
        
        if bye_packets:
            print("\nBYE包详情:")
            print("-" * 80)
            for i, bye in enumerate(bye_packets[:10]):  # 只显示前10个
                print(f"BYE包 #{i+1}:")
                print(f"  帧号: {bye['frame']}")
                print(f"  源IP:端口: {bye['src_ip']}:{bye['src_port']}")
                print(f"  目标IP:端口: {bye['dst_ip']}:{bye['dst_port']}")
                print(f"  SSRC: {bye['ssrc']}")
                print(f"  原始数据: {bye['rtcp_info']['raw_hex']}")
                print()
                
            if len(bye_packets) > 10:
                print(f"... 还有 {len(bye_packets) - 10} 个BYE包")
        
        # 显示一些潜在RTCP包的详情
        print(f"\n前10个潜在RTCP包详情:")
        print("-" * 80)
        for i, pkt in enumerate(potential_rtcp[:10]):
            rtcp = pkt['rtcp_info']
            print(f"RTCP包 #{i+1}:")
            print(f"  帧号: {pkt['frame']}")
            print(f"  源IP:端口: {pkt['src_ip']}:{pkt['src_port']}")
            print(f"  目标IP:端口: {pkt['dst_ip']}:{pkt['dst_port']}")
            print(f"  包类型: {rtcp.get('type_name', 'Unknown')}")
            print(f"  版本: {rtcp.get('version')}")
            print(f"  长度: {rtcp.get('length')} (声明) / {rtcp.get('raw_length')} (实际)")
            if 'ssrc' in rtcp:
                print(f"  SSRC: {rtcp['ssrc']}")
            print(f"  原始数据: {rtcp['raw_hex']}")
            print()
            
    except subprocess.CalledProcessError as e:
        print(f"tshark执行失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检查PCAP文件中的RTCP包')
    parser.add_argument('pcap_file', help='输入的PCAP文件路径')
    
    args = parser.parse_args()
    
    if not args.pcap_file:
        print("请指定PCAP文件路径")
        sys.exit(1)
        
    check_rtcp_packets(args.pcap_file)

if __name__ == "__main__":
    main()
