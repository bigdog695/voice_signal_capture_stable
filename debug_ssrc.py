#!/usr/bin/env python3

import subprocess
import struct
import sys

def parse_rtp_packet(payload_hex):
    """解析RTP包"""
    try:
        # 移除冒号并转换为字节
        payload_bytes = bytes.fromhex(payload_hex.replace(':', ''))
        
        if len(payload_bytes) < 12:
            return None
            
        # 解析RTP头
        byte0 = payload_bytes[0]
        version = (byte0 >> 6) & 0x3
        padding = (byte0 >> 5) & 0x1
        extension = (byte0 >> 4) & 0x1
        cc = byte0 & 0xF
        
        byte1 = payload_bytes[1]
        marker = (byte1 >> 7) & 0x1
        payload_type = byte1 & 0x7F
        
        if version != 2:
            return None
            
        if payload_type not in [0, 8]:  # 只处理G711U和G711A
            return None
            
        # 提取SSRC
        ssrc = struct.unpack('!I', payload_bytes[8:12])[0]
        
        return {
            'ssrc': ssrc,
            'payload_type': payload_type,
            'version': version
        }
    except Exception as e:
        return None

def main():
    pcap_file = "/home/bigdog695/work/sip_rtp_1h.pcap"
    target_ssrc = 0x069f17fb
    
    print(f"正在查找SSRC {target_ssrc:08x} 的所有包...")
    
    # 使用tshark提取UDP包
    cmd = [
        'tshark', '-r', pcap_file,
        '-Y', 'udp and (ip.src == 192.168.0.201 or ip.dst == 192.168.0.201)',
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'ip.src',
        '-e', 'ip.dst', 
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-e', 'udp.payload',
        '-E', 'separator=|'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    lines = result.stdout.strip().split('\n')
    
    found_packets = []
    
    for line in lines:
        if not line.strip():
            continue
            
        fields = line.split('|')
        if len(fields) >= 6:
            frame_num, src_ip, dst_ip, src_port, dst_port, payload = fields[:6]
            
            if payload:
                rtp_info = parse_rtp_packet(payload)
                if rtp_info and rtp_info['ssrc'] == target_ssrc:
                    found_packets.append({
                        'frame': frame_num,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'ssrc': rtp_info['ssrc'],
                        'payload_type': rtp_info['payload_type']
                    })
                    
                    if len(found_packets) <= 5:  # 只显示前5个
                        print(f"Frame {frame_num}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, SSRC: {rtp_info['ssrc']:08x}, PT: {rtp_info['payload_type']}")
    
    print(f"\n总共找到 {len(found_packets)} 个包含SSRC {target_ssrc:08x} 的包")
    
    if found_packets:
        # 统计不同的网络连接组合
        connections = {}
        for packet in found_packets:
            conn_key = f"{packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']}"
            if conn_key not in connections:
                connections[conn_key] = []
            connections[conn_key].append(packet['frame'])
        
        print(f"\n发现 {len(connections)} 种不同的网络连接:")
        for conn, frames in connections.items():
            print(f"  {conn}: {len(frames)} 个包 (例如Frame: {frames[0]})")
            
        # 检查Frame 2442519是否在其中
        frame_2442519_conn = None
        for conn, frames in connections.items():
            if '2442519' in frames:
                frame_2442519_conn = conn
                break
        
        if frame_2442519_conn:
            print(f"\nFrame 2442519 属于连接: {frame_2442519_conn}")
        else:
            print(f"\nFrame 2442519 不在找到的包中")

if __name__ == "__main__":
    main()
