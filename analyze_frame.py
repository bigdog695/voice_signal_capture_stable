#!/usr/bin/env python3
"""
分析特定帧号的包
"""

import subprocess
import struct
import sys
import argparse

def analyze_specific_frame(pcap_file, frame_number):
    """分析特定帧号的包"""
    print(f"分析PCAP文件中的帧号 {frame_number}")
    print("=" * 80)
    
    # 使用tshark提取特定帧
    cmd = [
        'tshark', '-r', pcap_file,
        '-Y', f'frame.number == {frame_number}',
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
            print(f"未找到帧号 {frame_number}")
            return
            
        for line in lines[1:]:  # 跳过标题行
            if not line.strip():
                continue
                
            fields = line.split('|')
            if len(fields) >= 7:
                frame_num, src_ip, dst_ip, src_port, dst_port, udp_len, payload = fields[:7]
                
                print(f"帧号: {frame_num}")
                print(f"源IP:端口: {src_ip}:{src_port}")
                print(f"目标IP:端口: {dst_ip}:{dst_port}")
                print(f"UDP长度: {udp_len}")
                print(f"原始payload: {payload[:200]}{'...' if len(payload) > 200 else ''}")
                print()
                
                if payload:
                    analyze_payload_detailed(payload)
                    
    except subprocess.CalledProcessError as e:
        print(f"tshark执行失败: {e}")

def analyze_payload_detailed(payload_hex):
    """详细分析payload"""
    print("详细payload分析:")
    print("-" * 40)
    
    if not payload_hex:
        print("无payload数据")
        return
        
    try:
        payload_bytes = bytes.fromhex(payload_hex.replace(':', ''))
        print(f"Payload长度: {len(payload_bytes)} 字节")
        
        if len(payload_bytes) < 4:
            print("Payload太短，无法解析")
            return
            
        # 十六进制显示
        print("\n十六进制数据 (前64字节):")
        hex_data = payload_hex.replace(':', '')
        for i in range(0, min(128, len(hex_data)), 32):
            chunk = hex_data[i:i+32]
            formatted = ' '.join(chunk[j:j+2] for j in range(0, len(chunk), 2))
            print(f"{i//2:04x}: {formatted}")
        
        # 尝试解析为RTP
        print("\n=== RTP解析尝试 ===")
        analyze_as_rtp(payload_bytes)
        
        # 尝试解析为RTCP
        print("\n=== RTCP解析尝试 ===")
        analyze_as_rtcp(payload_bytes)
        
        # 尝试解析为复合RTCP包
        print("\n=== 复合RTCP包解析 ===")
        analyze_compound_rtcp(payload_bytes)
        
    except Exception as e:
        print(f"解析失败: {e}")

def analyze_as_rtp(payload_bytes):
    """尝试作为RTP包解析"""
    try:
        if len(payload_bytes) < 12:
            print("长度不足，不是RTP包")
            return
            
        # RTP头解析
        byte0 = payload_bytes[0]
        version = (byte0 >> 6) & 0x3
        padding = (byte0 >> 5) & 0x1
        extension = (byte0 >> 4) & 0x1
        cc = byte0 & 0x0F
        
        byte1 = payload_bytes[1]
        marker = (byte1 >> 7) & 0x1
        payload_type = byte1 & 0x7F
        
        sequence = struct.unpack('!H', payload_bytes[2:4])[0]
        timestamp = struct.unpack('!I', payload_bytes[4:8])[0]
        ssrc = struct.unpack('!I', payload_bytes[8:12])[0]
        
        print(f"RTP版本: {version}")
        print(f"填充: {padding}")
        print(f"扩展: {extension}")
        print(f"CSRC计数: {cc}")
        print(f"标记: {marker}")
        print(f"负载类型: {payload_type}")
        print(f"序列号: {sequence}")
        print(f"时间戳: {timestamp}")
        print(f"SSRC: {ssrc} (0x{ssrc:08x})")
        
        if version == 2 and payload_type in [0, 8]:
            print("✓ 看起来像有效的RTP包")
        else:
            print("✗ 不像标准的RTP包")
            
    except Exception as e:
        print(f"RTP解析失败: {e}")

def analyze_as_rtcp(payload_bytes):
    """尝试作为RTCP包解析"""
    try:
        if len(payload_bytes) < 8:
            print("长度不足，不是RTCP包")
            return
            
        # RTCP头解析
        byte0 = payload_bytes[0]
        version = (byte0 >> 6) & 0x3
        padding = (byte0 >> 5) & 0x1
        rc = byte0 & 0x1F
        
        packet_type = payload_bytes[1]
        length = struct.unpack('!H', payload_bytes[2:4])[0]
        
        print(f"RTCP版本: {version}")
        print(f"填充: {padding}")
        print(f"RC/SC: {rc}")
        print(f"包类型: {packet_type}")
        print(f"长度字段: {length}")
        print(f"预期字节数: {(length + 1) * 4}")
        
        # 包类型名称
        type_names = {
            200: 'SR (Sender Report)',
            201: 'RR (Receiver Report)',
            202: 'SDES (Source Description)',
            203: 'BYE (Goodbye)',
            204: 'APP (Application Defined)'
        }
        
        type_name = type_names.get(packet_type, f'Unknown ({packet_type})')
        print(f"包类型名称: {type_name}")
        
        if len(payload_bytes) >= 8:
            ssrc = struct.unpack('!I', payload_bytes[4:8])[0]
            print(f"SSRC: {ssrc} (0x{ssrc:08x})")
        
        # 特别分析BYE包
        if packet_type == 203:
            print("\n*** BYE包详细分析 ***")
            analyze_bye_packet(payload_bytes)
        
        if version == 2 and packet_type in [200, 201, 202, 203, 204]:
            print("✓ 看起来像有效的RTCP包")
        else:
            print("✗ 不像标准的RTCP包")
            
    except Exception as e:
        print(f"RTCP解析失败: {e}")

def analyze_bye_packet(payload_bytes):
    """详细分析BYE包"""
    try:
        if len(payload_bytes) < 8:
            print("BYE包长度不足")
            return
            
        byte0 = payload_bytes[0]
        sc = byte0 & 0x1F  # Source Count
        length = struct.unpack('!H', payload_bytes[2:4])[0]
        
        print(f"源计数 (SC): {sc}")
        print(f"包含的SSRC数量: {sc}")
        
        # 读取SSRC列表
        ssrc_list = []
        for i in range(sc):
            if len(payload_bytes) >= 8 + (i + 1) * 4:
                ssrc = struct.unpack('!I', payload_bytes[4 + i * 4:8 + i * 4])[0]
                ssrc_list.append(ssrc)
                print(f"SSRC #{i+1}: {ssrc} (0x{ssrc:08x})")
        
        # 检查是否有原因字符串
        reason_offset = 4 + sc * 4
        if len(payload_bytes) > reason_offset:
            if len(payload_bytes) >= reason_offset + 1:
                reason_length = payload_bytes[reason_offset]
                print(f"原因长度: {reason_length}")
                
                if reason_length > 0 and len(payload_bytes) >= reason_offset + 1 + reason_length:
                    reason_text = payload_bytes[reason_offset + 1:reason_offset + 1 + reason_length]
                    try:
                        reason_str = reason_text.decode('utf-8', errors='ignore')
                        print(f"原因文本: '{reason_str}'")
                    except:
                        print(f"原因数据: {reason_text.hex()}")
        
    except Exception as e:
        print(f"BYE包分析失败: {e}")

def analyze_compound_rtcp(payload_bytes):
    """解析复合RTCP包"""
    print("解析复合RTCP包:")
    print("-" * 40)
    
    offset = 0
    packet_num = 1
    
    while offset < len(payload_bytes):
        if offset + 4 > len(payload_bytes):
            print(f"剩余数据不足4字节，停止解析")
            break
            
        try:
            # 解析RTCP头
            byte0 = payload_bytes[offset]
            version = (byte0 >> 6) & 0x3
            padding = (byte0 >> 5) & 0x1
            rc = byte0 & 0x1F
            
            packet_type = payload_bytes[offset + 1]
            length = struct.unpack('!H', payload_bytes[offset + 2:offset + 4])[0]
            packet_length = (length + 1) * 4  # 实际字节数
            
            print(f"\n--- RTCP包 #{packet_num} (偏移 {offset}) ---")
            print(f"版本: {version}")
            print(f"填充: {padding}")
            print(f"RC/SC: {rc}")
            print(f"包类型: {packet_type}")
            print(f"长度字段: {length}")
            print(f"包长度: {packet_length} 字节")
            
            # 包类型名称
            type_names = {
                200: 'SR (Sender Report)',
                201: 'RR (Receiver Report)',
                202: 'SDES (Source Description)',
                203: 'BYE (Goodbye)',
                204: 'APP (Application Defined)'
            }
            
            type_name = type_names.get(packet_type, f'Unknown ({packet_type})')
            print(f"包类型名称: {type_name}")
            
            # 显示这个包的原始数据
            packet_data = payload_bytes[offset:offset + min(packet_length, len(payload_bytes) - offset)]
            hex_str = ' '.join(f'{b:02x}' for b in packet_data[:32])
            if len(packet_data) > 32:
                hex_str += '...'
            print(f"原始数据: {hex_str}")
            
            # 如果有SSRC字段
            if offset + 8 <= len(payload_bytes):
                ssrc = struct.unpack('!I', payload_bytes[offset + 4:offset + 8])[0]
                print(f"SSRC: {ssrc} (0x{ssrc:08x})")
            
            # 特别处理BYE包
            if packet_type == 203:
                print("*** 找到BYE包! ***")
                bye_data = payload_bytes[offset:offset + packet_length]
                analyze_bye_packet(bye_data)
            
            # 移动到下一个包
            if packet_length == 0:
                print("包长度为0，停止解析")
                break
                
            offset += packet_length
            packet_num += 1
            
            # 安全检查
            if packet_num > 10:
                print("解析了太多包，可能有错误，停止")
                break
                
        except Exception as e:
            print(f"解析RTCP包 #{packet_num} 失败: {e}")
            break
    
    print(f"\n总共解析了 {packet_num - 1} 个RTCP包")

def main():
    parser = argparse.ArgumentParser(description='分析特定帧号的包')
    parser.add_argument('pcap_file', help='输入的PCAP文件路径')
    parser.add_argument('frame_number', type=int, help='要分析的帧号')
    
    args = parser.parse_args()
    
    analyze_specific_frame(args.pcap_file, args.frame_number)

if __name__ == "__main__":
    main()
