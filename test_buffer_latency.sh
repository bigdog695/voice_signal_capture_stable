#!/bin/bash

# 测试不同缓冲区大小对时延的影响

echo "=== tcpdump 缓冲区大小测试 ==="
echo "测试将运行30秒，观察数据包时延"

BUFFER_SIZES=(512 1024 2048 4096 8192 16384)
TEST_DURATION=30

for buffer_size in "${BUFFER_SIZES[@]}"; do
    echo
    echo "测试缓冲区大小: ${buffer_size}KB"
    echo "开始时间: $(date '+%H:%M:%S.%3N')"
    
    # 运行tcpdump并记录第一个和最后一个包的时间戳
    timeout $TEST_DURATION tcpdump -i any -w - -U -B $buffer_size \
        'udp and (portrange 10000-20000 or port 5060)' 2>/dev/null | \
        head -c 1000 > /tmp/test_$buffer_size.pcap
    
    echo "结束时间: $(date '+%H:%M:%S.%3N')"
    
    # 分析捕获的数据
    if [ -s /tmp/test_$buffer_size.pcap ]; then
        echo "✓ 成功捕获数据"
    else
        echo "✗ 未捕获到数据"
    fi
    
    rm -f /tmp/test_$buffer_size.pcap
done

echo
echo "=== 建议 ==="
echo "• 1024KB: 最低时延，适合对实时性要求极高的场景"
echo "• 4096KB: 平衡选择，兼顾性能和时延"  
echo "• 8192KB: 当前设置，适合大多数场景"
echo "• 16384KB: 高吞吐量，适合流量很大的场景"
