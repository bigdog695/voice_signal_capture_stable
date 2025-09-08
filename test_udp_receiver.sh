#!/bin/bash

# UDP接收端测试脚本 (在目标服务器运行)
# 配合 test_udp_reliability.sh 使用

set -e

# 配置
LISTEN_PORT="${LISTEN_PORT:-8888}"
LOG_FILE="/tmp/udp_receive_test.log"
RECEIVED_FILE="/tmp/received_packets.txt"

echo "=== UDP接收端测试 ==="
echo "监听端口: $LISTEN_PORT"
echo "日志文件: $LOG_FILE"
echo

# 检查依赖
command -v nc >/dev/null 2>&1 || { 
    echo "错误: 需要安装 netcat"
    exit 1
}

# 清理之前的测试
> $LOG_FILE
> $RECEIVED_FILE

echo "=== 启动UDP接收 ==="
echo "正在监听端口 $LISTEN_PORT..."
echo "按 Ctrl+C 停止接收"
echo

# 捕获退出信号
trap 'analyze_results; exit 0' SIGINT SIGTERM

# 分析接收结果
analyze_results() {
    echo
    echo "=== 接收测试结果分析 ==="
    
    if [ ! -s "$RECEIVED_FILE" ]; then
        echo "✗ 未接收到任何数据包"
        echo "请检查:"
        echo "1. 网络连通性"
        echo "2. 防火墙设置"
        echo "3. 端口是否被占用"
        return
    fi
    
    # 统计接收到的包
    RECEIVED_COUNT=$(wc -l < $RECEIVED_FILE)
    echo "接收到的包数: $RECEIVED_COUNT"
    
    # 分析包序号连续性
    echo "正在分析包序号连续性..."
    grep -o "RTP_TEST_PACKET_[0-9]*" $RECEIVED_FILE | \
    sed 's/RTP_TEST_PACKET_//' | sort -n > /tmp/packet_numbers.txt
    
    FIRST_PACKET=$(head -1 /tmp/packet_numbers.txt)
    LAST_PACKET=$(tail -1 /tmp/packet_numbers.txt)
    EXPECTED_COUNT=$((LAST_PACKET - FIRST_PACKET + 1))
    
    echo "包序号范围: $FIRST_PACKET - $LAST_PACKET"
    echo "期望接收: $EXPECTED_COUNT 包"
    echo "实际接收: $RECEIVED_COUNT 包"
    
    if [ $RECEIVED_COUNT -eq $EXPECTED_COUNT ]; then
        echo "✓ 无丢包，UDP转发完全可靠"
    else
        LOST_COUNT=$((EXPECTED_COUNT - RECEIVED_COUNT))
        LOSS_RATE=$(echo "scale=2; $LOST_COUNT * 100 / $EXPECTED_COUNT" | bc -l)
        echo "✗ 丢失 $LOST_COUNT 包，丢包率: ${LOSS_RATE}%"
        
        if (( $(echo "$LOSS_RATE < 1" | bc -l) )); then
            echo "✓ 丢包率很低，UDP转发质量优秀"
        elif (( $(echo "$LOSS_RATE < 3" | bc -l) )); then
            echo "⚠ 丢包率较低，UDP转发质量良好"
        else
            echo "✗ 丢包率偏高，建议考虑TCP方案"
        fi
    fi
    
    # 分析接收时间间隔
    if [ $RECEIVED_COUNT -gt 10 ]; then
        echo "正在分析接收时间间隔..."
        grep -o "TIME_[0-9.]*" $RECEIVED_FILE | sed 's/TIME_//' | \
        head -10 | tail -5 > /tmp/timestamps.txt
        echo "最近5个包的时间间隔分析已保存到 /tmp/timestamps.txt"
    fi
    
    echo
    echo "=== UDP转发可靠性评估 ==="
    if [ $RECEIVED_COUNT -gt 0 ]; then
        if (( $(echo "${LOSS_RATE:-0} < 2" | bc -l) )); then
            echo "✅ 推荐使用UDP转发 - 丢包率可接受"
        else
            echo "⚠️  建议考虑TCP+重连方案 - 丢包率较高"
        fi
    else
        echo "❌ 不建议使用UDP - 可能存在网络问题"
    fi
    
    rm -f /tmp/packet_numbers.txt /tmp/timestamps.txt
}

# 启动接收
echo "开始接收UDP数据包..."
nc -u -l $LISTEN_PORT | tee $RECEIVED_FILE | while IFS= read -r line; do
    echo "$(date '+%H:%M:%S.%3N') - 收到包: $(echo "$line" | cut -c1-50)..."
done

echo "接收结束"
