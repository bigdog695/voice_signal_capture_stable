#!/bin/bash

# UDP转发可靠性测试脚本
# 模拟RTP数据包的UDP转发，测试丢包率和延迟

set -e

# 配置
TARGET_IP="${TARGET_IP:-100.120.241.10}"
TEST_PORT="${TEST_PORT:-8900}"
PACKET_SIZE="${PACKET_SIZE:-200}"  # RTP包大小约200字节
PACKETS_PER_SEC="${PACKETS_PER_SEC:-200}"  # 模拟40个通话，每个5包/秒
TEST_DURATION="${TEST_DURATION:-30}"  # 测试30秒
LOG_FILE="/tmp/udp_test.log"

echo "=== UDP转发可靠性测试 ==="
echo "目标服务器: $TARGET_IP:$TEST_PORT"
echo "包大小: $PACKET_SIZE 字节"
echo "发送速率: $PACKETS_PER_SEC 包/秒"
echo "测试时长: $TEST_DURATION 秒"
TOTAL_PACKETS=$((PACKETS_PER_SEC * TEST_DURATION))
echo "预计发送: $TOTAL_PACKETS 个包"
echo

# 检查网络连通性
echo "=== 网络连通性检查 ==="
if ping -c 3 -W 2 $TARGET_IP > /dev/null 2>&1; then
    RTT=$(ping -c 3 -W 2 $TARGET_IP | tail -1 | awk -F '/' '{print $5}')
    echo "✓ 网络连通正常，平均延迟: ${RTT}ms"
else
    echo "✗ 网络不通，请检查目标IP"
    exit 1
fi

# 检查依赖
command -v nc >/dev/null 2>&1 || { 
    echo "错误: 需要安装 netcat"
    exit 1
}

# 创建测试数据生成器
create_test_data() {
    packet_num=$1
    timestamp=$(date +%s.%3N)
    # 模拟RTP包头 + 序号 + 时间戳
    printf "RTP_TEST_PACKET_%06d_TIME_%s_SIZE_" "$packet_num" "$timestamp"
    # 填充到指定大小
    padding_size=$((PACKET_SIZE - 50))
    if [ $padding_size -gt 0 ]; then
        head -c $padding_size /dev/zero | tr '\0' 'X'
    fi
    printf "\n"
}

echo "=== 开始UDP发送测试 ==="
echo "正在生成测试数据并发送..."

# 清理日志
> $LOG_FILE

# 发送测试数据
{
    for i in $(seq 1 $TOTAL_PACKETS); do
        create_test_data $i
        # 控制发送速率
        if [ $((i % PACKETS_PER_SEC)) -eq 0 ]; then
            sleep 1
        else
            sleep 0.005  # 5ms间隔
        fi
    done
} | nc -u $TARGET_IP $TEST_PORT 2>>$LOG_FILE &

SENDER_PID=$!

echo "✓ 发送进程启动 (PID: $SENDER_PID)"
echo "✓ 正在发送数据到 $TARGET_IP:$TEST_PORT"

# 监控发送进度
echo
echo "=== 发送进度监控 ==="
for sec in $(seq 1 $TEST_DURATION); do
    if kill -0 $SENDER_PID 2>/dev/null; then
        sent_packets=$((sec * PACKETS_PER_SEC))
        echo "$(date '+%H:%M:%S') - 已发送: $sent_packets 包 (${sec}/${TEST_DURATION}秒)"
        sleep 1
    else
        echo "发送进程提前结束"
        break
    fi
done

# 等待发送完成
wait $SENDER_PID 2>/dev/null || true

echo
echo "=== 发送完成 ==="
echo "总发送包数: $TOTAL_PACKETS"

# 检查发送错误
if [ -s "$LOG_FILE" ]; then
    echo "发送过程中的错误:"
    cat $LOG_FILE
else
    echo "✓ 发送过程无错误"
fi

echo
echo "=== 网络质量评估 ==="
echo "基于ping结果的网络质量:"
ping -c 10 -i 0.2 $TARGET_IP | tail -1 | awk -F '/' '{
    avg = $5
    if (avg < 5) print "✓ 延迟优秀 (" avg "ms) - UDP转发质量预期: 很好"
    else if (avg < 20) print "✓ 延迟良好 (" avg "ms) - UDP转发质量预期: 良好"  
    else if (avg < 50) print "⚠ 延迟一般 (" avg "ms) - UDP转发质量预期: 一般"
    else print "✗ 延迟较高 (" avg "ms) - UDP转发质量预期: 可能有问题"
}'

echo
echo "=== 建议 ==="
echo "1. 如果发送无错误且延迟<20ms，UDP转发应该很可靠"
echo "2. 对于RTP音频，偶尔丢包(1-2%)是可接受的"
echo "3. 如果担心可靠性，可以考虑TCP+重连方案"
echo
echo "测试完成！"
