#!/bin/bash

# 简化版UDP测试脚本 - 兼容性更好

# 配置
TARGET_IP=${TARGET_IP:-100.120.241.10}
TEST_PORT=${TEST_PORT:-8900}
PACKET_COUNT=${PACKET_COUNT:-1000}

echo "=== 简化UDP测试 ==="
echo "目标服务器: $TARGET_IP:$TEST_PORT"
echo "发送包数: $PACKET_COUNT"
echo

# 检查网络连通性
echo "检查网络连通性..."
if ping -c 3 -W 2 $TARGET_IP > /dev/null 2>&1; then
    echo "✓ 网络连通正常"
else
    echo "✗ 网络不通"
    exit 1
fi

# 检查nc
if ! command -v nc >/dev/null 2>&1; then
    echo "错误: 需要安装 netcat"
    exit 1
fi

echo
echo "开始发送测试数据..."
echo "在目标服务器运行: nc -u -l $TEST_PORT"
echo

# 发送测试数据
{
    i=1
    while [ $i -le $PACKET_COUNT ]; do
        echo "TEST_PACKET_${i}_$(date +%s)"
        i=$((i + 1))
        sleep 0.01
    done
} | nc -u $TARGET_IP $TEST_PORT

echo "发送完成!"
echo "在目标服务器检查是否收到 $PACKET_COUNT 个包"
