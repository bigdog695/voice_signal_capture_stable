#!/bin/bash

# 简化版UDP接收测试脚本

LISTEN_PORT=${LISTEN_PORT:-8900}

echo "=== 简化UDP接收测试 ==="
echo "监听端口: $LISTEN_PORT"
echo "按 Ctrl+C 停止"
echo

# 检查nc
if ! command -v nc >/dev/null 2>&1; then
    echo "错误: 需要安装 netcat"
    exit 1
fi

echo "开始接收..."

# 接收并统计
received_count=0
start_time=$(date +%s)

trap 'end_time=$(date +%s); duration=$((end_time - start_time)); echo; echo "=== 测试结果 ==="; echo "接收包数: $received_count"; echo "测试时长: ${duration}秒"; if [ $received_count -gt 0 ]; then echo "✓ UDP转发正常"; else echo "✗ 未收到数据"; fi; exit 0' SIGINT SIGTERM

nc -u -l $LISTEN_PORT | while IFS= read -r line; do
    received_count=$((received_count + 1))
    echo "收到包 $received_count: $(echo "$line" | cut -c1-30)..."
done
