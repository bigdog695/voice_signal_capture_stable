#!/bin/bash

# 监控镜像服务对系统的影响
# 运行此脚本来验证镜像服务不会影响热线业务

echo "=== 系统影响监控 ==="
echo "此脚本将监控tcpdump镜像服务对系统的影响"
echo "按 Ctrl+C 停止监控"
echo

# 获取tcpdump和nc的进程ID
get_process_info() {
    TCPDUMP_PID=$(pgrep -f "tcpdump.*portrange.*5060" | head -1)
    NC_PID=$(pgrep -f "nc.*8888" | head -1)
}

# 监控循环
while true; do
    clear
    echo "=== $(date) ==="
    echo
    
    # 系统总体状态
    echo "【系统总体状态】"
    echo "CPU使用率: $(top -bn1 | grep 'Cpu(s)' | awk '{print $2 $4}' | sed 's/%us,/ + /g' | sed 's/%sy//g')"
    echo "内存使用: $(free -h | grep 'Mem:' | awk '{print $3 "/" $2 " (" $5 ")"}')"
    echo "负载平均: $(uptime | awk -F'load average:' '{print $2}')"
    echo
    
    # 镜像服务进程状态
    get_process_info
    echo "【镜像服务状态】"
    if [ -n "$TCPDUMP_PID" ]; then
        echo "✓ tcpdump 运行中 (PID: $TCPDUMP_PID)"
        ps -p $TCPDUMP_PID -o pid,pcpu,pmem,time,cmd --no-headers 2>/dev/null || echo "  进程信息获取失败"
    else
        echo "✗ tcpdump 未运行"
    fi
    
    if [ -n "$NC_PID" ]; then
        echo "✓ nc 运行中 (PID: $NC_PID)"
        ps -p $NC_PID -o pid,pcpu,pmem,time,cmd --no-headers 2>/dev/null || echo "  进程信息获取失败"
    else
        echo "✗ nc 未运行"
    fi
    echo
    
    # 网络连接状态
    echo "【网络连接】"
    netstat -an | grep -E ":5060|:8888" | head -5
    echo
    
    # 磁盘I/O (如果有日志写入)
    echo "【磁盘状态】"
    df -h / | tail -1
    echo
    
    echo "=== 5秒后刷新 (Ctrl+C 停止) ==="
    sleep 5
done
