# TCP连接断开问题排查指南

## 问题描述

在使用`sender.sh`和`socat`接收端处理流量转发时，发现TCP连接经常断开，具体表现为：

```
receiver: 2025-09-16 02:00:02,009 - INFO - 数据流已结束，TCP连接可能已断开
sender: 2025-09-16 02:00:02.036: Connection closed
```

根据日志时间戳，接收端先断开连接，然后发送端检测到连接关闭。

## 可能的原因

1. **TCP超时断开**：长时间没有数据传输，TCP连接可能因为超时而断开
2. **网络问题**：网络波动或临时中断导致连接断开
3. **Python进程异常**：`recover_audio_streaming.py`脚本可能发生异常导致进程退出
4. **资源限制**：系统资源（如内存、文件描述符）耗尽
5. **socat参数配置**：socat默认配置可能不适合长连接场景

## 排查工具

我们提供了两个脚本来帮助排查问题：

1. `debug_socat_connection.sh` - 详细的调试脚本，使用strace监控socat系统调用
2. `enhanced_receiver.sh` - 增强版接收端脚本，添加了TCP keepalive机制

## 使用方法

### 详细调试

运行详细调试脚本来捕获连接断开的具体原因：

```bash
bash debug_socat_connection.sh
```

这将创建`socat_debug_logs`目录，包含以下日志文件：
- `socat_main.log` - 主要事件日志
- `socat_detailed.log` - socat详细输出
- `python_process.log` - Python进程状态
- `network_status.log` - 网络连接状态
- `socat_strace.log` - socat系统调用跟踪

### 使用增强版接收端

使用增强版接收端脚本替代原来的socat命令：

```bash
bash enhanced_receiver.sh
```

增强版脚本添加了TCP keepalive机制，可以防止长时间无数据传输导致的连接断开。

## 排查要点

1. 检查`socat_strace.log`中的网络相关系统调用，特别是`close`、`shutdown`等事件前后的调用
2. 检查`python_process.log`确认Python进程是否正常退出
3. 检查`network_status.log`了解连接断开前的网络状态
4. 检查系统日志(`/var/log/syslog`或`journalctl`)是否有网络或资源相关错误

## 解决方案

1. **启用TCP keepalive**：在socat命令中添加`so-keepalive=1,keepidle=30,keepintvl=5,keepcnt=10`参数
2. **增加重连机制**：在接收端脚本中添加自动重连逻辑
3. **优化Python脚本**：确保`recover_audio_streaming.py`能够优雅处理连接断开
4. **网络优化**：如果是网络问题，考虑优化网络配置或使用更稳定的网络连接

## 建议的接收端命令

```bash
socat -d -d -d TCP-LISTEN:8900,reuseaddr,fork,so-keepalive=1,keepidle=30,keepintvl=5,keepcnt=10 \
SYSTEM:"python3 /home/barryhuang/work/recover_audio_streaming.py /dev/stdin --zmq --zmq-endpoint 'tcp://127.0.0.1:5555' --chunk-seconds 2"
```

这个命令启用了TCP keepalive机制，可以有效防止长时间无数据传输导致的连接断开。
