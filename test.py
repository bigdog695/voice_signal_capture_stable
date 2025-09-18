   # 发送端
   tcpdump -i any -s 0 -n -w - -U -B 262144 'udp and (portrange 10000-20000 or port 5060)' 2>tcpdump.err | \
   socat -u - UDP-SENDTO:100.120.241.10:8900