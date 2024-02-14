echo 9999999 > /proc/sys/net/core/somaxconn 

echo 4194304 > /proc/sys/net/core/rmem_max 

echo 4194304 > /proc/sys/net/core/wmem_max 

echo 4194304 > /proc/sys/net/core/rmem_default 

echo 4194304 > /proc/sys/net/core/wmem_default 

echo "4096 87380 4194304" > /proc/sys/net/ipv4/tcp_rmem 

echo "4096 87380 4194304" > /proc/sys/net/ipv4/tcp_wmem 

echo "4096 87380 4194304" > /proc/sys/net/ipv4/tcp_mem 

echo 250000 > /proc/sys/net/core/netdev_max_backlog 

echo 50 > /proc/sys/net/core/busy_read 

echo 50 > /proc/sys/net/core/busy_poll 

echo 3 > /proc/sys/net/ipv4/tcp_fastopen 

echo 0 > /proc/sys/kernel/numa_balancing 

echo 0 > /proc/sys/net/ipv4/tcp_timestamps 

echo 1 > /proc/sys/net/ipv4/tcp_low_latency 

echo 0 > /proc/sys/net/ipv4/tcp_sack 

echo 1 > /proc/sys/net/ipv4/tcp_syncookies
