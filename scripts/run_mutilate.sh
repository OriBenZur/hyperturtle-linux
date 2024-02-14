# SERVER_IP="172.17.0.2" # Container IP
SERVER_IP="132.68.52.133"  # "132.68.52.224" # ACSL1 # L1ubuntu 132.68.52.133
SERVER_IP="132.68.52.224"  # "132.68.52.224" # ACSL1 # L1ubuntu 132.68.52.133
SERVER_IP="10.0.0.2"
INITIAL_IP="172.18.0."
OUTPUT_FILE="" # "native_results" # "virt_results"
INITIAL_IP_OFFSET=3
N_THREADS=$(($(nproc) / 2))
QPS=5000
if [ -n "$1" ]; then
    N_THREADS=$1
fi
if [ -n "$2" ]; then
    QPS=$2
fi
if [ -n "$3" ]; then
    OUTPUT_FILE="--save $3"
fi
N_CORES=$(($N_THREADS))
CONNECTIONS=$((16 / $N_THREADS))
# KATA="--runtime io.containerd.kata.v2"
# DOCKER_RUN="sudo docker run $SET_CPU --rm $NET $KATA --name master memcache-perf"
NUMA_CTL="sudo numactl --physcpubind 16-$(($N_CORES + 16)) --membind 1"
MUTILATE="/home/ori/mutilate/mutilate"
# SET_CPU=--cpuset-cpus="1-${N_CORES}"
# NET="--net memcached_network"
for ((i = 16; i < 32; i++)); do sudo cpufreq-set -c $i -d 2.1GHz -u 2.1GHz; done
# sudo sed -i 's/^default_vcpus = [0-9]\+$/default_vcpus = '"$N_CORES"'/' /opt/kata/share/defaults/kata-containers/configuration.toml
# sudo docker run --runtime io.containerd.kata.v2 --name memcached_server --rm -d  memcached -m 48 -c 32768 -t 1
# sudo docker run --cpuset-cpus=0 --name memcached_server --rm -d  memcached -m 48 -c 32768 -t 1

MEMCACHED_QEMU_PID=$(pgrep qemu)
# For each qemu process


# (
#     PID_LIST=

#     # loop until both qemu processes are running
#     while [[ ${#PID_LIST[@]} -ne 2 ]]
#     do
#         sleep 1
#         PID_LIST=($(pgrep qemu | sort -n))
#     done

#    sudo taskset -cp 0 ${PID_LIST[0]} > /dev/null
#    sudo taskset -cp 1-15 ${PID_LIST[1]}

#     echo "PINNED CPUS"
# )& 
# (
#     sleep 1
#     sudo perf kvm stat -p $(pgrep qemu | sort -n | tail -n 1) -e cycles:G,cycles:H
# )&
find results/memcached.direct_connection.new -type d -empty -delete

$NUMA_CTL $MUTILATE -s $SERVER_IP \
    --threads=15 --agentmode --affinity &

agents_pid=$!

$NUMA_CTL $DOCKER_RUN $MUTILATE -s $SERVER_IP \
    -T $N_THREADS -c 16 --binary --depth 4 --measure_depth=4 --measure_connections=1 --measure_qps=1000 \
    -K fb_key -V fb_value -i fb_ia --affinity \
    -w 5 -u 0.033 -t 15 --agent=127.0.0.1 \
    -q $QPS
    # --scan 500:1000:500
    # --search=99:500
# sudo numactl --physcpubind 0-15  ./mcperf --noload --warmup 2 -t 10 -T 15 -K fb_key -V fb_value -i fb_ia -q 5000 -u 0.1 -s 10.0.0.2 -c 7 --binary --depth 4

sudo kill -9 $agents_pid
# sudo pkill -SIGINT perf
# sudo sed -i 's/^default_vcpus = [0-9]\+$/default_vcpus = '"1"'/' /opt/kata/share/defaults/kata-containers/configuration.toml
for ((i = 16; i < 32; i++)); do sudo cpufreq-set -c $i -d 800MHz -u 2.1GHz; done

