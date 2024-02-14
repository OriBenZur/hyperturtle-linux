#!/bin/bash

# FILEPATH: /mnt/bigdisk/ori/nestedTPT_measurements/scripts/test_netperf.sh

OUTPUT_FILE=$1

# Define the IP address of the target machine
TARGET_IP="10.0.0.1"

DOCKER_CMD="docker exec netperf_client"

# Define the packet sizes to test
PACKET_SIZES=("64" "128" "256" "512" "1024")


do_test() {
    $DOCKER_CMD > /dev/null netperf -H $TARGET_IP -t UDP_RR -l 10 -p 11211 -v 2 -b 1 -- -r 64,64 -o mean_latency,p99_latency,stddev_latency,transaction_rate

    # Test latency for different packet sizes
    for size in "${PACKET_SIZES[@]}"; do
        echo "Testing latency for packet size: $size"
        $DOCKER_CMD netperf -H $TARGET_IP -t UDP_RR -l 10 -p 11211 -v 2 -b 1 -- -r $size,$size -o mean_latency,p99_latency,stddev_latency,transaction_rate
    done

    # Test throughput
    echo "Testing throughput"
    $DOCKER_CMD netperf -H $TARGET_IP -t TCP_STREAM -p 11211
}

sudo sed -i "s/default_vcpus = [0-9]*/default_vcpus = 1/g" /opt/kata/share/defaults/kata-containers/configuration.toml
docker run --runtime io.containerd.kata.v2 -d --rm --name netperf_client alectolytic/netperf

# Pin QEMU processes to core 1
for pid in $(pgrep qemu); do sudo taskset -cp 1 $pid; done
for pid in $(pgrep vhost); do sudo taskset -cp 2 $pid; done

do_test > double_virtio_netperf.txt

docker kill netperf_client
docker run --runtime io.containerd.kata.v2 -d --rm --device /dev/vfio/16 --network=none --cap-add=NET_ADMIN --name netperf_client alectolytic/netperf
docker exec netperf_client ifconfig eth0 192.168.122.77
docker exec netperf_client ip route replace default via 192.168.122.1 dev eth0 src 192.168.122.77
do_test > direct_assignment_netperf.txt

docker kill netperf_client
