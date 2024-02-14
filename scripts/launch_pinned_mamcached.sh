if [ "$#" -lt 4 ]; then
    echo "Error: Expected 4 arguments, got $#"
    exit 1
fi

N_SERVERS=$1
N_VCPUS=$2
N_THREADS=$3
VHOST_CORES=$4


sed -i "s/default_vcpus = [0-9]*/default_vcpus = $N_VCPUS/g" /opt/kata/share/defaults/kata-containers/configuration.toml
if [ $(($N_VCPUS + $VHOST_CORES)) -gt $(($(nproc) - 1)) ]; then
    echo "Error: N_VCPUS + VHOST_CORES ($N_VCPUS + $VHOST_CORES) must be <= nproc"
    exit 1
fi

is_virtualized=$(sudo dmesg | grep "Hypervisor detected" | wc -l)
i=1

MEMCACHED_OPTIONS="--disable-evictions --memory-limit=1024 --extended hashpower=25 --extended no_hashexpand --extended no_lru_crawler --extended no_lru_maintainer --extended no_slab_reassign --extended no_slab_automove"
MEMCACHED_OPTIONS=
MEMCACHED="memcached -t $N_THREADS -B binary $MEMCACHED_OPTIONS"
DH="dhclient eth0 && su-exec memcache $MEMCACHED"
CMD="--rm --device /dev/vfio/16 --network=none --cap-add=NET_ADMIN --name memcached_serv$i memcached_dhw sh -c"

# exit 1
if [ "$#" -ge 5 ] && [ "$5" = "d" ]; then
    CMD="-p192.168.122.76:11211:11211 --rm --name  memcached_serv$i memcached_dhw su-exec memcache $MEMCACHED"
    DH=
fi


if ! lsmod | grep -q vhost_net || [ "$(cat /sys/module/vhost_net/parameters/experimental_zcopytx)" -eq 0 ]; then
    sudo modprobe vhost_net experimental_zcopytx=1
fi

# for ((i=1; i<=N_SERVERS; i++))
# do
KATA_RUNTIME="--runtime io.containerd.kata.v2"
sudo docker run $KATA_RUNTIME -d $CMD "$DH"
# done

sleep 2
i=0
for pid in $(pgrep -w qemu | tac); do 
    echo "sudo taskset -cp $((($i % $N_VCPUS) + 1)) $pid"
    sudo taskset -cp $((($i % $N_VCPUS) + 1)) $pid
    i=$(($i + 1))
done
j=0
echo "startin vhost pinning"
if [ -z "$DH" ]; then
    for pid in $(pgrep -w vhost | tac); do 
        sudo taskset -cp $((($j % $VHOST_CORES) + 1 + $N_VCPUS)) $pid
        j=$(($j + 1))
    done
    ssh_cmd="j=0; l1_vcpus=$(nproc); for pid in \$(pgrep -w vhost | tac); do sudo taskset -cp \$(((\$j % (16 - 1 -\$l1_vcpus)) + $(nproc) + 1)) \$pid; j=\$((\$j + 1)); done"
else
    ssh_cmd="j=0; VHOST_CORES=$VHOST_CORES; for pid in \$(pgrep -w vhost | tac); do sudo taskset -cp \$(((\$j % \$VHOST_CORES) + $(nproc) + 1)) \$pid; j=\$((\$j + 1)); done"
fi
ssh ori@10.0.0.2 -i /home/ubuntu/.ssh/id_rsa $ssh_cmd
echo "finished vhost pinning"



# for pid in $(ps -aHx -o cmd,tid | grep qemu | awk '{print $NF}'); do sudo chrt -f -a -p 3 $pid; done
# for pid in $(pgrep vhost |); do sudo taskset --all-tasks -cp $(($N_VCPUS + 2)) $pid; done
# for pid in $(pgrep vhost); do sudo renice -n -20 -p $pid; done

cpu_for_non_worker=0
if [ $N_VCPUS -eq $N_THREADS ]; then
    cpu_for_non_worker=1
elif [ $N_VCPUS -ge $(($N_THREADS + 2)) ]; then
    cpu_for_non_worker=2
fi

while [ $(docker exec memcached_serv1 ps -aT | grep mc-worker | wc -l) -lt $N_THREADS ]; do
    sleep 1
done

if [ $N_VCPUS -gt 1 ]; then

    for pid in $(docker exec memcached_serv1 ps -a | grep memcached | awk '{print $1}'); do
        docker exec memcached_serv1 su-exec memcache taskset -cp -a $cpu_for_non_worker $pid
    done
fi

i=1
for pid in $(docker exec memcached_serv1 ps -aT | grep mc-worker | awk '{print $1}'); do
    docker exec memcached_serv1 su-exec memcache taskset -cp $(($i % $N_VCPUS)) $pid
    i=$(($i + 1))
done
# netperf -H 10.0.0.1 -t TCP_RR 
# netserver
# for ((i=0; i<8; i++)); do sudo taskset -cp $i $(($i + 25803)); done

