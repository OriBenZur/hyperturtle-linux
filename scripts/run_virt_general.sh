#!/bin/bash

SOURCE_DIR=$(dirname "$0")
GUEST_DIR=/mnt/bigdisk/ori/devirt-guest/
NIC_PASS=0

# Defaults
#MEM_SIZE=64
MEM_SIZE=8
IMAGE=
DEVIRT=
DEVIRT_MACHINE= #"devirt=off"
SHARED_DIR_PATH="/home/ori/nestedTPT_measurements"
SSH_PORT=2222
QMP_PORT=4444
SSH_FORWARD=2223
NUM_CPUS=16
KPTI_STR=""

# Opts
OPT_HUGE=0
OPT_DEVIRT=0

while getopts ghdm:c:i:f:q:S:H:r: opt; do
    case $opt in
        h)
            OPT_HUGE=1
            ;;
        g)
            OPT_HUGE=2
            ;;
        d)
            OPT_DEVIRT=1
            ;;
        c)
            NUM_CPUS=$((${OPTARG}))
            echo "new cpu num ${OPTARG}!"
            ;;
        m)
            MEM_SIZE=$((${OPTARG}))
            echo "new mem size ${OPTARG}G!"
            ;;
        i)
            IMAGE=$OPTARG           #Image to run
            ;;
        f)
            SHARED_DIR_PATH=$OPTARG
            ;;
        q)
            QMP_PORT=$OPTARG
            ;;
        S)
            SSH_PORT=$OPTARG     #Port that is forwarded to the guest's 22
            ;;
        H)
            SSH_FORWARD=$OPTARG
            ;;
        r)
            REDIRECT=$OPTARG
            ;;
    esac
done

if [ "$NIC_PASS" -eq 1 ]; then
    sudo modprobe vfio-pci
    echo 0000:86:00.1 | sudo tee /sys/bus/pci/drivers/vfio-pci/unbind
    echo 0000:86:00.1 | sudo tee /sys/devices/pci0000\:85/0000\:85\:00.0/0000\:86\:00.1/driver/unbind
    echo "15b3 1016" | sudo tee /sys/bus/pci/drivers/vfio-pci/remove_id
    echo "15b3 1016" | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id
    echo 0000:86:00.1 | sudo tee /sys/bus/pci/drivers/vfio-pci/bind
fi


# Init for Qemu
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
MEMORY="-object memory-backend-ram,size=${MEM_SIZE}G,merge=off,prealloc=on,id=m0"

# Free old huge pages if there are any
echo 0 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 0 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages

sudo umount /hugepages

if (( $OPT_HUGE != 0 )); then
    MEMORY="-object memory-backend-file,size=${MEM_SIZE}G,merge=off,mem-path=/hugepages,prealloc=on,id=m0"
    sudo mkdir /hugepages
	if (( $OPT_HUGE == 2 )); then
		echo "run huge memory 1G"
		NUM_HUGE=$((${MEM_SIZE}))
		echo $NUM_HUGE | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages
		sudo mount -t hugetlbfs -o pagesize=1G none /hugepages
	else
		echo "run huge memory 2M"
		NUM_HUGE=$(((${MEM_SIZE} * 1024)/2))
		echo $NUM_HUGE | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
		sudo mount -t hugetlbfs -o pagesize=2M none /hugepages
	fi

    sudo chown -R lior:lior /hugepages
fi

if (( $OPT_DEVIRT == 1 )); then
    DEVIRT="-device devirt-plain"
    DEVIRT_MACHINE="devirt=on"
    KPTI_STR="pti=on "
    echo "run devirt"
fi

NUM_CPUS_MAX_STR="-$(( $NUM_CPUS - 1 ))"
# Run Qemu
#sudo gdb --args \
# -drive file=$SOURCE_DIR/ubuntu.img,if=virtio,format=raw \
sudo numactl --physcpubind 0${NUM_CPUS_MAX_STR} --membind 0 \
qemu-system-x86_64 -s -name debug-threads=on \
-serial mon:stdio -m ${MEM_SIZE}G \
-drive file=$IMAGE,if=virtio,format=qcow2 \
-machine pc,${DEVIRT_MACHINE} \
-virtfs local,path=$SHARED_DIR_PATH,mount_tag=hostshare,security_model=none,id=hostshare \
-enable-kvm -cpu host,migratable=no,+tsc,+tsc-deadline,+rdtscp,+invtsc,+monitor \
$MEMORY \
-device e1000,netdev=net0 \
-netdev user,id=net0,hostfwd=tcp:0.0.0.0:${SSH_PORT}-:22,hostfwd=tcp:0.0.0.0:${SSH_FORWARD}-:${SSH_PORT},hostfwd=tcp:0.0.0.0:2244-:11211,hostfwd=tcp:0.0.0.0:2245-:2244 \
-device vfio-pci,host=0000:86:00.1 \
-smp ${NUM_CPUS},sockets=1,maxcpus=${NUM_CPUS} \
-numa node,nodeid=0,cpus=0${NUM_CPUS_MAX_STR},memdev=m0 \
-rtc clock=host \
-qmp tcp:localhost:4444,server,nowait \
-vnc localhost:5900 \
$DEVIRT \
# -kernel $GUEST_DIR/arch/x86/boot/bzImage -append "nokaslr norandmaps root=/dev/vda2 console=ttyS0 earlyprintk=serial,ttyS0 ignore_loglevel printk_delay=0 systemd.unified_cgroup_hierarchy=1 nopku ${KPTI_STR}" \

if [ "$NIC_PASS" -eq 1 ]; then
    echo 0000:86:00.1 | sudo tee /sys/bus/pci/drivers/vfio-pci/unbind
fi
#-kernel $GUEST_DIR/arch/x86/boot/bzImage -append 'nokaslr norandmaps root=/dev/vda2 console=ttyS0 earlyprintk=serial,ttyS0 ignore_loglevel printk_delay=0 systemd.unified_cgroup_hierarchy=1 nopku' \
