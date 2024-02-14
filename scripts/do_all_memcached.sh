#! /bin/bash
RESULTS_PATH=~/results/memcached.direct_connection.new
IP="10.0.0.2"
N_ITERATIONS=5
IS_D=
VCPUS=($(seq 1 1 3))
scan_configs=( "double_virtio_L2" "direct_assignment_L2" "direct_assignment_L2_packet_counter" )
all_configs=("${scan_configs[@]}" "direct_assignment_L2_pass" "direct_assignment_L2_rate_limiter")


# # For general
qpss=($(seq 3000 2000 20000))
qpss+=($(seq 20000 3000 50000))
qpss+=($(seq 50000 10000 100000)) 

# # For limits
# note that double virtio breaks between 44000 and 46000, we might want to sample this range better

if [ -f "reminder_cancel_special_config" ]; then
    echo "Error! Tried to re-run special config"
    exit
fi
VCPUS=(4) # remove
scan_configs=("direct_assignment_L2" "double_virtio_L2") # remove
# qpss=(19000 20000 38000)
L1_FREE_CPUS=10
touch "reminder_cancel_special_config"



# if [[ $1 == s* ]]; then
    configs=("${scan_configs[@]}")
# else
#     configs=("${all_configs[@]}")
# fi
for config in "${configs[@]}"; do
    # if [[ $config == "double_virtio_L2" ]]; then # TODO: remove
    #     VCPUS=(3) # TODO: remove
    # fi # TODO: remove

    # read -p "Press Enter to continue or 'c' to skip this iteration: " input
    # if [[ $input == "c" ]]; then
    #     continue
    if [[ $config == *"double"* ]]; then
        ssh ori@$IP "echo Ab123456 | sudo -S /mnt/bigdisk/ori/nestedTPT_measurements/scripts/port_forward.sh 76 11211 11211"
        IS_D="d"
    else
        ssh ori@$IP "echo Ab123456 | sudo -S /mnt/bigdisk/ori/nestedTPT_measurements/scripts/port_forward.sh 77 11211 11211"
        IS_D=""
    fi
    for n_vcpus in "${VCPUS[@]}"; do
        MEMCACHED_THREADS=($(seq 1 1 $n_vcpus))
        MEMCACHED_THREADS=($n_vcpus) # TODO: remove
        for n_worker_threads in "${MEMCACHED_THREADS[@]}"; do
            max_n_vhost_threads=$(($n_worker_threads < $L1_FREE_CPUS - $n_vcpus ? $n_worker_threads : $L1_FREE_CPUS - $n_vcpus))
            VHOST_THREADS=($(seq 1 1 $max_n_vhost_threads))
            VHOST_THREADS=(1) # TODO: remove
            for n_vhost_threads in "${VHOST_THREADS[@]}"; do

                echo "Running config: $config, vcpus: $n_vcpus, workers: $n_worker_threads, vhosts: $n_vhost_threads"
                ssh L1ubuntu@$IP -p2222 -i /home/ori/.ssh/id_ed25519 "docker kill memcached_serv1; echo ubuntu | sudo -S ./shared_folder/scripts/launch_pinned_mamcached.sh 1 $n_vcpus $n_worker_threads $n_vhost_threads $IS_D" > /dev/null
                /home/ori/memcache-perf/mcperf --binary --loadonly -s $IP -K fb_key -V fb_value -i fb_ia

                for qps in "${qpss[@]}"; do 
                    echo "Running qps: $qps"
                    # Check if directory exists, create it if it doesn't
                    if [ ! -d "$RESULTS_PATH/${qps}QPS" ]; then
                        mkdir -p "$RESULTS_PATH/${qps}QPS"
                    fi

                    file_name="$RESULTS_PATH/${qps}QPS/${config}_${n_vcpus}vcpus_${n_worker_threads}workers_${n_vhost_threads}vhost.new"

                    # Delete old results
                    # if [ -f "$file_name" ]; then
                        # rm "$file_name"
                        # continue
                    # fi

                    # Run 10 times
                    for ((i = 0; i < $N_ITERATIONS; i++)); do
                        /home/ori/scripts/run_mutilate.sh 15 $qps >> $file_name
                    done

                done
            done
        done
    done
    if [[ $config == *"double"* ]]; then
        ssh ori@$IP "echo Ab123456 | sudo -S /mnt/bigdisk/ori/nestedTPT_measurements/scripts/port_unforward.sh 76 11211 11211"
    else
        ssh ori@$IP "echo Ab123456 | sudo -S /mnt/bigdisk/ori/nestedTPT_measurements/scripts/port_unforward.sh 77 11211 11211"
    fi

done



    # sudo iptables -t nat -D PREROUTING -p tcp --dport 11211 -j DNAT --to-destination 192.168.122.77
