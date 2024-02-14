if [ "$#" -ne 1 ]; then
    echo "Error: Expected 1 argument, got $#"
    exit 1
fi

N_COPIES=$1
ITERATIONS=4

echo "Starting $N_COPIES containers"

start_time=$(date +%s.%3N)
for i in $(seq 1 $N_COPIES); do
    iter_start_time=$(date +%s.%3N)
    cmd="docker run -d --runtime io.containerd.kata.v2 --rm --name gups$i gups ./gups --log2_length 24 --log2_iterations $ITERATIONS"
    # echo $cmd
    $cmd > /dev/null
    docker pause gups$i > /dev/null
    iter_end_time=$(date +%s.%3N)
    iter_time=$(echo "$iter_end_time - $iter_start_time" | bc)
    # echo "Iteration time: $iter_time seconds"
done

launch_loop_end_time=$(date +%s.%3N)
launch_loop_time=$(echo "$launch_loop_end_time - $start_time" | bc)
# echo "Launch loop time: $launch_loop_time seconds"



for pid in $(pgrep -f "qemu"); do
    sudo taskset -a -p 8 $pid
done

docker unpause $(docker ps -q --filter "name=gups" | head -n $N_COPIES) > /dev/null
# for i in $(seq 1 $N_COPIES); do docker unpause gups$i; done

work_loop_start_time=$(date +%s.%3N)
for i in $(seq 1 $N_COPIES); do docker wait gups$i > /dev/null; done

end_time=$(date +%s.%3N)
worktime=$(echo "$end_time - $work_loop_start_time" | bc)
echo "Work time taken: $worktime seconds"
echo "Work time per container: $(echo "$worktime / $N_COPIES" | bc) seconds per container"


