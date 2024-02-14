N_ITERATIONS=$1
#!/bin/bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
nproc=$(nproc)

# if [ "$nproc" -gt "$N_ITERATIONS" ]; then
#     echo "Error: nproc is greater than N_ITERATIONS"
#     exit 1
# fi

for ((i=1;i<=N_ITERATIONS;i++)); do
    "$SCRIPT_DIR/run_gups_parallel.sh" $i
done

