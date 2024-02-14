#! /bin/bash

default_number_of_threads=32
# if [[ -z $OMP_NUM_THREADS ]]; then
export OMP_NUM_THREADS=$default_number_of_threads
# fi
# if [[ -z $OMP_THREAD_LIMIT ]]; then
export OMP_THREAD_LIMIT=$default_number_of_threads
# fi

$(dirname $0)/omp-csr -s 25
