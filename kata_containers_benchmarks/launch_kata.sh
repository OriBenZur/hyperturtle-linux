#! /bin/bash
for i in {1..10}; do
    docker run --runtime io.containerd.kata.v2 --name ub1 --rm alpine echo hello
done
