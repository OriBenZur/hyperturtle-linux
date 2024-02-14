#! /bin/bash
for i in {1..4}; do
docker run --runtime io.containerd.kata.v2 --name ub --rm alpine echo hello
done
