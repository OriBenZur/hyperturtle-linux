#! /bin/bash
sudo docker network create memcached_network
sudo docker build -t memcached_client_server .

# run memtier benchmark not in a container to test memcached


