#!/bin/bash

head_port=$1
node_size=$2
script=""

num=$(seq 1 $node_size)

cd build/Release/

for i in $num; do
    node_port=$((head_port+i))
    ./net $node_port $head_port &
    sleep 0.1
done
