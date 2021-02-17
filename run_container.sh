#!/bin/bash

if $(docker ps | grep -q "shade-so"); then
    echo "Container exists, starting..."
    docker start -a -i shade-so
else
    echo "Container doesn't exist, start creating..."
    docker run -it -v /home/demons/LIEF:/LIEF -v $PWD:/root/shade-so --privileged --name shade-so shade-so:0.1 bash
fi
