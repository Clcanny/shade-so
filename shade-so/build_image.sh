#!/bin/bash

if $(docker images | grep -q "shade-so:0.1"); then
    echo "Image exists, skip building."
else
    echo "Image doesn't exist, start building..."
    docker build -t shade-so:0.1 .
fi
