#!/bin/bash 
echo "resetting nodric device"
pushd /home/cyber2slab/zephyrproject/zephyr
#sleep 1
pwd
/home/cyber2slab/.local/bin//west flash
#sleep 5
popd 
