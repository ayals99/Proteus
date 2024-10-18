#!/bin/bash 
echo "resetting nodric device: in shell"

cd /home/usr/zephyrproject/zephyr
pwd

# sleep 1

/home/usr/.local/bin/west flash
#sleep 5
