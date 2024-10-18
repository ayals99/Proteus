#!/bin/bash
#echo "<YOUR PASSWORD>" | sudo -S ./start_core.sh

if [ "$EUID" -ne 0 ]
	then echo "Need to run as root"
	exit
fi

echo "Launching start_core.sh"

echo "Killing any already running srsepc process"
pkill -9 -f srsepc
ps -ef | grep srsepc | grep -v grep | awk '{print $2}' | xargs sudo kill -9

echo "Killing the core_statelearner server listening on port 60000"
#sudo kill $(lsof -t -i:60000)
#kill -9 $(lsof -t -i:60000) #if we keep this line, log executor will be killed when we pre core.

echo "Killing done!"


source_dir=`pwd`
cd ../../srsran_4g_attacker/build/srsepc/src


sudo ./srsepc epc.conf &> /tmp/epc_fuzzing.log &


cd "$source_dir"

echo "Finished launching start_core.sh"
