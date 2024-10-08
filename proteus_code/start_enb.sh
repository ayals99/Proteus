#!/bin/bash
#echo "<YOUR PASSWORD>" | sudo -S ./start_gnb.sh

if [ "$EUID" -ne 0 ]
	then echo "Need to run as root"
	exit
fi

echo "Launching start_gnb.sh"

echo "Killing any already running srsgnb process"
pkill -9 -f srsenb
# ps -ef | grep srsenb | grep -v grep | awk '{print $2}' | xargs sudo kill -9

echo "Kiliing the enodeb_statelearner server listening on port 60000"
#sudo kill $(lsof -t -i:60001)
#kill -9 $(lsof -t -i:60001)

source_dir=`pwd`

cd ../../srsran_4g_attacker/build/srsenb/src

rm /tmp/enb_fuzzing.log

./srsenb enb.conf &> /tmp/enb_fuzzing.log &

cd "$source_dir"

echo "srsenb is running in the background"
echo "log is saved to /tmp/enb_fuzzing.log"
echo "Finished lauching start_gnb.sh"

