#!/bin/bash
#echo "<YOUR PASSWORD>" | sudo -S ./kill_core.sh 

if [ "$EUID" -ne 0 ]
	then echo "Need to run as root"
	exit
fi

echo "Killing all ports"
kill -9 $(lsof -t -i:60000)
kill -9 $(lsof -t -i:60001)
kill -9 $(lsof -t -i:61000)
echo "Killing all ports"