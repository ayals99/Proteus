#!/usr/bin/env bash

# System packages
#sudo mkdir -p /usr/share/man/man1 # make sure man1 dir exists
#sudo apt-get install build-essential python-pip python-dev graphviz libgraphviz-dev libssl-dev \
#pciutils kmod wireless-tools net-tools dnsmasq iproute2 iptables aircrack-ng freeradius python-matplotlib -y
# Kernel header & wifi subsytem
#sudo apt install linux-headers-$(uname -r) linux-modules-extra-$(uname -r) -y

set -e # exit on error
# Python packages
sudo python2.7 -m pip install \
pyserial==3.4 \
pyrecord==1.0.1 \
psutil==5.6.3 \
numpy==1.16 \
Flask==0.11.1 \
pygraphviz==1.5 \
colorama==0.4.1 \
cryptography==2.7 \
pycryptodome==3.8.2 \
socketio==0.1.7 \
ddt==1.2.1 \
mock==3.0.5 \
Flask-SocketIO==4.1.0 \
logbook==1.4.4 \
gevent==1.2.2 \
pycallgraph==1.0.1 \
pygmo==2.10 \
socketIO-client==0.7.2

# Build python modules
sh -c "cd bluetooth/smp_server/ && make && sudo make install"

exit 0
