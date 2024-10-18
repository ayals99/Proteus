#!/bin/bash 
echo "resetting esp32 device: in shell"

# cd /home/synsec/esp/gatt_security_server
# pwd

# export IDF_PATH=/home/synsec/esp/esp-idf
# . /home/synsec/esp/esp-idf/export.sh; idf.py -p /dev/ttyUSB0 flash
# idf.py set-target esp32c3
# idf.py build

# idf.py -p /dev/ttyUSB0 flash

sudo su <<EOF
alias python=python3.8; export IDF_PATH=/home/usr/esp/esp-idf; cd /home/usr/esp/ble_ancs; . /home/usr/esp/esp-idf/export.sh; idf.py set-target esp32c3; idf.py -p /dev/ttyUSB0 flash
EOF


# alias python=python3.7; python --version; export IDF_PATH=/home/synsec/esp/esp-idf; cd /home/synsec/esp/gatt_security_server; pwd; . /home/synsec/esp/esp-idf/export.sh; idf.py -p /dev/ttyUSB0 flash
