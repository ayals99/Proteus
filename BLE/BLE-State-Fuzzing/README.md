# BLE-State-Fuzzing

First thing you need to flash the driver firmware to the board before starting the python code. The binary firmware code is on the `nRF52_driver_firmware.zip` file. You need to install nrfutil tool to flash the firmware on the board. Remember to pt the nRF52840 on DFU mode before flashing (reset the USB dongle while it is connected to your PC by pressing the small reset button).

You can run the following commands to install the python dependencies and to flash the firmware:

`python -m pip install nrfutil pyserial pycryptodome`

`nrfutil dfu usb-serial -p COM_PORT -pkg nRF52_driver_firmware.zip`

If the previous flashing method didn't work, you can also flash the firmware by using the Programmer App from nRF Connect for Desktop (https://www.nordicsemi.com/Products/Development-tools/nrf-connect-for-desktop), which gives a nice interface to flash the hex firmware (`nRF52_driver_firmware.hex` and `s140_nrf52_6.1.1_softdevice.hex`).  

After flashing the firmware, remove the device from workstation and reconnect it. Now, green lights should turn on.  


Next you need to install the dependencies for the BLEController. You can install using `requirements.sh`. If you get into any issues while install the requirement that may be because of conflicting versions of `python-engineio` and `python-socketio`. If there are any issues make sure to install the following versions:

` python-engineio==3.11.2`

`python-socketio==4.4.0`

Also install bluez-tools with `sudo apt-get install -y bluez-tools`.  

To copy config files to appropriate locations, run `./copy_template_configs.sh`


To test Ubuntu blueZ, before running the programs you need to BluZ on the laptop: `bluetoothctl`. Then give `advertise off` then `advertise on`.  


You need to give Nordic chip address (connected to ble_central.py) as the master address, and the test device address as the slave address `BLEController/addr_config.json`. The master address can be found in the Programmer App from nRF Connect for Desktop. Note the serial number and add ':' after each two hex characters. Also, both slave and master address should be in lower case hex characters.

You may need to change the `device` (arbitrary) and `device_name` (only needed if the slave address changes dynamically) in `ble.properties` file and add device specific conditions in both `TCPServer-new.py`.



Now to run the BLEController: `sudo python ble_central.py`


To run the device controller: `sudo python2.7 TCPServer-new.py l <device>`




***Wireshark***

Add `DLT=157`with payload protocol `nordic_ble` in wireshark to see all BLE packets. You will not be able to Link Layer packets. For link layer only HCI commands will be visible. For the upper layers (L2CAP, SMP, ATT), all the packets should be visible.



***BTStack***
A reset routine has been added to TCPServer for btstack_dell. Directory may need to be changed when deployed in another machine. Example and makefile has been changed.  

To run BTStack:

```bash
cd ./btstack/port/libusb/
make
sudo ./sm_pairing_peripheral
```

To run LCOV:

```bash
cd ./btstack/port/libusb/
lcov --capture --directory ./ --output-file coverage.info
genhtml coverage.info --output-directory out
```

HTML output can be found in `./btstack/port/libusb/out/`  

