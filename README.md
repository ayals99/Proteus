# Proteus
Proteus is a black-box, automated, stateful and property-driven testing framework for wireless communication protocols.
For details, please check out our [paper](https://arxiv.org/pdf/2409.02905) (ACM CCS 2024).

# Tested Protocols and Devices
* 4G LTE: 11 devices (Table 12 in [paper](https://arxiv.org/pdf/2409.02905))
* Bluetooth Low Energy (BLE): 11 devices (Table 13 in [paper](https://arxiv.org/pdf/2409.02905))

# Vulnerabilities 
Proteus uncovered 25 unique issues, including 112 instances. Affected vendors have positively
acknowledged 14 vulnerabilities through 5 CVEs.

# CVEs
* CVE-2024-32911
* CVE-2024-38426
* CVE-2024-20889
* CVE-2024-29155
* CVE-2024-20890

# Instructions to use Proteus
We provide 2 separate folders incorporating testing for 4G LTE and BLE protocol respectively.
We evaluated the framework on Ubuntu 20.04.

# Python Package Requirements
Python >= 3.8 is recommended. `z3-solver`, `setproctitle` and `numpy` packages are required.
For conda users, you can use the provided `environment.yml` file to create a new virtual environment with all required packages. 

```
conda env create -f environment.yml
```

# Running Proteus
1. For the protocol, place the guiding FSM in .dot format in `reference_fsm` folder and mention filename in `test_client_generate_testset_p1.py` file.
2. Provide PLTL properties in `automated_lte_properties.txt` file. Run `skeleton_qre_generator.py` to create trace skeletons (would be placed in `qre_expressions/fuzzing.txt` file, can be manually provided as well).
3. Provide message and fields in `considered_inputs_dir/message_fields_<YOUR_PROTOCOL>.txt` file. Run `input_messages_extractor.py` with the same file to extract a JSON respresentation `considered_inputs_dir/message_fields_<YOUR_PROTOCOL>.json`.
4. For destination state mutation configuration, you can mention possible destination state(s) in `considered_inputs_dir/next_state_mutations.txt` file.
5. For configuring input message mutations, you can place them in `considered_inputs_dir/popular_mutations.txt` file.
6. Run `test_client_generate_testset_p1.py`. This will generate the testcases in `testcases_dump` folder.
7. Run `client_ota_p2.py` which will schedule and execute testcases against the target.

# 4G LTE : srsRAN Adapter
We adopt and modified [srsRAN](https://github.com/srsran) to work as adapter sending concretized messages to the target. To setup the adapter, follow these steps:

* Install dependencies.
```
sudo apt-get install build-essential cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev
```

* Building.
```
cd Modified_cellular_stack
mkdir build && cd build
cmake ..
make -j8
```

* Executing notes: Required configuration files for enodeB and epc are provided in `Modified_cellular_stack/conf`. We also provided scripts to run/kill enodeB and epc. Please put the correct directory in those scripts based on your configuration. Also the `.sh` files provided requires your password. Also remove all `.gitkeep` files from empty directories before running.

# BLE : Setting up Adapter

## System requirements  

- Ubuntu 20.04 machine (tested OS)  
- Python 2.7  (Note: Adapter is a different program than Proteus)
- nRF52480 dongle  

## Setup

### Setup environment

```bash
sudo chmod +x ./setup.sh
sudo ./setup.sh
cd Proteus/BLE-State-Fuzzing/BLEController/bluetooth/smp_server/
/usr/bin/python2.7 setup.py build
sudo /usr/bin/python2.7 setup.py install
mkdir -p ~/.local/lib/python2.7/site-packages/
cp dist/BLESMPServer-1.0.1-py2.7-linux-x86_64.egg ~/.local/lib/python2.7/site-packages
cd ../../

## Setup nRF52840

- Install nRF Connect for Desktop from [Nordic website](https://www.nordicsemi.com/Products/Development-tools/nrf-connect-for-desktop)
- You will need to write the provided hex files to the nRF52840 dongle. You can do this on windows or ubuntu. Windows is more preferable.
- To do this on ubuntu, run the nRF connect in sudo mode and add --no-sandbox flag
- Run the Programmer app from nRF connect
- Connect nRF52840 in DFU mode and write the two files from `nRF52840_hex_files/`
- After writing the hex files, remove the device from workstation and reconnect it.
- To test the Android device, you will need to install the nRF Connect for Mobile app on your device. 
- The device has been tested on Pixel 6, in case you test on another phone you will need to modify the `adb shell input tap X Y` lines to simulate the expected X Y values.


## Run 
- Go to Proteus/proteus_code/address_finder.py, update the file path and device name in the script. 


- Run ble_central
```bash
cd BLE-State-Fuzzing/BLEController
sudo python ble_central.py
```

- Run TCPServer
```bash
cd BLE-State-Fuzzing/TCPServer-Python
sudo python2.7 TCPServer-new.py l <device>
```
Note: For devices thate were not tested by Proteus, please make sure the corresponding function for clicking, rebooting and reset bluetooth are updated to adapt to the tesing device.

- Start Tesing
```bash
cd proteus_code
python client_ota_p2_new.py
```

