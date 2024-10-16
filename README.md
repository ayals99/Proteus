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
We provide 2 separate branches incorporating testing for 4G LTE and BLE protocol respectively.
We evaluated the framework on Ubuntu 20.04.

# Python Package Requirements
Python >= 3.8 is recommended. `z3-solver`, `setproctitle` and `numpy` packages are required.
For conda users, you can use the provided environment.yaml file to create a new virtual environment with all required packages. 

# Running Proteus
1. For the protocol, place the guiding FSM in .dot format in `reference_fsm` folder and mention filename in `test_client_generate_testset_p1.py` file.
2. Provide PLTL properties in `automated_lte_properties.txt` file. Run `skeleton_qre_generator.py` to create trace skeletons (would be placed in `qre_expressions/fuzzing.txt` file, can be manually provided as well).
3. Provide message and fields in `considered_inputs_dir/message_fields_lte.txt` file.
4. Run `test_client_generate_testset_p1.py`. This will generate the testcases in `testcases_dump` folder.
5. Run `client_ota_p2.py` which will schedule and execute testcases against the target.

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
