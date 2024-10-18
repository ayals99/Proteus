#!/usr/bin/python
# import socket programming library
import socket
import os
import time
import sys
import serial
from stat import *
import logging
import signal
import subprocess
# import thread module
from thread import *
import threading
from atsend import *
global device
global environment
print_lock = threading.Lock()
import sys
import platform
from subprocess import Popen
import time
import psutil

def Main():
    # os.system("adb shell input tap 985 530")
    # time.sleep(2)

    # doing this permanently turns bluetooth off after a few minutes
    os.system("adb shell cmd statusbar expand-notifications")
    time.sleep(2)
    # os.system("adb shell input tap 450 450")    # turn device bluetooth off
    # time.sleep(5)
    # os.system("adb shell input tap 450 450")    # turn device bluetooth on
    # time.sleep(5)
    os.system("adb shell cmd statusbar collapse")
    # time.sleep(2)
            
if __name__ == '__main__':
    Main()