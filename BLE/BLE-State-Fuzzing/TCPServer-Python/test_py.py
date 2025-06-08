#!/usr/bin/env python
"""Show messages in two new console windows simultaneously."""
import sys
import platform
from subprocess import Popen
import time


import os, signal
  
def process():
     
    # Ask user for the name of process
    name = "bluetoothctl"
    try:
         
        # iterating through each instance of the process
        for line in os.popen("ps ax | grep " + name + " | grep -v grep"):
            fields = line.split()
             
            # extracting Process ID from the output
            pid = fields[0]
             
            # terminating process
            os.kill(int(pid), signal.SIGKILL)
        print("Process Successfully terminated")
         
    except:
        print("Error Encountered while running script")
  
#procId.communicate('advertise on\ndiscoverable on\npairable on\n')
def randomFunction():
    cmd = ['bluetoothctl', 'advertise', 'on']
    return "import subprocess; procId = subprocess.Popen(['bluetoothctl', 'advertise', 'on'], stdin = subprocess.PIPE);import sys; print(sys.argv[1]);input('Press Enter..')"

messages = 'This is Console1', 'This is Console2'
if platform.system() == "Windows":
    new_window_command = "cmd.exe /c start".split()
else:  #XXX this can be made more portable
    new_window_command = "x-terminal-emulator -e".split()
echo = [sys.executable, "-c",randomFunction()]
processes = Popen(new_window_command + echo + ["New Bluetoothctl thread"])
processes.wait()
#time.sleep(500)
#process()

# wait for the windows to be closed
