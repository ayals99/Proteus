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
# import pyautogui


import os, signal
'''
huwaeiy5: subprocess.call("adb shell input keyevent KEYCODE_WAKEUP & adb shell am start -a android.settings.AIRPLANE_MODE_SETTINGS & adb shell input tap 300 1100",shell=True)
huwaeihonor: subprocess.call("adb shell input keyevent KEYCODE_WAKEUP & adb shell am start -a android.settings.AIRPLANE_MODE_SETTINGS & adb shell input tap 300 300",shell=True)
'''
# GLOBAL VARIABLES
WIN_RUNTIME = ['cmd.exe', '/C']
OS_LINUX_RUNTIME = ['/bin/bash', '-l', '-c']

TASKLIT = 'tasklist'
KILL = ['taskkill', '/F', '/IM']

isWindows = False
environment = ''
DEFAULT_BAUD=115200
DEFAULT_TIMEOUT=1


##################################################################################################
def set_environment():
    global environment, isWindows
    if os.name == 'posix':
        environment = 'linux'
        isWindows = False
    elif os.name == 'nt':
        environment = 'windows'
        isWindows = True
    else:
        raise Exception('EnvironmentError: unknow OS')


# Check if a process is running
def isProcessRunning(serviceName):
    command = ''
    if isWindows:
        command = TASKLIT
    else:
        command = "pidof " + serviceName
        command = OS_LINUX_RUNTIME + [command]

    result = subprocess.check_output(command)
    return serviceName in result


# Used for killing (ADB) process
def killProess(serviceName):
    command = ''
    if isWindows and environment == 'windows':
        command = KILL + [serviceName]
        print command

    elif isWindows == False and environment == 'linux':
        command = "ps -ef | grep " + serviceName + " | grep -v grep | awk '{print $2}' | xargs sudo kill -9"
        command = OS_LINUX_RUNTIME + [command]
    else:
        raise Exception('EnvironmentError: unknow OS')
    subprocess.check_output(command)
    return

def check_pid(pid):        
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True



# def kill(process, kill_signal = signal.SIGINT, hard_kill=False):
#     print("kill() -> kill_signal: {}, hard_kill: {}".format(kill_signal, hard_kill))
#     process_util = psutil.Process(process.pid)
#     print("GOT process_util:", process_util.pid)
#
#     for child_proc in process_util.children(recursive=True):
#         print("Killing Child Proc :", child_proc.pid)
#         # child_proc.kill()
#         os.kill(child_proc.pid, kill_signal)
#         outs, errs = child_proc.communicate(timeout=5)
#
#         print("Child killed :", child_proc.pid)
#
#     # process.kill()
#     os.kill(process.pid, kill_signal)
#
#     print("************* type(process) :", type(process))
#
#     outs, errs = process.communicate(timeout=5)
#
#     if hard_kill:
#         os.system("sudo kill {}".format(process.pid))
#
#     print("Killed :", process.pid)


# def kill(process):
#     os.system("sudo kill -SIGINT {}".format(process.pid))
#     # os.killpg(os.getpgid(process.pid), signal.SIGTERM)
#     # process_util = psutil.Process(process.pid)
#     # print("GOT process_util:", process_util.pid)
#     #
#     # for child_proc in process_util.children(recursive=True):
#     #     print("Killing Child Proc :", child_proc.pid)
#     #     child_proc.terminate()
#     #     print("Child killed :", child_proc.pid)
#     #
#     # process.terminate()
#     print("Killed :", process.pid)

def kill(process, kill_signal = signal.SIGINT, hard_kill=False):
    print("kill() -> kill_signal: {}, hard_kill: {}".format(kill_signal, hard_kill))
    os.kill(process.pid, kill_signal)
    print("done os.kill")
    outs, errs = process.communicate()
    print("Killed :", process.pid)


###################################################################################################

def function_to_be_executed_concurrently():
    procId = subprocess.Popen('bluetoothctl', stdin = subprocess.PIPE)
    procId.communicate('advertise on')

def kill_process():
     
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
  

def randomFunction():
    cmd = ['bluetoothctl', 'advertise', 'on']
    #return "import subprocess; procId = subprocess.Popen(['bluetoothctl', 'advertise', 'on', ], stdin = subprocess.PIPE); procId = subprocess.Popen(['bluetoothctl', 'pairable', 'on', ], stdin = subprocess.PIPE);import sys; print(sys.argv[1]);input('Press Enter..')"
    return "import subprocess; procId = subprocess.Popen(['bluetoothctl', 'advertise', 'on', 'pairable', 'on', ], stdin = subprocess.PIPE);import sys; print(sys.argv[1]);input('Press Enter..')"

processes = None


def handle_reset(client_socket):

    print '--- START: Handling RESET command ---'
    print 'device: ' + device

    if device in ["bluez"]:
        '''
        global processes
        subprocess.call("./remove_bluetooth_devices.sh",shell=True)
        subprocess.call("sudo hciconfig hci0 down",shell=True)
        time.sleep(1)
        subprocess.call("sudo hciconfig hci0 up",shell=True)
        subprocess.call("sudo /etc/init.d/bluetooth  restart",shell=True)
        time.sleep(1)
        subprocess.call("sudo systemctl restart bluetooth.service",shell=True)
        time.sleep(1)
        if processes is not None:
            kill_process()
        time.sleep(1)
        subprocess.call("sudo rmmod btusb",shell=True)
        time.sleep(1)
        subprocess.call("sudo modprobe btusb",shell=True)
        if platform.system() == "Windows":
            new_window_command = "cmd.exe /c start".split()
        else:  #XXX this can be made more portable
            new_window_command = "x-terminal-emulator -e".split()
        echo = [sys.executable, "-c",randomFunction()]
        processes = Popen(new_window_command + echo + ["New Bluetoothctl thread"])
        processes.wait()
        subprocess.call("./remove_bluetooth_devices.sh",shell=True)
        time.sleep(1)
        client_socket.send('DONE\n')
        '''
        subprocess.call("./remove_bluetooth_devices.sh",shell=True)
        subprocess.call("sudo hciconfig hci0 down",shell=True)
        time.sleep(1)
        subprocess.call("./remove_bluetooth_devices.sh",shell=True)
        subprocess.call("sudo hciconfig hci0 up",shell=True)
        #subprocess.call("sudo /etc/init.d/bluetooth  restart",shell=True)
        time.sleep(1)
        subprocess.call("./remove_bluetooth_devices.sh",shell=True)
        
        client_socket.send('DONE\n')
        


    
        print "initial sleep"
        time.sleep(2)

       
        # time.sleep(2)
        os.system("adb shell input tap 1000 550")               # turn off switch
        time.sleep(2)
      
        os.system("adb shell input swipe 642 20 730 1500")  
        time.sleep(1)
        os.system("adb shell input tap 265 320")
        time.sleep(1)
        os.system("adb shell input tap 265 320")
        time.sleep(1)
        os.system("adb shell input swipe 730 1500 642 20") 
        # os.system("adb shell input tap 750 350")                # adv tab
        # time.sleep(2)
        os.system("adb shell input tap 1000 550")               # turn on switch
        time.sleep(2)

        client_socket.send('DONE_RESET\n')
    elif device in ["oppo"]:
        print "initial sleep"
        time.sleep(1)
       
        os.system("adb shell svc bluetooth disable")
        time.sleep(2)
        os.system("adb shell svc bluetooth enable")
        time.sleep(4)
    
        
        os.system("adb shell input tap 1000 530")               # turn off switch
        time.sleep(1)

    

        client_socket.send('DONE_RESET\n')



    elif device in ['esp32']:
        time.sleep(1)
        print "start"
        os.system("./esp32.sh")
        # time.sleep(2)
        print "end"
        client_socket.send('DONE\n')
    # elif device in ['ESP_BLE_ANCS']:
    #     time.sleep(1)
    #     print "start"
    #     os.system("./esp32.sh")
    #     # subprocess.Popen("./esp32.sh", shell=True)
    #     time.sleep(1)
    #     print "end"
    #     client_socket.send('DONE\n')

    
    elif device in ["s10"]:
        time.sleep(1)
        os.system("adb shell settings put global airplane_mode_on 1")
        time.sleep(2)
        os.system("adb shell settings put global airplane_mode_on 0")
        time.sleep(2)
        os.system("adb shell input tap 1000 530")               # turn off switch
        time.sleep(1)
        client_socket.send('DONE_RESET\n')
    elif device in ["hisense"]:
        time.sleep(1)
        os.system("adb shell am start -a android.bluetooth.adapter.action.REQUEST_DISABLE")
        time.sleep(1)
        os.system("adb shell input tap 500 872")               
        os.system("adb shell am start -a android.bluetooth.adapter.action.REQUEST_ENABLE")
        time.sleep(1)
        os.system("adb shell input tap 500 872")               
        time.sleep(2)
        os.system("adb shell input tap 650 330")               # turn off switch
        time.sleep(1)
        client_socket.send('DONE_RESET\n')
    elif device in ["sony"]:
        time.sleep(1)
        os.system("adb shell svc bluetooth disable")
        time.sleep(1)
        os.system("adb shell svc bluetooth enable")
        time.sleep(3)
        os.system("adb shell input tap 991 457")               # turn off switch
        time.sleep(1)
        client_socket.send('DONE_RESET\n')
    elif device in ["moto"]:
        time.sleep(1)
        os.system("adb shell svc bluetooth disable")
        time.sleep(1)
        os.system("adb shell svc bluetooth enable")
        time.sleep(3)
        os.system("adb shell input tap 991 457")               # turn off switch
        time.sleep(1)
        client_socket.send('DONE_RESET\n')
    elif device in ["pixel7"]:
        time.sleep(1)
        os.system("adb shell svc bluetooth disable")
        time.sleep(1)
        os.system("adb shell svc bluetooth enable")
        time.sleep(3)
        os.system("adb shell input tap 991 457")               # turn off switch
        time.sleep(1)
        client_socket.send('DONE_RESET\n')
    elif device in ["pixel6"]:
        time.sleep(1)
        os.system("adb shell svc bluetooth disable")
        time.sleep(1)
        os.system("adb shell svc bluetooth enable")
        time.sleep(3)
        os.system("adb shell input tap 991 457")               # turn off switch
        time.sleep(1)
        client_socket.send('DONE_RESET\n')
    elif device in ["a22"]:
        time.sleep(1)
        os.system("adb shell input tap 994 325")
        time.sleep(1)
        os.system("adb shell svc bluetooth disable")
        time.sleep(1)
        os.system("adb shell svc bluetooth enable")
        time.sleep(3)
        os.system("adb shell input tap 1000 530")               # turn off switch
        time.sleep(1)
        client_socket.send('DONE_RESET\n')
    elif device in ["s6"]:
        os.system("adb shell input swipe 737 50 737 2100 ")
        time.sleep(0.5)
        os.system("adb shell input tap 1264 335")
        time.sleep(1.5)
        os.system("adb shell input tap 1264 335")
        time.sleep(0.5)
        os.system("adb shell input tap 855 2130")
        time.sleep(12)
        os.system("adb shell input tap 855 2130")
        time.sleep(0.5)
        os.system("adb shell input tap 1300 657")
        time.sleep(0.5)
        client_socket.send('DONE_RESET\n')

    else:
        time.sleep(1)
        client_socket.send('DONE\n')         
    print '### DONE: Handling RESET command ###'




def handle_accept_pair(client_socket, ack_required):
    # adb tap condition
    
    if device in ["oppo"]:
        print("got accept pair in oppo")
        time.sleep(1)
        os.system("adb shell input tap 172 1277")  # allow access to contacts and call logs, just need to click once and it will remember
        time.sleep(0.1)
        os.system("adb shell input tap 779 1400")
    elif device in ["pixel7"]:
        print("got accept pair in pixel7")
        time.sleep(1.5)
        os.system("adb shell input tap 190 445")
        time.sleep(0.3)
        os.system("adb shell input tap 180 1238")
        time.sleep(0.1)
        os.system("adb shell input tap 900 1375")
    elif device in ["pixel6"]:
        print("got accept pair in pixel6")
        time.sleep(1.5)
        os.system("adb shell input tap 190 445")
        time.sleep(0.3)
        os.system("adb shell input tap 180 1238")
        time.sleep(0.1)
        os.system("adb shell input tap 900 1375")
    elif device in ["s10"]:
        print("got accept pair in s10")
        time.sleep(1.5)
        os.system("adb shell input tap 827 1988") 
    elif device in ["hisense"]:
        print("got accept pair in hisense")
        time.sleep(1.5)
        os.system("adb shell input tap 149 281")
        time.sleep(0.3)
        os.system("adb shell input tap 222 790")
        time.sleep(0.1)
        os.system("adb shell input tap 470 900")
    elif device in ["sony"]:
        print("got accept pair in sony")
        time.sleep(1.8)
        os.system("adb shell input tap 224 387") 
        time.sleep(0.3)
        os.system("adb shell input tap 200 1233")
        time.sleep(0.1)
        os.system("adb shell input tap 910 1357")
    elif device in ["moto"]:
        print("got accept pair in moto")
        time.sleep(2.0)
        os.system("adb shell input tap 176 385") 
        time.sleep(0.3)
        os.system("adb shell input tap 900 1300")
    elif device in ["a22"]:
        print("got accept pair in a22")
        time.sleep(1.5)
        os.system("adb shell input tap 788 2100")


    if(ack_required):
        client_socket.send('DONE\n')
        print '### DONE: Handling accept pair command ###'
        
        



def handle_accept_pair_confirm(client_socket, ack_required):     # this is for no_sc that will pop up two times 
    # adb tap condition

        #os.system("adb shell input tap 589 783")
        
    if device in ["oppo"]:  
        print("got accept pair in oppo")
        time.sleep(2)
        os.system("adb shell input tap 172 1277")
        time.sleep(0.1)
        os.system("adb shell input tap 779 1400")
        time.sleep(1)
        print("got accept pair in oppo")
        os.system("adb shell input tap 779 1400")
    elif device in ["s10"]:
        print("got accept pair in s10")
        time.sleep(1.5)
        os.system("adb shell input tap 827 1988")
        time.sleep(0.3)
        os.system("adb shell input tap 827 1988")
    elif device in ["hisense"]:
        print("got accept pair in hisense")
        time.sleep(1.5)
        os.system("adb shell input tap 149 281")
        time.sleep(0.3)
        os.system("adb shell input tap 222 790")
        time.sleep(0.1)
        os.system("adb shell input tap 470 900")
        time.sleep(0.5)
        os.system("adb shell input tap 149 281")
        time.sleep(0.1)
        os.system("adb shell input tap 470 900")
    elif device in ["sony"]:
        print("got sm_random_send in sony")
        time.sleep(2)
        os.system("adb shell input tap 224 387") 
        time.sleep(0.3)
        os.system("adb shell input tap 910 1357")
    elif device in ["moto"]:
        print("got accept_pair_confirm in moto")
        time.sleep(2.0)
        os.system("adb shell input tap 176 385") 
        time.sleep(0.3)
        os.system("adb shell input tap 900 1300")
        time.sleep(1.0)
        os.system("adb shell input tap 176 385") 
        time.sleep(0.3)
        os.system("adb shell input tap 900 1300")
    elif device in ["a22"]:
        print("got accept pair in a22")
        time.sleep(1.5)
        os.system("adb shell input tap 788 2100")
        time.sleep(0.3)
        os.system("adb shell input tap 788 2100")
    elif device in ["pixel7"]:
        print("got sm_random_send in pixel7")
        time.sleep(2)
        os.system("adb shell input tap 190 445")
        time.sleep(0.2)
        os.system("adb shell input tap 900 1375")
    elif device in ["pixel6"]:
        print("got sm_random_send in pixel6")
        time.sleep(2)
        os.system("adb shell input tap 190 445")
        time.sleep(0.2)
        os.system("adb shell input tap 900 1375")

    if(ack_required):
        client_socket.send('DONE\n')
        print '### DONE: Handling handle_accept_pair_confirm command ###'


def handle_dh_key_confirm(client_socket, ack_required):
    # adb tap condition

        #os.system("adb shell input tap 589 783")
           

    if(ack_required):
        client_socket.send('DONE\n')
        print '### DONE: Handling handle_dh_key_confirm command ###'



def handle_reboot(client_socket):
    if device in ["oppo"]:
        os.system("adb shell input tap 997 355")
        time.sleep(0.5)
        os.system("adb shell svc bluetooth disable")     
        time.sleep(2)
        os.system("adb shell svc bluetooth enable")
        time.sleep(2)
        os.system("adb shell svc bluetooth disable")     
        time.sleep(2)
        os.system("adb shell svc bluetooth enable")
        time.sleep(2)
        os.system("adb shell svc bluetooth disable")      
        time.sleep(2)
        os.system("adb shell svc bluetooth enable")
        time.sleep(2)
        os.system("adb shell input tap 960 585")               # turn on switch
        time.sleep(1)
    elif device in ["s10"]:
        time.sleep(1)
        os.system("adb shell settings put global airplane_mode_on 1")
        time.sleep(2)
        os.system("adb shell settings put global airplane_mode_on 0")
        time.sleep(2)
        os.system("adb shell settings put global airplane_mode_on 1")
        time.sleep(2)
        os.system("adb shell settings put global airplane_mode_on 0")
        time.sleep(2)
        os.system("adb shell settings put global airplane_mode_on 1")
        time.sleep(2)
        os.system("adb shell settings put global airplane_mode_on 0")
        time.sleep(2)
        os.system("adb shell input tap 1000 530")               # turn off switch
        time.sleep(1)
    elif device in ["hisense"]:
        os.system("adb reboot")                                 # reboot phone
        time.sleep(32)
        os.system("adb shell input swipe 167 1300 664 435 ")    # unlock phone 1
        time.sleep(2)
        os.system("adb shell input tap 463 1222")               # nordic app
        time.sleep(3)
        os.system("adb shell input tap 543 210")                # advertiser tab
        time.sleep(2)
    elif device in ["sony"]:
        os.system("adb reboot")                                 # reboot phone
        time.sleep(45)
        os.system("adb shell input swipe 535 1921 550 900 ")    # unlock phone 1
        time.sleep(0.3)
        os.system("adb shell input swipe 535 1921 550 900 ")    # unlock phone 1
        time.sleep(0.3)
        os.system("adb shell input tap 547 2475")
        time.sleep(1)
        os.system("adb shell input tap 740 1718")               # nordic app
        time.sleep(3)
        os.system("adb shell input tap 694 297")                # advertiser tab
        time.sleep(2)
    elif device in ["moto"]:
        os.system("adb reboot")                                 # reboot phone
        time.sleep(28)
        os.system("adb shell input swipe 167 1900 930 668 ")    # unlock phone 1
        time.sleep(1)
        os.system("adb shell input tap 555 2312")
        time.sleep(1)    
        os.system("adb shell input tap 660 1720")               # nordic app
        time.sleep(3)
        os.system("adb shell input tap 700 300")                # advertiser tab
        time.sleep(1)
    elif device in ["pixel7"]:
        os.system("adb reboot")                                 # reboot phone
        time.sleep(25)
        os.system("adb shell input swipe 167 1900 930 668 ")    # unlock phone 1
        time.sleep(1)
        os.system("adb shell input tap 555 2312")
        time.sleep(1)    
        os.system("adb shell input tap 660 1720")               # nordic app
        time.sleep(3)
        os.system("adb shell input tap 700 350")                # advertiser tab
        time.sleep(1)
    elif device in ["pixel6"]:
        os.system("adb reboot")                                 # reboot phone
        time.sleep(25)
        os.system("adb shell input swipe 167 1900 930 668 ")    # unlock phone 1
        time.sleep(1)
        os.system("adb shell input tap 555 2312")
        time.sleep(1)    
        os.system("adb shell input tap 660 1720")               # nordic app
        time.sleep(3)
        os.system("adb shell input tap 700 350")                # advertiser tab
        time.sleep(1)
    elif device in ["a22"]:
        time.sleep(1)
        os.system("adb shell svc bluetooth disable")
        time.sleep(1)
        os.system("adb shell svc bluetooth enable")
        time.sleep(3)
        os.system("adb shell svc bluetooth disable")
        time.sleep(1)
        os.system("adb shell svc bluetooth enable")
        time.sleep(3)
        os.system("adb shell svc bluetooth disable")
        time.sleep(1)
        os.system("adb shell svc bluetooth enable")
        time.sleep(3)
        os.system("adb shell input tap 800 800")
        time.sleep(0.5)               
        os.system("adb shell input tap 1000 530")               # turn switch
        time.sleep(1)
    elif device in ["s6"]:
        os.system("adb shell input swipe 737 50 737 2100 ")
        time.sleep(0.5)
        os.system("adb shell input tap 1264 335")
        time.sleep(1.5)
        os.system("adb shell input tap 1264 335")
        time.sleep(0.5)
        os.system("adb shell input tap 855 2130")
        time.sleep(12)
        os.system("adb shell input tap 855 2130")
        time.sleep(0.5)
        os.system("adb shell input tap 1300 657")
        time.sleep(0.5)
 

    client_socket.send('DONE\n')
    print '### DONE: Reboot Device ###'

def sm_random_send(client_socket,ack_required):

    # if device in ["oppo"]:
    #     print("got accept pair in oppo")
    #     time.sleep(2)
    #     os.system("adb shell input tap 779 1400")
    if device in ["pixel7"]:
        print("got sm_random_send in pixel7")
        time.sleep(2)
        os.system("adb shell input tap 190 445")
        time.sleep(0.2)
        os.system("adb shell input tap 180 1215")
        time.sleep(0.2)
        os.system("adb shell input tap 900 1375")
    elif device in ["pixel6"]:
        print("got sm_random_send in pixel6")
        time.sleep(2)
        os.system("adb shell input tap 190 445")
        time.sleep(0.2)
        os.system("adb shell input tap 180 1215")
        time.sleep(0.2)
        os.system("adb shell input tap 900 1375")
    elif device in ["oppo"]:
        print("got sm_random_send in oppo")
        time.sleep(1)
        os.system("adb shell input tap 779 1400")
    elif device in ["s10"]:
        print("got sm_random_send in s10")
        time.sleep(2)
        os.system("adb shell input tap 827 1988")
    elif device in ["hisense"]:
        print("got sm_random_send in hisense")
        time.sleep(2)
        os.system("adb shell input tap 149 281")
        time.sleep(0.5)
        os.system("adb shell input tap 470 900")
    elif device in ["sony"]:
        print("got sm_random_send in sony")
        time.sleep(2)
        os.system("adb shell input tap 224 387") 
        time.sleep(0.3)
        os.system("adb shell input tap 910 1357")
    elif device in ["moto"]:
        print("got sm_random_send in moto")
        time.sleep(2.0)
        os.system("adb shell input tap 176 385") 
        time.sleep(0.3)
        os.system("adb shell input tap 900 1300")
    elif device in ["a22"]:
        print("got sm_random_send in a22")
        time.sleep(2)
        os.system("adb shell input tap 788 2100")


    if(ack_required):
        client_socket.send('DONE\n')
        print '### DONE: Handling handle_sm_rand_send command ###'
        


####################################################################################################
# thread fuction
def client_handler(client_socket):

    while True:


        data = client_socket.recv(1024)

        if not data:
            print('Bye')
            # lock released on exit
            print_lock.release()
            break

        command = data.lower().strip()

        print "GOT COMMAND : " + command

        if "reset" in command:
            handle_reset(client_socket)

        if "accept_pair_confirm" in command:
            handle_accept_pair_confirm(client_socket, True)
        elif "accept_pair_no_sc" in command:   # oppo will pop up second window after handle_accept_pair when using no_sc, oob will not
            handle_accept_pair_confirm(client_socket, True)
        elif "accept_pair" in command:
            handle_accept_pair(client_socket, True)
        
        if "dh_key_confirm" in command:
            handle_dh_key_confirm(client_socket, True)
            
        if "sm_random_send" in command:
            sm_random_send(client_socket, True)
        
        if "reboot" in command:
            handle_reboot(client_socket)

    client_socket.close()

def Main():
    global environment
    global device
    host = ""
    # if (len(sys.argv)<2):
    #     print 'Usage: TCPServer-new.py <hostname> l,w'
    #     exit()

    if (len(sys.argv)<3):
        print 'Usage: TCPServer-new.py <hostname> l,w <device name> bluez, dongle, dialog, nordic, nrf5340dk, btstack_dell'
        exit()

    if sys.argv[1] is "l":
		environment = "linux"
    else:
		environment = "windows"

    device = sys.argv[2] 
    
    print str(sys.argv)

    print '#############################################'
    print '######### BLE Controller started #############'
    print '#############################################'

    print 'Initializing the controller...'
    port = 61000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    print("socket binded to post", port)

    # put the socket into listening mode
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
