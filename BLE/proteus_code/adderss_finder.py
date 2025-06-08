import socket
import time
import subprocess
import select
import threading
import os





deviceName = "WEIS0671"     #"Zephyr", "user_Pixel" # modify device name here
deviceAddress = "00:00:00:00:00:00"    



def SlaveAddressFinder(device_name = "WEIS0671"): # modify device name here
    print("SlaveAddressFinder for device: " + device_name)
    global deviceName
    deviceName = device_name


def getDeviceName():
    return deviceName

def setDeviceName(deviceName):
    deviceName = deviceName

def getDeviceAddress():
    return deviceAddress

def setDeviceAddress(device_add):
    global deviceAddress
    deviceAddress = device_add


def reset_blueZ(timeoutSeconds):
    code_path = "/home/tester/Desktop/Proteus/BLE"
    try:
        subprocess.Popen(
            os.path.join(code_path, "BLE-State-Fuzzing/log_executor/src/remove_bluetooth_devices.sh"), 
            shell=True)
        time.sleep(2)

        subprocess.Popen(f"echo \"password\" | sudo -S {os.path.join(code_path, 'BLE-State-Fuzzing/off-breder.sh')}", shell=True) # modify password

        time.sleep(1)
        # Uncomment the next line to print output from the script
        # print("Reset: ", process.communicate()[0].decode())

    except Exception as e:
        print(e)

    return True

def findAddressWithName(timeout_seconds):
    # resetting bluetooth devices. Otherwise wrong address may come up
    reset_thread = threading.Thread(target=reset_blueZ, args=(timeout_seconds,))
    reset_thread.start()

    try:
        
        process = subprocess.Popen("bluetoothctl", stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        process.stdin.write(b"scan on\n")
        process.stdin.flush()
        timeout_at = time.time() + timeout_seconds
        while time.time() <= timeout_at:
            if select.select([process.stdout], [], [], 0.1)[0]:
                line = process.stdout.readline().decode().strip()
                if not line:
                    break
                #print("PROCESS OUTPUT: " + line)
                if (getDeviceName() not in line):
                    continue
                if "NEW" not in line:
                    continue    
                print("PROCESS OUTPUT: " + line)
                line_parts = line.split()
                if line_parts[2] == "Device":
                    process.terminate()
                    new_address = line_parts[3].lower()
                    print("Found address: " + new_address)
                    if getDeviceAddress().lower() == new_address and new_address == "00:00:00:00:00:00":
                        return False
                    else:
                        setDeviceAddress(new_address)
                        return True
                time.sleep(0.5)
        process.terminate()
    except Exception as e:
        print(e)
    return False

def findAddress(timeout_seconds):
    updated_address = False
    print("Finding address for device: " + getDeviceName())
    updated_address = findAddressWithName(timeout_seconds)
    print("Updated address: " + deviceAddress)
    
    return updated_address




if __name__ == "__main__":
    findAddress(10)
    slave_address = getDeviceAddress()
    print("New slave address: " + slave_address)
