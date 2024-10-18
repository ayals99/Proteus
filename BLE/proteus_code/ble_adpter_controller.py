import socket
import time
import subprocess
import adderss_finder
import os
import sys

ble_controller_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
device_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


device_addr_update_needed = "always"
combine_query = False

device_controller_ip_address = "127.0.0.1"
ble_controller_ip_address = "127.0.0.1"
ble_controller_port = 60000
device_controller_port = 61000

pre_reset_counter = 0
scan_req_timeout_counter = 0
num_symbols_after_pre = 0
discon_req_sent = False
con_req_after_reset = False
pair_req_after_reset = False
pre_needed = True
last_pair = ""

pre_counter = 0


unepxected = 0
number_of_queries = 0

device = ""

expectedResults = ["scan_resp",
            "adv_ind",
            "feature_req",
            "feature_resp",
            "length_resp",
            "length_req",
            "mtu_req",
            "version_resp",
            "pair_resp",
            "pair_resp_no_sc",
            "enc_resp",
            "ll_reject",
            "start_enc_req",
            "char_req",
            "pri_resp",
            "pri_req",
            "public_key_response",
            "sm_confirm",
            "sm_random_received",
            "dh_key_response",
            "start_enc_resp",
            "char_resp",
            "att_error",
            "desc_resp",
            "read_resp",
            "mtu_resp",
            "sec_req",
            "enc_pause_resp",
            "unknown_resp",
            "sm_failed",
            "DONE"]


scan_req_expectedResults = [ "scan_resp","null_action"]
con_req_expectedResults = [ "feature_req","null_action"]
feature_res_expectedResults = [ "length_req","null_action"]
length_res_expectedResults = [ "mtu_req","null_action"]
version_req_expectedResults = [ "version_resp","null_action"]
pair_req_expectedResults = [ "pair_resp","pair_resp_no_sc","null_action"]
enc_req_expectedResults = [ "enc_resp","ll_reject","null_action"]
pri_req_expectedResults = [ "pri_resp","null_action"]






def get_expected_result(symbol, result):
    final_result = "null_action"

    expected_results_lookup = {
        "scan_req": scan_req_expectedResults,
        "feature_req": con_req_expectedResults,
        "feature_resp": feature_res_expectedResults,
        "length_resp": length_res_expectedResults,
        "version_req": version_req_expectedResults,
        "pair_req": pair_req_expectedResults,
        "enc_req": enc_req_expectedResults,
        "pri_req": pri_req_expectedResults,
        
    }

    for key, expected_results in expected_results_lookup.items():
        if key in symbol and result in expected_results:
            final_result = result
            break

    return final_result



def init_ble_controller():
    global ble_controller_ip_address
    global ble_controller_port
    global ble_controller_socket
    try:
        print("Connecting to BLE controller...")
    
        ble_controller_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ble_controller_socket.connect((ble_controller_ip_address, ble_controller_port))
        ble_controller_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        print("Connected to BLE Controller")

    except socket.gaierror as e:
        print("Unknown host error:{}".format(e))
        init_ble_controller()
    except socket.error as e:
        print("Socket error:{}".format(e))
        init_ble_controller()
    except Exception as e:
        print(e)
        init_ble_controller()

   



def init_device_con():
    global device_controller_ip_address
    global device_controller_port
    global device_socket
    try:
        print("Connecting to device controller...")
        print("Device controller IP Address: {}".format(device_controller_ip_address))

        device_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        device_socket.connect((device_controller_ip_address, device_controller_port))
        device_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        print("Connected to Device Controller")

    except socket.gaierror as e:
        print("Unknown host error: {}".format(e))
    except socket.error as e:
        print("Socket error: {}".format(e))
    except Exception as e:
        print(e)



def compute_levenshtein_distance(lhs, rhs):
    distance = [[0 for _ in range(len(rhs) + 1)] for _ in range(len(lhs) + 1)]

    for i in range(len(lhs) + 1):
        distance[i][0] = i
    for j in range(len(rhs) + 1):
        distance[0][j] = j

    for i in range(1, len(lhs) + 1):
        for j in range(1, len(rhs) + 1):
            cost = 0 if lhs[i - 1] == rhs[j - 1] else 1
            distance[i][j] = min(
                distance[i - 1][j] + 1,
                distance[i][j - 1] + 1,
                distance[i - 1][j - 1] + cost
            )

    return distance[len(lhs)][len(rhs)]

def get_closest(result, expected_results):
    print("Getting closest of {}".format(result))

    if result in expected_results:
        return result

    min_distance = float('inf')
    correct_word = None

    for word in expected_results:
        distance = compute_levenshtein_distance(result, word)

        if distance < min_distance:
            correct_word = word
            min_distance = distance

    return correct_word

def reset_ble():
    result = ""
    print("Sending symbol: RESET to BLE controller")
    try:
        ble_controller_socket.send("RESET\n".encode())
        time.sleep(3 * 2)
        result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
        print("ACK for RESET_UE: {}".format(result))
        while not result.upper() == "DONE":
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            print("ACK for RESET_UE: {}".format(result))
    except socket.timeout:
        print("Timeout")
    except socket.error as e:
        print(e)
    except Exception as e:
        print(e)
  

    return result

def reset_device():
    result = ""
    print("Sending symbol: RESET to Device controller")
    try:
        time.sleep(1)
        device_socket.send("RESET\n".encode())
        result = device_socket.recv(1024).decode().split('\n')[0].strip()
        print("ACK for RESET_DEVICE: {}".format(result))
    except socket.timeout:
        print("Timeout")
    except socket.error as e:
        print(e)
    except Exception as e:
        print(e)
  

    return result

def reboot_device():
    result = ""
    print("Sending symbol: reboot to Device controller")
    try:
        time.sleep(1)
        device_socket.send("reboot\n".encode())
        result = device_socket.recv(1024).decode().split('\n')[0].strip()
        print("ACK for REBOOT_DEVICE: {}".format(result))
    except socket.timeout:
        print("Timeout")
    except socket.error as e:
        print(e)
    except Exception as e:
        print(e)
  

    return result

def collect_cov(iteration):
    result = ""
    print("Sending symbol: collect_cov to Device controller")
    try:
        time.sleep(1)
        device_socket.send(("collect_cov"+str(iteration)+"\n").encode())
        # result = device_socket.recv(1024).decode().split('\n')[0].strip()
        # print("ACK for RESET_DEVICE: {}".format(result))
    except socket.timeout:
        print("Timeout")
    except socket.error as e:
        print(e)
    except Exception as e:
        print(e)
        
def need_slave_address_update():
    result = ""
    MAX_TRY = 3
    for i in range(MAX_TRY):
        print("Trying to send scan_req. Iteration: " + str(i))
        while not ("scan_resp" in result or "adv_ind" in result):
            try:
                ble_controller_socket.settimeout(5)
                ble_controller_socket.send(("scan_req" + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result)
            except socket.timeout:
                print("Timeout occurred for scan_req")
                result = "null_action"
            except Exception as e:
                print(e)
        if not result.lower() == "null_action":
            return False
    return True




def send_slave_address():
    print("Trying to find new slave address...")

    updated = adderss_finder.findAddress(15) # used to be 15
    if not updated:
        print("Slave address not changed.")
        return False
    slave_address = adderss_finder.getDeviceAddress()
    print("New slave address: " + slave_address)

    try:
        ble_controller_socket.settimeout(15)
        ble_controller_socket.send(f"update_slave_address-{slave_address}\n".encode())

        result = ""
        while (result == "" or
            result == "adv_ind" or
            result == "scan_resp" or
            result == "version_resp"):
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)
        if result.lower() == "done":
            print("Slave address updated successfully")
            return True
    except socket.timeout:
        print("Timeout occurred for update_slave_address")
        global pre_counter
        pre_counter += 1
        if pre_counter == 5:
            reboot_device()
            pre_counter = 0
        reset_ble()
    except Exception as e:
        print(e)

    return False




def pre_initial():   # ends with reset
    global pre_needed

    os.system("adb shell input tap 1000 350")  # tab click 
    time.sleep(1)

    pre_needed = False
    pre_reset_counter = 0
    global combine_query
    global last_pair
    
    if not combine_query:
        print("Sleeping for a bit")
        time.sleep(2)

        result = ""
        result_for_ble_controller = ""
        result_for_device = ""
        reset_done = False

        print("---- Starting RESET ----")
        result_for_ble_controller = reset_ble()  #comment here in debuging to save time
        result_for_device = reset_device()
        need_update = False
        update_slave_success = False

        if device_addr_update_needed == "test":
            need_update = need_slave_address_update()
        elif device_addr_update_needed == "always":
            need_update = True

        print("Slave address needs update : ", need_update)

        while need_update and not update_slave_success:
            update_slave_success = send_slave_address()
            print("Slave address update successful : ", update_slave_success)

            if not update_slave_success:
                print("Sending symbol: reset to Device controller")
                time.sleep(1.5)
                update_slave_success = send_slave_address()
                if not update_slave_success:
                    reboot_device()   
                    result_for_device = reset_device()
                    print("ACK for reset: ", result_for_device)

        con_req_after_reset = False  

        just_send_version_req = False   
        ble_controller_socket.settimeout(3)
        try:
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            result = ""
        except socket.timeout as e:        
            result = "null_action"
        if just_send_version_req == False and result == "version_resp":
            result = ""
        try:
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            result = ""
        except socket.timeout as e:        
            result = "null_action"
   

        result = step("discon_req")
        result = step("scan_req")
        if result != "scan_resp":
            pre_reset_counter += 1
            print("*** PRE NOT WORKING. RESET COUNTER : ", pre_reset_counter, " ***1")
            pre_needed = True
            reboot_device()
            pre_initial()
            return
        result_for_ble_controller = reset_ble()
  
        
        num_symbols_after_pre = 0
        pre_reset_counter = 0
        discon_req_sent = False
        pair_req_after_reset = False
        last_pair = ""

        print("---- RESET DONE ----")
        try:
            time.sleep(2)
        except Exception as e:
            print(e)






def step(symbol):
    print("STEP: " + symbol)
    global num_symbols_after_pre
    num_symbols_after_pre += 1
    global last_pair
    try:
        time.sleep(2) # Sleep for 2 seconds
    except Exception as e:
        print(e)

    result = ""
    result_ble_controller = ""
    scan_result = ""
    result_for_device = ""
    
    if symbol.startswith("scan_req"):
        got_scan_resp = False
        try:
            ble_controller_socket.settimeout(5)
            ble_controller_socket.send((symbol + "\n").encode())

            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result and result[0] == ' ':
                result = result[1:]
                
            result = get_closest(result,expectedResults)

            while "adv_ind" in result or "DONE" in result or "True" in result or "False" in result or not "scan_resp" in result:
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()

                if result and result[0] == ' ':
                    result = result[1:]

                result = get_closest(result,expectedResults)
                
    


            while "scan_resp" in result: # consume all scan_resps
                print("** GOT scan_resp IN WHILE ***")
                got_scan_resp = True
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()

                if result and result[0] == ' ':
                    result = result[1:]
                    
                result = get_closest(result,expectedResults)
                
            if got_scan_resp:
                global scan_req_timeout_counter
                scan_req_timeout_counter = 0
                result = "scan_resp"
            
        except socket.timeout as e:
            
            if got_scan_resp:
                scan_req_timeout_counter = 0
                return "scan_resp"
            else:
                print(f"Timeout occured for {symbol} for {scan_req_timeout_counter} times...")
                scan_req_timeout_counter += 1
                if scan_req_timeout_counter > 5:
                    scan_req_timeout_counter = 0
                    return "null_action"
                else:
                    return step("scan_req")

        except IOError as e:
            print(e)
        
    elif (symbol.startswith("con_req") or symbol.startswith("pair_req") 
    or symbol.startswith("pair_confirm_wrong_value") or symbol.startswith("pair_confirm")
    or symbol.startswith("pair_req_no_sc") or symbol.startswith("pair_req_oob")
    or symbol.startswith("pair_req_no_sc_bonding") or symbol.startswith("sm_random_send")
    or symbol.startswith("dh_check") or symbol.startswith("start_enc_resp")
    or symbol == "enc_pause_req" or symbol == "enc_pause_resp" or symbol.startswith("start_enc_resp_plain")
    or symbol == "enc_pause_req_plain" or symbol == "enc_pause_resp_plain"
    or symbol.startswith("dh_check_invalid") or symbol.startswith("sign_info")):
        try:
            result1 = ""

            if symbol.startswith("con_req"):
                print("extra timeout for con_req")
                ble_controller_socket.settimeout(5)
                con_req_after_reset = True
                discon_req_sent = False
                
            
            elif symbol.startswith("dh_check"):
                print("extra timeout for dh_check")
                ble_controller_socket.settimeout(10)
            elif symbol.startswith("pair_req"):
                print("extra timeout for pair_req")
                ble_controller_socket.settimeout(8)
                # device_socket.send(("accept_pair" + "\n").encode())
                pair_req_after_reset = True
                
            else:
                ble_controller_socket.settimeout(5)

            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()

            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)

            if not "con_req" in symbol and "feature_req" in result:
                ble_controller_socket.settimeout(5)
                ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
            while ("adv_ind" in result or "scan_resp" in result or "DONE" in result or "True" in result 
               or "False" in result or "char_resp" in result or "mtu_req" in result or "att_error" in result):
                if "pair_req" in symbol and "mtu_req" in result:
                    print("mtu_req caught in pair_req")
                    time.sleep(0)
                    ble_controller_socket.settimeout(5)
                    ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)

                if "feature_req" in result:
                    result = "null_action"

            if "feature_req" in result:
                result = "null_action"
        except socket.timeout:
            print(f"Timeout occurred for in the first case: {symbol}")
            result = "null_action"

            if "feature_req" in result:
                result = "null_action"
        except IOError as e:
            print(e)
        except Exception as e: 
            print(e)
            
    elif symbol.startswith("sec_service_req"):
        try:
            print("sec_service_req case!")
            result1 = ""
            ble_controller_socket.settimeout(5)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)

            if "con_req" not in symbol and "feature_req" in result:
                ble_controller_socket.settimeout(5)
                ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)

            while "adv_ind" in result or "scan_resp" in result or "DONE" in result or "True" in result or "False" in result or "char_resp" in result:
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)

                if "con_req" not in symbol and "feature_req" in result:
                    result = "null_action"

        except socket.timeout:
            print(f"Timeout occurred for {symbol}")
            if not result.startswith("desc_resp"):
                result = "null_action"

        except IOError as e:
            print(e)

    elif "feature_req" in symbol or "feature_resp" in symbol:
        try:
            result1 = ""
            ble_controller_socket.settimeout(7)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)

            while "adv_ind" in result or "scan_resp" in result or "DONE" in result or "True" in result or "False" in result or "char_resp" in result or "mtu_req" in result or "att_error" in result:
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)

        except socket.timeout:
            print(f"Timeout occurred for in the first case: {symbol}")
            result = "null_action"

        except IOError as e:
            print(e)
    
    elif symbol.startswith("version_req") or symbol.startswith("version_resp"):
        try:
            print("version_req from learner!")
            result1 = ""
            ble_controller_socket.settimeout(8)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)

            while "adv_ind" in result or "scan_resp" in result or "DONE" in result or "True" in result or "False" in result or "feature_req" in result:
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
                if "con_req" not in symbol and "feature_req" in result:
                    result = "null_action"
        except socket.timeout:
            print(f"Timeout occurred for in the first case: {symbol}")
            if not result.startswith("desc_resp"):
                result = "null_action"

        except IOError as e:
            print(e)
     
    elif symbol.startswith("length_req") or symbol.startswith("length_resp"):
        try:
            print("length_req from learner (increased timer)!")
            result1 = ""
            time.sleep(0.5)
            ble_controller_socket.settimeout(8)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)
            while ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("feature_req" in result) or ("char_resp" in result):
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
                if ("con_req" not in symbol) and ("feature_req" in result):
                    result = "null_action"
        except socket.timeout:
            print("Timeout occurred for " + symbol)
            result = "null_action"
        except IOError as e:
            print(e)
        except InterruptedError as e:
            print(e)
    
    elif symbol.startswith("mtu_req"):
        try:
            print("mtu_req from learner!")
            result1 = ""
            ble_controller_socket.settimeout(6)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)
            while ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result):
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
                if ("con_req" not in symbol) and ("feature_req" in result):
                    result = "null_action"
        except socket.timeout:
            print("Timeout occurred for " + symbol)
            if not result.startswith("desc_resp"):
                result = "null_action"
        except IOError as e:
            print(e)
            
    elif symbol.startswith("mtu_resp"):
        try:
            print("mtu_req from learner!")
            result1 = ""
            ble_controller_socket.settimeout(6)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)
            while ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result):
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
                if ("con_req" not in symbol) and ("feature_req" in result):
                    result = "null_action"
        except socket.timeout:
            print("Timeout occurred for " + symbol)
            if not result.startswith("desc_resp"):
                result = "null_action"
        except IOError as e:
            print(e)

    elif symbol.startswith("pri_req"):
        try:
            result1 = ""
            ble_controller_socket.settimeout(6)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if ("adv_ind" in result) or ("scan_resp" in result) or ("feature_req" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("pri_resp" in result) or ("length_req" in result) or ("ll_reject" in result):
                if "pri_resp" not in result:
                    print("I am in the check case for pri_req!")
                    ble_controller_socket.send((symbol + "\n").encode())
                    result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                while "pri_resp" in result:
                     result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result1 = result[1:]
                result1 = get_closest(result1,expectedResults)
            if ("adv_ind" in result) or ("feature_req" in result) or ("ll_reject" in result) or ("char_resp" in result) or ("scan_resp" in result):
                result = "null_action"
        except socket.timeout:
            print(f"Timeout occurred for {symbol} with result: {result}")
            if "pri_resp" not in result:
                result = "null_action"
        except IOError as e:
            print(e)
    
    elif symbol.startswith("includes_req"):
        try:
            result1 = ""
            ble_controller_socket.settimeout(5)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)
            if ("con_req" not in symbol and "feature_req" in result):
                ble_controller_socket.settimeout(5)
                ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
            while ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("char_resp" in result):
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
                if "con_req" not in symbol and "feature_req" in result:
                    result = "null_action"
        except socket.timeout:
            print("Timeout occured for " + symbol)
            if not result.startswith("desc_resp"):
                result = "null_action"
        except IOError as e:
            print(e)
    
    elif symbol.startswith("feature_resp"):
        result1 = ""
        try:
            print("feature_resp case!")
            ble_controller_socket.settimeout(5)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)
            if "feature_req" in result:
                ble_controller_socket.settimeout(4)
                ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
            while ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("char_resp" in result) or ("att_error" in result):
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
                if "con_req" not in symbol and "feature_req" in result:
                    result = "null_action"
            ble_controller_socket.settimeout(4)
            result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result1 != "" and result1[0] == ' ':
                result1 = result1[1:]
            result1 = get_closest(result1,expectedResults)
            if "mtu_req" not in result1:
                ble_controller_socket.settimeout(15)
                result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result1 != "" and result1[0] == ' ':
                    result1 = result1[1:]
                result1 = get_closest(result1,expectedResults)
            if result and "mtu_req" in result1:
                result = result
        except socket.timeout:
            print("Timeout occured for " + symbol + " result: " + result + " result1: " + result1)
            if result and "adv_ind" not in result and "scan_resp" not in result:
                print("hit this special special case!")
                if result == "feature_req" or result == "desc_resp" or result == "char_resp":
                    print("special case caught feature_req for feature_resp")
                    result = "null_action"
            else:
                result = "null_action"
            result = "null_action"
        except IOError as e:
            print(e)
        
    elif symbol.startswith("key_exchange") or symbol.startswith("key_exchange_invalid"):
        try:
            ble_controller_socket.settimeout(7)
            ble_controller_socket.send((symbol + "\n").encode())
            # device_socket.send(("dh_key_confirm" + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            while ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("feature_req" in result) or ("char_resp" in result) or ("att_error" in result):
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
            result1 = ""
            result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result1 != "" and result1[0] == ' ':
                result1 = result1[1:]
            result1 = get_closest(result1,expectedResults)
            while ("adv_ind" in result1) or ("scan_resp" in result1) or ("DONE" in result1):
                result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result1 != "" and result1[0] == ' ':
                    result1 = result1[1:]
                result1 = get_closest(result1,expectedResults)
            if result1:
                result = result + "_" + result1
        except socket.timeout:
            print("Timeout occured for " + symbol + " with result: " + result)
            if not result.startswith("desc_resp"):
                result = "null_action"
        except IOError as e:
            print(e)
            
    elif symbol.startswith("enc_req"):
        result1 = ""
        try:
            ble_controller_socket.settimeout(8)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            while ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("feature_req" in result) or ("char_resp" in result) or ("att_error" in result):
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
            
            result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result1 != "" and result1[0] == ' ':
                result1 = result1[1:]
            result1 = get_closest(result1,expectedResults)
            
            while ("adv_ind" in result1) or ("scan_resp" in result1) or ("DONE" in result1):
                result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result1 != "" and result1[0] == ' ':
                    result1 = result1[1:]
                result1 = get_closest(result1,expectedResults)
                
            if result1:
                result = result + "_" + result1
                
        except socket.timeout:
            print("Timeout occured for " + symbol)
            if result1 and (result1 == "ll_reject" or result1 == "start_enc_req"):
                result = result + "_" + result1
            elif result and (result == "ll_reject" or result == "start_enc_req"):
                result = "enc_resp" + "_" + result
            elif "adv_ind" in result:
                result = "null_action"
                
            if not result1 and result and result != "null_action":
                if result == "enc_resp":
                    result = result + "_" + "ll_reject"
                    
            if result == "scan_resp" or result == "adv_ind":
                print("Caught scan_resp in enc_req case")
                result = "null_action"
                
            if not result:
                result = "null_action"
        except IOError as e:
            print(e)
    
    elif symbol.startswith("char_req"):
        try:
            result1 = ""
            ble_controller_socket.settimeout(3)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            
            if ("adv_ind" in result) or ("att_error" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("char_resp" in result) or ("mtu_req" in result):
                if "char_resp" not in result:
                    print("I am in the check case for char_req!")
                    ble_controller_socket.settimeout(8)
                    ble_controller_socket.send((symbol + "\n").encode())

                if "mtu_req" in result:
                   result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                while ("char_resp" in result1) or ("att_error" in result1):
                    result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                    if result1 != "" and result1[0] == ' ':
                        result1 = result1[1:]
                    result1 = get_closest(result1,expectedResults)
            
            if ("adv_ind" in result) or ("feature_req" in result):
                result = "null_action"
            else:
                if result1:
                    result = result

        except socket.timeout:
            print(f"Timeout occured for {symbol} result: {result}")
            if not result.startswith("char_resp"):
                result = "null_action"
        except IOError as e:
            print(e)
            
    elif symbol.startswith("desc_req"):
        try:
            result1 = ""
            ble_controller_socket.settimeout(3)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if ("adv_ind" in result) or ("scan_resp" in result) or ("feature_req" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("desc_resp" in result) or ("length_req" in result) or ("ll_reject" in result) or ("att_error" in result):
                if "desc_resp" not in result:
                    print("I am in the check case for desc_req!")
                    ble_controller_socket.send((symbol + "\n").encode())
                    result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                while "desc_resp" in result:
                    result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                    if result1 != "" and result1[0] == ' ':
                        result1 = result1[1:]
                    result1 = get_closest(result1,expectedResults)
            
            if ("DONE" in result) or ("True" in result) or ("False" in result) or ("adv_ind" in result) or ("feature_req" in result) or ("ll_reject" in result) or ("char_resp" in result) or ("scan_resp" in result):
                result = "null_action"

        except socket.timeout:
            print(f"Timeout occured for {symbol} with result: {result}")
            if "desc_resp" not in result:
                result = "null_action"
        except IOError as e:
            print(e) 
        
    elif symbol.startswith("read"):
        try:
            result1 = ""
            ble_controller_socket.settimeout(4)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()

            if ("desc_resp" in result) or ("read_resp" in result) or ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("att_error" in result) or ("char_resp" in result):
                print("I am in the check case for read IKkkkkk!")
                if "read_resp" not in result:
                    ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                while "read_resp" in result:
                    print("I am in the check case for looping!")
                    result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                    if result != "" and result[0] == ' ':
                        result = result[1:]
                    result = get_closest(result,expectedResults)

            if ("adv_ind" in result) or ("feature_req" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("scan_resp" in result):
                result = "null_action"

        except socket.timeout:
            print(f"Timeout occured for {symbol}")
            if not result.startswith("read_resp"):
                result = "null_action"
        except IOError as e:
            print(e)
    
    elif symbol.startswith("write"):
        try:
            result1 = ""
            ble_controller_socket.settimeout(5)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()

            if ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("char_resp" in result) or ("att_error" in result):
                print("I am in the check case for write!")
                ble_controller_socket.settimeout(5)
                ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                while "write_resp" in result:
                    result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                    if result != "" and result[0] == ' ':
                        result = result[1:]
                    result = get_closest(result,expectedResults)

            if ("adv_ind" in result) or ("feature_req" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result):
                result = "null_action"

        except socket.timeout:
            print(f"Timeout occured for {symbol}")
            if not result.startswith("write_resp"):
                result = "null_action"
        except IOError as e:
            print(e)
    
    else:
        try:
            print(f"Else case Symbol: {symbol}")

            if "discon_req" in symbol:
                discon_req_sent = True

            ble_controller_socket.send((symbol + "\n").encode())
            ble_controller_socket.settimeout(3)
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)

        except socket.timeout:
            print(f"Timeout occured for {symbol}")
            result = "null_action"

        except IOError as e:
            print(e)

    if result == "att_error":
        print("Caught att_error, replacing with null_action")
        result = "null_action"

    if "enc_req" in symbol and result != "null_action":
        result_list = result.split("_")
        if result_list[0] == "att_error" and result_list[1] == "enc_resp":
            print("reversed order!")
            result = f"{result_list[1]}_{result_list[0]}"

    if result == "mtu_req":
        print("Caught mtu_req, replaced with null_action")
        result = "null_action"

    if "feature_req" in result:
        print("Caught feature_req, replaced with null_action")
        result = "null_action"

    print(f"{symbol} -> {result}")
    return result

    







def step_general(symbol):
    print("STEP: " + symbol)
    # write this print into a file
    global num_symbols_after_pre
    num_symbols_after_pre += 1
    global last_pair
    try:
        time.sleep(2) # Sleep for 2 seconds
    except Exception as e:
        print(e)

    result = ""
    result_ble_controller = ""
    scan_result = ""
    result_for_device = ""
    
    if symbol.startswith("scan_req"):
        got_scan_resp = False
        try:
            ble_controller_socket.settimeout(5)
            ble_controller_socket.send((symbol + "\n").encode())

            result = ble_controller_socket.recv(1024).decode().replace("\\n","\n").split('\n')[0].strip()
            if result and result[0] == ' ':
                result = result[1:]
                
            result = get_closest(result,expectedResults)
            resend_scan_req_counter = 0
            while "scan_resp" not in result:
                if "adv_ind" not in result:
                    if resend_scan_req_counter > 10:
                        return "null_action"
                    print("*** RESENDING scan_resp ***")
                    resend_scan_req_counter += 1
                    ble_controller_socket.settimeout(5)
                    ble_controller_socket.send((symbol + "\n").encode())

                try:
                    result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                    result = get_closest(result,expectedResults)

                    if "scan_resp" in result:
                        print("** GOT scan_resp IN IF ***")
                        got_scan_resp = True
                        break

                except socket.timeout:
                    result = "null_action"


            while "scan_resp" in result: # consume all scan_resps
                print("** GOT scan_resp IN WHILE ***")
                got_scan_resp = True
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()

                if result and result[0] == ' ':
                    result = result[1:]
                    
                result = get_closest(result,expectedResults)
                
            if got_scan_resp:
                result = "scan_resp"
            
        except socket.timeout as e:
            
            if got_scan_resp:
                return "scan_resp"
            else:
                print(f"Timeout occured for {symbol} for {scan_req_timeout_counter} times...")
                result = "null_action"

        except IOError as e:
            print(e)
        
    elif (symbol.startswith("con_req") or symbol.startswith("length_resp") or symbol.startswith("feature_resp")
    or symbol.startswith("mtu_resp") or symbol.startswith("pri_resp") or symbol.startswith("pair_req")
    or symbol.startswith("pair_req: no_sc") or symbol.startswith("pair_req: no_sc_bonding") or symbol.startswith("pair_req: oob")
    or symbol.startswith("sm_random_send") or symbol.startswith("dh_check")
    or symbol.startswith("pair_confirm") or symbol.startswith("pair_confirm_wrong_value")
    or symbol.startswith("start_enc_resp") or symbol.startswith("start_enc_resp_plain")
    or symbol.startswith("enc_pause_req") or symbol.startswith("enc_pause_resp")
    or symbol.startswith("dh_check_invalid") or symbol.startswith("sign_info")):
        try:
            result1 = ""
            if symbol.startswith("dh_check"):
                ble_controller_socket.settimeout(7)
                ble_controller_socket.send((symbol + "\n").encode())
            
            
            elif symbol.startswith("pair_req"):
                print("extra timeout for pair_req")
                ble_controller_socket.settimeout(7)
                ble_controller_socket.send((symbol + "\n").encode())
                if "no_sc == 1" in symbol:
                    device_socket.send(("accept_pair_no_sc" + "\n").encode())
                else:
                    device_socket.send(("accept_pair" + "\n").encode())
                accept_result = device_socket.recv(1024).decode().split('\n')[0].strip()
                print("DEVICE ACCEPT: " + accept_result)

            elif symbol.startswith("sm_random_send"):
                ble_controller_socket.settimeout(5)
                device_socket.send(("sm_random_send" + "\n").encode())
                ble_controller_socket.send((symbol + "\n").encode())
                result_for_device = device_socket.recv(1024).decode().split('\n')[0].strip()
                print("*** MANUAL ACCEPT 2 ***")
            elif symbol.startswith("pair_confirm"):
                ble_controller_socket.settimeout(5)
                print("Sending pair_confirm")
                device_socket.send(("accept_pair_confirm" + "\n").encode())
                ble_controller_socket.send((symbol + "\n").encode())
                result_for_device = device_socket.recv(1024).decode().split('\n')[0].strip()
            else:
                ble_controller_socket.settimeout(8)
                ble_controller_socket.send((symbol + "\n").encode())
            
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)
            
            
            if symbol.startswith("pair_req"):
                print("pair_req"+result)
            
            while ("adv_ind" in result or "scan_resp" in result or "DONE" in result or
                "char_resp" in result or "mtu_req" in result or "att_error" in result or "length_resp" in result or
                ("version_resp" in result and not symbol.startswith("con_req")) or
                "ll_reject" in result or "pair_resp" in result and not symbol.startswith("pair_req")):
                
                if "con_req" in symbol:
                    time.sleep(1)
                    ble_controller_socket.settimeout(3)
                    ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
                print("result: "+result)
                
                
        except socket.timeout as e:
            result = "null_action"

        except IOError as e:
            print(e)        
            
            
        if (symbol.startswith("con_req:")):
            try:
                if "null_action" not in result:
                    result = "null_action"
                time.sleep(2)
            except Exception as e:
                print(e)        
            
            

            
    elif symbol.startswith("sec_service_req"):
        try:
            print("sec_service_req case!")
            result1 = ""
            ble_controller_socket.settimeout(5)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)

            if "con_req" not in symbol and "version_resp" in result:
                ble_controller_socket.settimeout(5)
                ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)

            while "adv_ind" in result or "scan_resp" in result or "DONE" in result or "char_resp" in result or "version_resp" in result:
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)

                if "con_req" not in symbol and "feature_req" in result:
                    result = "null_action"

        except socket.timeout:
            print(f"Timeout occurred for {symbol}")
            if not result.startswith("desc_resp"):
                result = "null_action"

        except IOError as e:
            print(e)

    elif "feature_req" in symbol or "feature_resp" in symbol:
        try:
            result1 = ""
            result = ""
            ble_controller_socket.settimeout(7)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            while (not result.startswith("feature_resp")) and result != "" and result != "null_action":
                time.sleep(3)
                ble_controller_socket.settimeout(6)
                ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)

            while "adv_ind" in result or "scan_resp" in result or "DONE" in result or "True" in result or "False" in result or "char_resp" in result or "mtu_req" in result or "att_error" in result:
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)

        except socket.timeout:
            print(f"Timeout occurred for in the first case: {symbol}")
            result = "null_action"

        except IOError as e:
            print(e)
    
    elif symbol.startswith("version_req"):
        try:
            print("version_req from learner!")
            result1 = ""
            result = ""
            ble_controller_socket.settimeout(5)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            while (not result.startswith("version_resp")) and result != "" and result != "null_action" and result != "unknown_resp" and result != "feature_req":
                time.sleep(3)
                ble_controller_socket.settimeout(6)
                ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)

            while "adv_ind" in result or "scan_resp" in result or "DONE" in result or "feature_req" in result:
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
                if "con_req" not in symbol and "feature_req" in result:
                    result = "null_action"
            while "version_resp" in result:
                result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
        except socket.timeout:
            print(f"Timeout occurred for in the first case: {symbol}")
            if result == "version_resp":
                return result
            if not result.startswith("desc_resp"):
                result = "null_action"

        except IOError as e:
            print(e)
     
    elif symbol.startswith("length_req") or symbol.startswith("length_resp"):
        try:
            print("length_req from learner (increased timer)!")
            result1 = ""
            result = ""
            time.sleep(0.5)
            ble_controller_socket.settimeout(4)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            while (not result.startswith("length_resp")) and result != "" and result != "null_action" and result != "unknown_resp":
                time.sleep(3)
                ble_controller_socket.settimeout(6)
                ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)
            
            while ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("version_resp" in result):
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
                if ("con_req" not in symbol) and ("feature_req" in result):
                    result = "null_action"
            time.sleep(3)
        except socket.timeout:
            print("Timeout occurred for " + symbol)
            result = "null_action"
        except IOError as e:
            print(e)
        except InterruptedError as e:
            print(e)
    
    elif symbol.startswith("mtu_req"):
        try:
            print("mtu_req from learner!")
            result1 = ""
            result = ""
            ble_controller_socket.settimeout(6)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            print("FIRST result: " + result)
            while (not result.startswith("mtu_resp")) and result != "" and result != "null_action" and result != "unknown_resp":
                print("inside while")
                time.sleep(3)
                ble_controller_socket.settimeout(6)
                ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                
                
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)
            print("SECOND result: " + result)
            while ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result):
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
                if ("con_req" not in symbol) and ("feature_req" in result):
                    result = "null_action"
        except socket.timeout:
            print("Timeout occurred for " + symbol)
            if not result.startswith("desc_resp"):
                result = "null_action"
        except IOError as e:
            print(e)
            


    elif symbol.startswith("pri_req"):
        try:
            result1 = ""
            result = ""
            ble_controller_socket.settimeout(6)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            
            if ("adv_ind" in result) or ("scan_resp" in result) or ("feature_req" in result) or ("DONE" in result) or ("pri_resp" in result) or ("length_req" in result) or ("ll_reject" in result) or ("version_resp" in result):
                if "pri_resp" not in result:
                    print("I am in the check case for pri_req!")
                    ble_controller_socket.send((symbol + "\n").encode())
                    result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                while "pri_resp" in result:
                     result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result1 != "" and result1[0] == ' ':
                    result1 = result1[1:]
                result1 = get_closest(result1,expectedResults)
            if ("adv_ind" in result) or ("feature_req" in result) or ("ll_reject" in result) or ("char_resp" in result) or ("scan_resp" in result) or ("version_resp" in result):
                result = "null_action"
        except socket.timeout:
            print(f"Timeout occurred for {symbol} with result: {result}")
            if "pri_resp" not in result:
                result = "null_action"
        except IOError as e:
            print(e)
    
    elif symbol.startswith("includes_req"):
        try:
            result1 = ""
            ble_controller_socket.settimeout(5)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)
            if ("con_req" not in symbol and "feature_req" in result):
                ble_controller_socket.settimeout(5)
                ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
            while ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("char_resp" in result):
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
                if "con_req" not in symbol and "feature_req" in result:
                    result = "null_action"
        except socket.timeout:
            print("Timeout occured for " + symbol)
            if not result.startswith("desc_resp"):
                result = "null_action"
        except IOError as e:
            print(e)
    
    
        
    elif symbol.startswith("key_exchange") or symbol.startswith("key_exchange_invalid"):
        try:
            ble_controller_socket.settimeout(7)
            ble_controller_socket.send((symbol + "\n").encode())
            # device_socket.send(("dh_key_confirm" + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            while ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("feature_req" in result) or ("char_resp" in result) or ("att_error" in result) or ("version_resp" in result) or ("pair_resp" in result):
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
            result1 = ""
            result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result1 != "" and result1[0] == ' ':
                result1 = result1[1:]
            result1 = get_closest(result1,expectedResults)
            while ("adv_ind" in result1) or ("scan_resp" in result1) or ("DONE" in result1):
                result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result1 != "" and result1[0] == ' ':
                    result1 = result1[1:]
                result1 = get_closest(result1,expectedResults)
            if result1:
                result = result + "_" + result1
        except socket.timeout:
            print("Timeout occured for " + symbol + " with result: " + result)
            if not result.startswith("desc_resp"):
                result = "null_action"
        except IOError as e:
            print(e)
            
    elif symbol.startswith("enc_req"):
        result1 = ""
        try:
            ble_controller_socket.settimeout(6)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            while ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("feature_req" in result) or ("char_resp" in result) or ("att_error" in result) or ("version_resp" in result) or ("pair_resp" in result):
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result != "" and result[0] == ' ':
                    result = result[1:]
                result = get_closest(result,expectedResults)
            
            result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result1 != "" and result1[0] == ' ':
                result1 = result1[1:]
            result1 = get_closest(result1,expectedResults)
            
            while ("adv_ind" in result1) or ("scan_resp" in result1) or ("DONE" in result1):
                result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                if result1 != "" and result1[0] == ' ':
                    result1 = result1[1:]
                result1 = get_closest(result1,expectedResults)
                
            if result1:
                result = result + "_" + result1
                
        except socket.timeout:
            print("Timeout occured for " + symbol)
            if result1 and (result1 == "ll_reject" or result1 == "start_enc_req"):
                result = result + "_" + result1
            elif result and (result == "ll_reject" or result == "start_enc_req"):
                result = "enc_resp" + "_" + result
            elif "adv_ind" in result:
                result = "null_action"
                
            if not result1 and result and result != "null_action":
                if result == "enc_resp":
                    result = result + "_" + "ll_reject"
                    
            if result == "scan_resp" or result == "adv_ind":
                print("Caught scan_resp in enc_req case")
                result = "null_action"
                
            if not result:
                print("result not caught, result1 = "+ result1)
                result = "null_action"
        except IOError as e:
            print(e)
    
    elif symbol.startswith("char_req"):
        try:
            result1 = ""
            ble_controller_socket.settimeout(3)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            
            if ("adv_ind" in result) or ("att_error" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("char_resp" in result) or ("mtu_req" in result) or ("version_resp" in result):
                if "char_resp" not in result:
                    print("I am in the check case for char_req!")
                    ble_controller_socket.settimeout(8)
                    ble_controller_socket.send((symbol + "\n").encode())

                if "mtu_req" in result:
                   result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                while ("char_resp" in result1) or ("att_error" in result1):
                    result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                    if result1 != "" and result1[0] == ' ':
                        result1 = result1[1:]
                    result1 = get_closest(result1,expectedResults)
            
            if ("adv_ind" in result) or ("feature_req" in result):
                result = "null_action"
            else:
                if result1:
                    result = result

        except socket.timeout:
            print(f"Timeout occured for {symbol} result: {result}")
            if not result.startswith("char_resp"):
                result = "null_action"
        except IOError as e:
            print(e)
            
    elif symbol.startswith("desc_req"):
        try:
            result1 = ""
            ble_controller_socket.settimeout(5)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if ("adv_ind" in result) or ("scan_resp" in result) or ("feature_req" in result) or ("False" in result) or ("desc_resp" in result) or ("length_req" in result) or ("ll_reject" in result) or ("att_error" in result) or ("version_resp" in result):
                if "desc_resp" not in result:
                    print("I am in the check case for desc_req!")
                    ble_controller_socket.send((symbol + "\n").encode())
                    result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                while "desc_resp" in result:
                    result1 = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                    if result1 != "" and result1[0] == ' ':
                        result1 = result1[1:]
                    result1 = get_closest(result1,expectedResults)
            
            if ("DONE" in result) or ("adv_ind" in result) or ("feature_req" in result) or ("ll_reject" in result) or ("char_resp" in result) or ("scan_resp" in result):
                result = "null_action"

        except socket.timeout:
            print(f"Timeout occured for {symbol} with result: {result}")
            if "desc_resp" not in result:
                result = "null_action"
        except IOError as e:
            print(e) 
        
    elif symbol.startswith("read"):
        try:
            result1 = ""
            ble_controller_socket.settimeout(4)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()

            if ("desc_resp" in result) or ("read_resp" in result) or ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("att_error" in result) or ("char_resp" in result) or ("version_resp" in result):
                print("I am in the check case for read IKkkkkk!")
                if "read_resp" not in result:
                    ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                while "read_resp" in result:
                    print("I am in the check case for looping!")
                    result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                    if result != "" and result[0] == ' ':
                        result = result[1:]
                    result = get_closest(result,expectedResults)

            if ("adv_ind" in result) or ("feature_req" in result) or ("DONE" in result) or ("scan_resp" in result) or ("version_resp" in result):
                result = "null_action"

        except socket.timeout:
            print(f"Timeout occured for {symbol}")
            if not result.startswith("read_resp"):
                result = "null_action"
        except IOError as e:
            print(e)
    
    elif symbol.startswith("write"):
        try:
            result1 = ""
            ble_controller_socket.settimeout(5)
            ble_controller_socket.send((symbol + "\n").encode())
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()

            if ("adv_ind" in result) or ("scan_resp" in result) or ("DONE" in result) or ("True" in result) or ("False" in result) or ("char_resp" in result) or ("att_error" in result) or ("version_resp" in result):
                print("I am in the check case for write!")
                ble_controller_socket.settimeout(5)
                ble_controller_socket.send((symbol + "\n").encode())
                result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                while "write_resp" in result:
                    result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
                    if result != "" and result[0] == ' ':
                        result = result[1:]
                    result = get_closest(result,expectedResults)

            if ("adv_ind" in result) or ("feature_req" in result) or ("scan_resp" in result) or ("DONE" in result) or ("version_resp" in result):
                result = "null_action"

        except socket.timeout:
            print(f"Timeout occured for {symbol}")
            if not result.startswith("write_resp"):
                result = "null_action"
        except IOError as e:
            print(e)
    
    else:
        try:
            print(f"Else case Symbol: {symbol}")

            if "discon_req" in symbol:
                discon_req_sent = True

            ble_controller_socket.send((symbol + "\n").encode())
            ble_controller_socket.settimeout(3)
            result = ble_controller_socket.recv(1024).decode().split('\n')[0].strip()
            if result != "" and result[0] == ' ':
                result = result[1:]
            result = get_closest(result,expectedResults)

        except socket.timeout:
            print(f"Timeout occured for {symbol}")
            result = "null_action"

        except IOError as e:
            print(e)

    if result == "att_error":
        print("Caught att_error, replacing with null_action")
        result = "null_action"

    if "enc_req" in symbol and result != "null_action":
        result_list = result.split("_")
        if result_list[0] == "att_error" and result_list[1] == "enc_resp":
            print("reversed order!")
            result = f"{result_list[1]}_{result_list[0]}"

    if result == "mtu_req":
        print("Caught mtu_req, replaced with null_action")
        result = "null_action"

    if "feature_req" in result:
        print("Caught feature_req, replaced with null_action")
        result = "null_action"

    print(f"{symbol} -> {result}")
    
    return result

    
    
    


if __name__ == "__main__":
   init_ble_controller()
   init_device_con()

   
