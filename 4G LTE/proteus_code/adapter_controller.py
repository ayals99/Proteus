import socket
import time
import subprocess
import os
import re

mme_socket = None
enodeb_socket = None
ue_socket = None

reboot_count = 0
enable_s1_count = 0
attach_request_guti_count = 0
enable_s1_timeout_count = 0
reset_mme_count = 0
sqn_synchronized = False
unexpected = 0
number_of_queries = 0

device = ""

expectedResults = ["attach_request",
            "attach_request_guti",
            "detach_request",
            "auth_response_rejected",
            "auth_response",
            "security_mode_complete",
            "security_mode_reject",
            "emm_status",
            "attach_complete",
            "rrc_reconf_complete",
            "rrc_security_mode_complete",
            "rrc_connection_setup_complete",
            "identity_response",
            "auth_failure_mac",
            "auth_failure_seq",
            "auth_failure_noneps",
            "tau_request",
            "service_request",
            "tau_complete",
            "ul_nas_transport",
            "null_action",
            "GUTI_reallocation_complete",
            "identity_response_protected",
            "auth_response_protected",
            "rrc_ue_cap_info",
            "rrc_connection_reest_req",
            "DONE"]

enables1_expectedResults = ["attach_request","attach_request_guti", "rrc_connection_setup_complete", "null_action"]
identityrequestplain_expectedResults = ["identity_response", "null_action"]
identityrequestprotected_expectedResults = ["identity_response_protected", "null_action"]
authrequestplain_expectedResults = ["auth_response", "auth_failure_mac", "auth_failure_seq", "auth_failure_noneps", "null_action"]
authrequestprotected_expectedResults = ["auth_response_protected", "auth_failure_mac", "auth_failure_seq", "auth_failure_noneps", "null_action"]
secmodcmd_expectedResults = ["security_mode_complete", "security_mode_reject", "null_action"]
attachaccept_expectedResults = ["attach_complete", "null_action"]
rrcreleasetau_expectedResults = ["tau_request", "null_action"]
tauaccept_expectedResults = ["tau_complete", "null_action"]
gutireallocation_expectedResults = ["GUTI_reallocation_complete", "null_action"]
dlnastransport_expectedResults = ["ul_nas_transport", "null_action"]
pagingtmsi_expectedResults = ["service_request", "null_action"]
pagingimsi_expectedResults = ["attach_request", "null_action"]
rrcconnectionsetup_expectedResults = ["rrc_connection_setup_complete", "null_action"]
rrcreconf_expectedResults = ["rrc_reconf_complete", "null_action","rrc_connection_reest_req"]
rrcsecuritymodecommand_expectedResults = ["rrc_security_mode_complete", "null_action"]
rrcuecapenquiry_expectedResults = ["rrc_ue_cap_info", "null_action"]

def initialize_socket():
    global mme_socket
    global enodeb_socket
    global ue_socket
    mme_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    enodeb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ue_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def start_core():
    subprocess.Popen("echo \"dummy_password\" | sudo -S ./start_epc.sh", shell=True) # put your password here.


def start_enb():
    subprocess.Popen("echo \"dummy_password\" | sudo -S ./start_enb.sh", shell=True)

def kill_core():
    subprocess.Popen("echo \"dummy_password\" | sudo -S ./kill_epc.sh", shell=True)
    
def kill_enb():
    subprocess.Popen("echo \"dummy_password\" | sudo -S ./kill_enb.sh", shell=True)
    
def start_uecontroller():
    subprocess.Popen("python3 ./UEController.py", shell=True)

def kill_uecontroller():
    subprocess.Popen("echo \"dummy_password\" | sudo -S ./kill_uecontroller.sh", shell=True)
    
    
def init_core_enb_con():

    mme_socket.connect(("localhost", 60000))
    print("Connected to core")
    enodeb_socket.connect(("localhost", 60001))
    print("Connected to eNodeB")
    
    time.sleep(1)
    enodeb_socket.send("Hello\n".encode())
    response = enodeb_socket.recv(1024).decode().split('\n')[0].strip()
    print("Received = {}".format(response))
    
    
def init_ue_con():
    print("Connecting to UE Controller...")
    time.sleep(0.5)
    ue_socket.connect(("localhost", 61000))
    print("Connected to UE Controller")


def start_core_enb():
    start_core()
    time.sleep(3)
    start_enb()
    time.sleep(6)


def send_enable_s1():
    try:
        result = ""
        print("Sending symbol: enable_s1 to UE controller")
        global enable_s1_count
        enable_s1_count += 1
        ue_socket.send("enable_s1".encode())
    except socket.timeout:
        print("Error : Socket Timeout")
    except socket.error as e:
        print("Error : {}".format(e))


def reset_mme():
    result = ""
    print("Sending symbol: RESET to MME controller")
    global reset_mme_count
    try:
        time.sleep(1)
        mme_socket.send(("RESET").encode())
        result = mme_socket.recv(1024).decode().split('\n')[0].strip()

        reset_mme_count += 1

        print("ACK for RESET_MME: {}".format(result))
    except socket.timeout:
        print("Timeout")
    except socket.error as e:
        print(e)

    return result


def reset_ue():
    result = ""
    print("Sending symbol: RESET to UE controller")
    try:
        time.sleep(1)
        ue_socket.send("RESET".encode())
        result = ue_socket.recv(1024).decode().split('\n')[0].strip()
        print("ACK for RESET_UE: {}".format(result))
    except socket.timeout:
        print("Timeout")
    except socket.error as e:
        print(e)

    return result


def reboot_ue():
    print("ending REBOOT_UE command to UE_CONTROLLER")
    result = ""
    try:
        ue_socket.send("ue_reboot".encode())
        print("Waiting for the response from UE ....")
        result = ue_socket.recv(1024).decode().split('\n')[0].strip()
        print("UE's ACK for REBOOT: {}".format(result))
    except socket.timeout:
        print("Timeout")
    except socket.error as e:
        print(e)

    return result


def restart_epc_enb():
    global mme_socket
    global enodeb_socket

    try:
        mme_socket.close()
        enodeb_socket.close()

        kill_core()
        time.sleep(1)
        kill_enb()
        time.sleep(1)
        start_core()
        time.sleep(3)
        start_enb()
        time.sleep(5)


        mme_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        enodeb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        time.sleep(1)
        mme_socket.connect(("localhost", 60000))
        print("connected with mme")
        time.sleep(1)
        enodeb_socket.connect(("localhost", 60001))
        print("connected with enb")

    except socket.error as e:
        print(e)


def handle_enb_epc_failure():
    result = ""
    global enable_s1_timeout_count
    try:
        restart_epc_enb()
        enable_s1_timeout_count = 0
    except socket.error as e:
        print(e)
    print("ENB EPC FAILURE HANDLING DONE.")


def step(symbol: str):
    print("enter step")
    global unexpected
    mme_rrc = 0
    time.sleep(50 / 1000)
    timeout = 1

    result_mme = ""

    try:
        if symbol.startswith("enable_s1"):
            unexpected = 0

            mme_socket.settimeout(20)
            send_enable_s1()

            result_mme = mme_socket.recv(1024).decode().split('\n')[0].strip()

            if "attach_request_guti" in result_mme:
                result_mme = "attach_request:emergency == 0"

            print("{} -> MME:::: {}".format(symbol, result_mme))
            return result_mme

    except socket.timeout:
        print("Timeout occured in step for {}".format(symbol))
        try:
            mme_socket.send(symbol.encode())
            result_mme = mme_socket.recv(1024).decode().split('\n')[0].strip()

            if "attach_request_guti" in result_mme:
                result_mme = "attach_request:emergency == 0"

            print("{} -> MME:::: {}".format(symbol, result_mme))
            return result_mme
        except socket.error as e:
            return "null_action"

    except socket.error as e:
        print("Error {}".format(e))
        print("Attempting to restart device and reset srsEPC. Also restarting query.")
        handle_enb_epc_failure()
        return "null_action:"

    try:
        if "reject" in symbol:
            mme_socket.settimeout(2)
            mme_socket.send(symbol.encode())
            result = mme_socket.recv(1024).decode().split('\n')[0].strip()
            print("{} -> {}".format(symbol, result_mme))
            return result
    except socket.timeout:
        print("Timeout occured for {}".format(symbol))
        return "null_action:"
    except socket.error as e:
        print("Error {}".format(e))
        print("Attempting to restart device and reset srsEPC. Also restarting query.")
        handle_enb_epc_failure()
        return "null_action:"

    try:
        if unexpected == 1:
            result = "null_action:"
            return result
        if (not symbol.startswith("enable_s1")) and (not ("reject" in symbol) and unexpected == 0): #main branch to execute
            if (symbol.startswith("rrc_security_mode_command")):
                mme_rrc = 1
                print(symbol)
                enodeb_socket.settimeout(timeout)
                enodeb_socket.send(symbol.encode())
            elif (symbol.startswith("rrc_reconf")):
                mme_rrc = 1
                print(symbol)
                enodeb_socket.settimeout(timeout)
                enodeb_socket.send(symbol.encode())
            elif (symbol.startswith("ue_capability_inquiry")):
                mme_rrc = 1
                print(symbol)
                enodeb_socket.settimeout(timeout)
                enodeb_socket.send(symbol.encode())
            elif (symbol.startswith("counter_check")):
                mme_rrc = 1
                print(symbol)
                enodeb_socket.settimeout(timeout)
                enodeb_socket.send(symbol.encode())
            elif (symbol.startswith("ue_information_request")):
                mme_rrc = 1
                print(symbol)
                enodeb_socket.settimeout(timeout)
                enodeb_socket.send(symbol.encode())
            elif (symbol.startswith("attach_accept")):
                mme_rrc = 0
                print(symbol)
                mme_socket.settimeout(timeout)
                mme_socket.send(symbol.encode())
            elif (symbol.startswith("authentication_request")):
                mme_rrc = 0
                print(symbol)
                mme_socket.settimeout(timeout)
                mme_socket.send(symbol.encode())
            elif (symbol.startswith("security_mode_command")):
                mme_rrc = 0
                print(symbol)
                mme_socket.settimeout(timeout)
                mme_socket.send(symbol.encode())
            elif (symbol.startswith("identity_request")):
                mme_rrc = 0
                print(symbol)
                mme_socket.settimeout(timeout)
                mme_socket.send(symbol.encode())
            elif (symbol.startswith("GUTI_reallocation")):
                mme_rrc = 0
                print(symbol)
                mme_socket.settimeout(timeout)
                mme_socket.send(symbol.encode())
            elif symbol.startswith("RESET"):
                print("### RESET ###")
                mme_socket.settimeout(timeout)
                mme_socket.send(symbol.encode())
            else:
                mme_rrc = 0
                print("The except case {}".format(symbol))
                mme_socket.settimeout(2)
                mme_socket.send(symbol.encode())

        result = ""
        if mme_rrc == 0:
            print("reading from MME")
            result = mme_socket.recv(1024).decode().split('\n')[0].strip()
        else:
            print("reading from RRC")
            result = enodeb_socket.recv(1024).decode().split('\n')[0].strip()


        if "DONE" in result or "attach_request" in result:
            print("Response of {} =  Unexpected attach_request")
            unexpected = 1
        else:
            if "emm_status" in result:
                print("Actual response of {} = emm_status".format(symbol))
                result = "emm_status:"
            if "attach_request_guti" in result:
                print("Actual response of {} = attach_request_guti".format(symbol))
                result = "attach_request:"
            if "detach_request" in result:
                result = "null_action:"
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
            else:
                print("Response of {} = {}".format(symbol, result))
                if result == "attach_request":
                    result = "attach_request:"
                elif result == "":
                    return "null_action:"
                return (result)

    except socket.timeout:
        print("Timeout occurred for {}".format(symbol))
        return "null_action:"
    except socket.error as e:
        print("Error {}".format(e))
        print("Attempting to restart device and reset srsEPC. Also restarting query.")
        handle_enb_epc_failure()
        return "null_action:"

    return result
counter = 0
reset_counter = 0



def pre():
    print("pre!")
    flag = 0
    global attach_request_guti_count
    global enable_s1_timeout_count
    global reboot_count
    global reset_counter
    global sqn_synchronized
    global ue_socket
    try:
        if True:
            reset_done = False
            attach_request_guti_count = 0
            enable_s1_timeout_count = 0
            reboot_count = 0
            i = 0
            print("---- Starting RESET ----")

            ue_socket.close()
            kill_uecontroller()
            time.sleep(0.5)

            start_uecontroller()
            time.sleep(1)
            ue_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            init_ue_con()

            while not reset_done:
                try:
                    result_for_mme = reset_mme()
                    enodeb_socket.settimeout(120)
                    mme_socket.settimeout(120)

                    if flag == 0:
                        pass

                    print("Sending enable_s1")
                    send_enable_s1()

                    result = mme_socket.recv(1024).decode().split('\n')[0].strip()
                    print("Response of ENABLE_S1: {}".format(result))

                    if "detach_request" in result:
                        print("Caught detach_request and sending enable_s1 again!")
                        pre()

                    if flag == 0:
                        mme_socket.send("attach_reject:emm_cause == 11".encode())
                        flag = 1
                        print("attach_reject sent!")



                    mme_socket.settimeout(30)
                    attach_request_guti_counter = 10

                    print("Sending enable_s1")
                    send_enable_s1()
                    time.sleep(1)
                    result = mme_socket.recv(1024).decode().split('\n')[0].strip()
                    print("Response of ENABLE_S1: {}".format(result))

                    if ("attach_request_guti" in result):
                        print("Pre failed!\n")
                        attach_request_guti_count += 1
                        flag = 1
                    elif result.startswith("attach_request"):
                        if flag == 0:
                            flag = 1
                            continue
                        attach_request_guti_count = 0

                        if not sqn_synchronized:
                            print("Sending symbol: auth_request to MME controller, handle error here!!!")
                            time.sleep(0.5)
                            send_enable_s1()
                            result = mme_socket.recv(1024).decode().split('\n')[0].strip()
                            print("Response of SQN_ENABLE_S1: {}".format(result))
                            time.sleep(0.5)
                            mme_socket.send("auth_request_plain_text".encode())
                            result = mme_socket.recv(1024).decode().split('\n')[0].strip()
                            print("RESULT FROM AUTH REQUEST: {}".format(result))

                            if "auth" in result:
                                print("Recieved {}. Synched the SQN value")
                                sqn_synchronized = True
                                reset_done = True
                                break
                        elif sqn_synchronized:
                            reset_done = True
                            print("reset done!")
                            break
                except socket.timeout:
                    enable_s1_timeout_count += 1
                    print("Timeout occured for enable_s1")
                    print("Sleeping for a while...")
                    handle_enb_epc_failure()
                    pre()

            result = reset_mme()
            print("---- RESET DONE ----")
    except socket.error as e:
        print("Error : {}".format(e))



