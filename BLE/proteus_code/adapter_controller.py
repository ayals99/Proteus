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


def getexpectedresult(symbol, result):

    final_result = "null_action"
    result = str(result)
    if "enable_s1" in symbol:
        if result in enables1_expectedResults:
            print(79)
            final_result = result
    elif "identity_request_plain" in symbol or "identity_request_mac" in symbol or "identity_request_wrong_mac" in symbol or "identity_request_replay" in symbol:
        print(82)
        print(result)
        print(type(result))
        print(type(identityrequestplain_expectedResults[0]))
        print(identityrequestplain_expectedResults)
        if result in identityrequestplain_expectedResults:
            final_result = result
    elif "identity_request_protected" in symbol:
        if result in identityrequestprotected_expectedResults:
            print(87)
            final_result = result
    elif "auth_request_plain" in symbol or "auth_request_replay" in symbol:
        print(90)
        if result in authrequestprotected_expectedResults:
            final_result = result
    elif "auth_request_protected" in symbol:
        if result in authrequestprotected_expectedResults:
            final_result = result
    elif "rrc_security_mode_command" in symbol or "rrc_security_mode_command_replay" in symbol or "rrc_security_mode_command_downgraded" in symbol:
        if result in rrcsecuritymodecommand_expectedResults:
            final_result = result
    elif "security_mode_command" in symbol or "security_mode_command_replay" in symbol or "security_mode_command_no_integrity" in symbol or "security_mode_command_plain" in symbol:
        if result in secmodcmd_expectedResults:
            final_result = result
    elif "attach_accept" in symbol or "attach_accept_mac" in symbol or "attach_accept_no_integrity" in symbol or "attach_accept_null_header" in symbol:
        if result in attachaccept_expectedResults:
            final_result = result
    elif "dl_nas_transport" in symbol or "dl_nas_transport_plain" in symbol:
        if result in dlnastransport_expectedResults:
            final_result = result
    elif "rrc_release_tau" in symbol:
        if result in rrcreleasetau_expectedResults:
            final_result = result
    elif "tau_accept" in symbol or "tau_accept_plain" in symbol:
        if result in tauaccept_expectedResults:
            final_result = result
    elif "GUTI_reallocation" in symbol or "GUTI_reallocation_plain" in symbol:
        if result in gutireallocation_expectedResults:
            final_result = result
    elif "paging_tmsi" in symbol:
        if result in pagingtmsi_expectedResults:
            final_result = result
    elif "rrc_connection_setup" in symbol:
        if result in rrcconnectionsetup_expectedResults:
            final_result = result
    elif "rrc_reconf" in symbol or "rrc_reconf_replay" in symbol or "rrc_reconf_downgraded" in symbol:
        if result in rrcreconf_expectedResults:
            final_result = result
    elif "rrc_ue_cap_enquiry" in symbol:
        if result in rrcuecapenquiry_expectedResults:
            final_result = result

    return final_result

def execute_query():
    global number_of_queries

    # queries = [["enable_s1", "identity_request_plain_text", "auth_request_plain_text","sm_command_protected", "RRC_sm_command_protected", "rrc_reconf", "attach_accept_protected"],
    #            ["enable_s1", "identity_request_plain_text", "auth_request_plain_text","sm_command_protected", "RRC_sm_command_protected", "rrc_reconf", "attach_accept_protected"],
    #            ["enable_s1", "identity_request_plain_text", "auth_request_plain_text","sm_command_protected", "RRC_sm_command_protected", "rrc_reconf", "attach_accept_protected"]]

    # queries = [["enable_s1", "identity_request_plain_text", "auth_request_plain_text","sm_command_protected","GUTI_reallocation_protected","attach_accept_protected","sm_command_int_cip","GUTI_reallocation_replay"]]
    # queries = [["enable_s1", "identity_request_plain_text", "auth_request_plain_text","sm_command_protected","GUTI_reallocation_protected","attach_accept_protected","sm_command_replay","GUTI_reallocation_replay"]]
    # queries = [["enable_s1", "identity_request_plain_text", "auth_request_plain_text","sm_command_protected","GUTI_reallocation_protected","attach_accept_protected","sm_command_int_cip","GUTI_reallocation_replay"]]
    # queries = [["enable_s1", "identity_request_plain_text", "auth_request_plain_text","sm_command_protected","attach_accept_protected","GUTI_reallocation_protected","sm_command_replay","GUTI_reallocation_replay"]]
    #queries = [["enable_s1", "augen_auth_info_answer_milenageth_request_pgen_auth_info_answer_milenagelain_text","sm_command_protected","GUTI_reallocation_protected","GUTI_reallocation_replay"]]
    queries = [
                ["enable_s1:",
                "identity_request:",
                "authentication_request:",
                "security_mode_command:",
                "rrc_security_mode_command: integrity == 1 & cipher == 1",
                "ue_capability_inquiry:cipher == 0 & integrity == 0",
                "attach_accept:cipher == 1 & integrity == 1 & replay == 0 & security_header_type == 2",
                ]
               ]


    for query in queries:
        pre()
        result_query = []
        number_of_queries = number_of_queries + 1
        print("query #{} : ".format(number_of_queries))
        for symbol in query:
            result = step(symbol)
            print("result: " + result)
            result_query.append(str(result))
            time.sleep(1)
    print(result_query)




def initialize_socket():
    global mme_socket
    global enodeb_socket
    global ue_socket
    mme_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    enodeb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ue_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def start_core():
    subprocess.Popen("echo \"123\" | sudo -S ./start_epc.sh", shell=True)


def start_enb():
    subprocess.Popen("echo \"123\" | sudo -S ./start_enb.sh", shell=True)

def kill_core():
    subprocess.Popen("echo \"123\" | sudo -S ./kill_epc.sh", shell=True)
    
def kill_enb():
    subprocess.Popen("echo \"123\" | sudo -S ./kill_enb.sh", shell=True)
    
def start_uecontroller():
    subprocess.Popen("python3 ./UEController.py", shell=True) 
    
    
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
    start_uecontroller()
    time.sleep(0.5)
    ue_socket.connect(("localhost", 61000))
    print("Connected to UE Controller")


def start_core_enb():
    start_core()
    time.sleep(6)
    start_enb()
    time.sleep(8)


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

        time.sleep(1)

        # start_epc_enb()

        mme_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        enodeb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        mme_socket.connect(("localhost", 48899))
        enodeb_socket.connect(("localhost", 48889))

    except socket.error as e:
        print(e)


def handle_enb_epc_failure():
    result = ""
    global enable_s1_timeout_count
    try:
        reboot_ue()
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

    result_mme = ""
    

    try:
        if symbol.startswith("enable_s1"):
            unexpected = 0
            try:
                while not ("attach_request" in result_mme):
                    mme_socket.settimeout(180)
                    send_enable_s1()

                    result_mme = mme_socket.recv(1024).decode().split('\n')[0].strip()
                    # comparison and getclosests not implemented

                if "attach_request_guti" in result_mme:
                    result_mme = "attach_request:emergency == 0"

                print("{} -> MME:::: {}".format(symbol, result_mme))
                return result_mme

            except socket.error as e:
                while not ("attach_request" in result_mme):
                    mme_socket.settimeout(180)
                    send_enable_s1()

                    result_mme = mme_socket.recv(1024).decode().split('\n')[0].strip()
                    # comparison and getclosests not implemented

                if "attach_request_guti" in result_mme:
                    result_mme = "attach_request:emergency == 0"

                print("{} -> MME: {}".format(symbol, result_mme))
                return result_mme
    except socket.timeout:
        print("Timeout occured in step for {}".format(symbol))
        try:
            mme_socket.send(symbol.encode())
        except socket.error as e:
            # handle_timeout()
            return "null_action"  # timeout mentioned in log executor
    except socket.error as e:
        print("Error {}".format(e))
        print("Attempting to restart device and reset srsEPC. Also restarting query.")
        handle_enb_epc_failure()
        return "null_action:"

    try:
        if "reject" in symbol:
            mme_socket.settimeout(5)
            mme_socket.send(symbol.encode())

            result = mme_socket.recv(1024).decode().split('\n')[0].strip()
            # comparison and getclosests not implemented
            print("{} -> {}".format(symbol, result_mme))
            return result
    except socket.timeout:
        print("Timeout occured for {}".format(symbol))
        print("Restarting UE and marking following command as null action")
        # handle_timeout()
        return "null_action:"  # timeout mentioned in log executor
    except socket.error as e:
        print("Error {}".format(e))
        print("Attempting to restart device and reset srsEPC. Also restarting query.")
        handle_enb_epc_failure()
        return "null_action:"

    try: # We will go this branch mainly
        if unexpected == 1:
            if symbol.startswith("rrc_release_tau"):
                unexpected = 0
        if unexpected == 1:
            result = "null_action:"
            return result
        if (not symbol.startswith("enable_s1")) and (not ("reject" in symbol)) and unexpected == 0:
            if (symbol.startswith("RRC_sm_command_protected")           # TODO later
                    or symbol.startswith("RRC_sm_command_replay")
                    or symbol.startswith("RRC_sm_command_downgraded"))\
                    or symbol.startswith("rrc_security_mode_command"):
                mme_rrc = 1
                print("IK now rrc_security_mode_command/rrc_security_mode_command_replay"
                      "/rrc_security_mode_command_downgraded")
                enodeb_socket.settimeout(2)  # why enb and mme different used?
                enodeb_socket.send(symbol.encode())
            elif (
                    symbol.startswith("rrc_reconf")           # TODO later
                    or symbol.startswith("rrc_reconf_replay")
                    or symbol.startswith("rrc_reconf_plain")
            ):
                mme_rrc = 1
                print("IK now rrc_reconf/rrc_reconf_replay/rrc_reconf_plain/rrc_reconf_downgraded")
                enodeb_socket.settimeout(2)
                enodeb_socket.send(symbol.encode())
            elif(
                symbol.startswith("ue_capability_inquiry")
            ):
                mme_rrc = 1
                print("ue_capability_inquiry")
                enodeb_socket.settimeout(2)
                enodeb_socket.send(symbol.encode())
            elif (
                    symbol.startswith("attach_accept")
            ):
                mme_rrc = 0
                print("IK now attach_accept")
                mme_socket.settimeout(2)
                mme_socket.send(symbol.encode())
            elif (
                    symbol.startswith("auth_request")
                    or symbol.startswith("security_mode_command")
            ):
                mme_rrc = 0
                print("IK now auth_request_plain/security_mode_command")
                mme_socket.settimeout(2)
                mme_socket.send(symbol.encode())
            elif (
                    symbol.startswith("rrc_release_tau")       # TODO later
            ):
                mme_rrc = 0
                print("### RRC RELEASE TAU###")
                return "null_action:"
                time.sleep(8)
                mme_socket.settimeout(5)
                mme_socket.send(symbol.encode())
            elif (
                    symbol.startswith("rrc_release")    # TODO later
            ):
                print("### RRC RELEASE ###")
                return "null_action:"
                mme_socket.settimeout(1)
                mme_socket.send(symbol.encode())
            elif (
                    symbol.startswith("paging_tmsi")     # TODO later
            ):
                print("### paging_tmsi ###")
                return "null_action:"
                mme_socket.settimeout(5)
                mme_socket.send(symbol.encode())
            elif (
                    symbol.startswith("tau_accept")             # TODO later
                    or symbol.startswith("tau_accept_plain")
            ):
                mme_rrc = 0
                return "null_action:"
                mme_socket.settimeout(2)
                mme_socket.send(symbol.encode())
            elif (                                                       
                    symbol.startswith("identity_request")
            ):
                mme_rrc = 0
                print("Case {}".format(symbol))
                mme_socket.settimeout(2)
                mme_socket.send(symbol.encode())
            elif (
                    symbol.startswith("GUTI_reallocation")
            ):
                mme_rrc = 0
                print("Case {}".format(symbol))
                mme_socket.settimeout(2)
                mme_socket.send(symbol.encode())
            elif symbol.startswith("wait"):
                s = "wait:time == 5"
                match = re.search(r'wait:time == (\d+)', s)
                if match:
                    value = int(match.group(1))
                    print(value)
                    print("Case {}".format(symbol))
                    value = value*60
                    mme_socket.settimeout(value)
                    mme_socket.send(symbol.encode())
                else:
                    print("Pattern not found!")
            elif symbol.startswith("RESET"):
                print("### RESET ###")
                mme_socket.settimeout(1)
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
            # return  "null action"    // temporary ban rrc message!!!
            result = enodeb_socket.recv(1024).decode().split('\n')[0].strip()
            if "rrc_connection_setup_complete" in result:
                print("reading again")
                result = enodeb_socket.recv(1024).decode().split('\n')[0].strip()
            # comparison and getclosests not implemented
        if "DONE" in result or "attach_request" in result:
            print("Response of {} =  Unexpected attach_request")
            unexpected = 1
            # result = getexpectedresult(symbol, result)
        elif not (symbol.startswith("rrc_release_tau")) and "tau_request" in result:
            print("Unexpected tau_request caught!")
            unexpected = 1
            # result = getexpectedresult(symbol, result)
        else:
            # result = getexpectedresult(symbol, result)
            if "emm_status" in result:
                print("Actual response of {} = emm_status".format(symbol))
                result = "emm_status:"
            if "attach_request_guti" in result:
                print("Actual response of {} = attach_request_guti".format(symbol))
                result = "attach_request:emergency == 0"
            if "detach_request" in result:
                result = "null_action:"
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
            else:
                print("Response of {} = {}".format(symbol, result))
                # print("{} -> {}".format(symbol, result))
                if result == "attach_request":
                    result = "attach_request:emergency == 0"
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

    try:
        # comparison and getclosests not implemented
        if result.lower().startswith("null_action"):
            result = "null_action:"
        if result.lower().startswith("detach_request"):  # why ???
            result = "null_action:"
    except socket.error as e:
        print("Error {}".format(e))
        print("Attempting to restart device and reset srsEPC. Also restarting query.")
        handle_enb_epc_failure()
        return "null_action:"

    # result = getexpectedresult(symbol, result)

    # print("#### {} / {} ####".format(symbol, result))
    if result == "attach_request":
        result = "attach_request:emergency == 0"
    elif result == "":
        return "null_action:"
    return result


counter = 0
reset_counter = 0


def post():
    global reset_counter
    reset_counter = 0


def pre():
    print("pre!")
    flag = 0
    global attach_request_guti_count
    global enable_s1_timeout_count
    global reboot_count
    global reset_counter
    global sqn_synchronized
    try:
        if True:  # !config.combine_query??
            reset_done = False
            attach_request_guti_count = 0
            enable_s1_timeout_count = 0
            reboot_count = 0
            i = 0
            print("---- Starting RESET ----")

            while not reset_done:
                try:
                    result_for_mme = reset_mme()
                    if (device == "huwaeiy5" and reset_counter == 0) or not device == "huwaeiy5":
                        result_for_ue = reset_ue()
                        reset_counter += 1

                    if device == "huwaeiy5":
                        enodeb_socket.settimeout(120)
                        mme_socket.settimeout(120)
                    else:
                        enodeb_socket.settimeout(120)
                        mme_socket.settimeout(120)

                    if flag == 0:
                        pass

                    print("Sending enable_s1")
                    send_enable_s1()

                    result = mme_socket.recv(1024).decode().split('\n')[0].strip()
                    print("This is time: {}".format(result))
                    # comparison and getclosests not implemented

                    if "detach_request" in result:
                        print("Caught detach_request and sending enable_s1 again!")
                        pre()

                    if flag == 0:
                        mme_socket.send("attach_reject:emm_cause == 11".encode())
                        flag = 1
                        print("Passing!!")
                        continue

                    print("Response of ENABLE_S1: {}".format(result))
                    mme_socket.settimeout(30)
                    attach_request_guti_counter = 10  # why ???
                    if (
                            "attach_request_guti" in result
                            or "service_request" in result
                            or "tau_request" in result
                            or "detach_request" in result
                    ):
                        print("not normal attach request!!!!!!!\n")
                        attach_request_guti_count += 1
                        flag = 1

                        if attach_request_guti_count < attach_request_guti_counter:
                            print("Sending symbol: attach_reject to MME controller "
                                  "to delete the UE context in attach_request_guti")
                            time.sleep(max(attach_request_guti_count - 1, 1))
                            mme_socket.send("attach_reject:emm_cause == 11".encode())
                        elif attach_request_guti_count % attach_request_guti_counter == 0:
                            handle_enb_epc_failure()
                            pass
                        elif attach_request_guti_count > attach_request_guti_counter:
                            print("Sending symbol: auth_reject to MME controller to delete the UE context")
                            mme_socket.send("auth_reject".encode())
                            time.sleep(2)
                            reboot_ue()
                    elif result.startswith("attach_request"):
                        if flag == 0:
                            flag = 1
                            continue

                        attach_request_guti_count = 0
                        if not sqn_synchronized:
                            print("Sending symbol: auth_request to MME controller, handle error here!!!")
                            mme_socket.send("auth_request_plain_text".encode())

                            result = mme_socket.recv(1024).decode().split('\n')[0].strip()
                            # comparison and getclosests not implemented
                            print("RESULT FROM AUTH REQUEST: {}".format(result))

                            if "auth" in result:
                                print("Recieved {}. Synched the SQN value")
                                sqn_synchronized = True
                                reset_done = True
                                break
                            else:
                                i += 1
                                print("Sleeping for some Seconds")
                                time.sleep(i)
                        elif sqn_synchronized:
                            reset_done = True
                            break
                    # reset_done = True
                except socket.timeout:
                    enable_s1_timeout_count += 1
                    print("Timeout occured for enable_s1")
                    print("Sleeping for a while...")
                    pre()
                    time.sleep(enable_s1_timeout_count)
                    if enable_s1_timeout_count == 10:
                        pass
                        handle_enb_epc_failure()

            result = reset_mme()
            if "attach_request_guti" in result:
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
            if not device == "huwaeiy5":
                result = reset_ue()
            print("---- RESET DONE ----")
    except socket.error as e:
        print("Error : {}".format(e))



def pree():
    print("pre!")
    flag = 0
    global attach_request_guti_count
    global enable_s1_timeout_count
    global reboot_count
    global reset_counter
    global sqn_synchronized
    try:
        if True:  # !config.combine_query??
            reset_done = False
            attach_request_guti_count = 0
            enable_s1_timeout_count = 0
            reboot_count = 0
            i = 0
            print("---- Starting RESET ----")

            while not reset_done:
                try:
                    result = reset_ue()
                    
                    print("Sending enable_s1")
                    send_enable_s1()

                    result = mme_socket.recv(1024).decode().split('\n')[0].strip()
                    print("This is time: {}".format(result))
                    # comparison and getclosests not implemented

                    if "detach_request" in result:
                        print("Caught detach_request and sending enable_s1 again!")
                        pre()

                    if flag == 0 and "attach_request" in result:
                        mme_socket.send("attach_reject:emm_cause == 11".encode())
                        
                        print("sending attach reject!!")
                   
                    result = reset_ue()
                    # if mme_socket:
                    #     mme_socket.close()
                    # time.sleep(1)
                    # if enodeb_socket:
                    #     enodeb_socket.close()
                    # time.sleep(1)
                    # kill_core()
                    # time.sleep(3)
                    # kill_core()
                    # time.sleep(3)
                    # kill_enb()
                    # time.sleep(5)
                    # kill_enb()
                    # time.sleep(10)
                    # start_core()
                    # time.sleep(7)
                    # start_enb()
                    # time.sleep(15)
                    # initialize_socket()
                    # init_core_enb_con()
                    # time.sleep(10)
                    # result = reset_mme()
                    # mme_socket.settimeout(30)
                    # print("Response of reset mme: {}".format(result))
                    send_enable_s1()
                    result = mme_socket.recv(1024).decode().split('\n')[0].strip()
                    if result.startswith("attach_request") and "attach_request_guti" not in result:
                        mme_socket.settimeout(30)
                        if flag == 0:
                            flag = 1
                            reset_done = True
                            result = reset_ue()
                            time.sleep(1)
                            print("reset done\n")
                            continue
                except socket.timeout:
                    enable_s1_timeout_count += 1
                    print("Timeout occured for enable_s1")
                    print("Sleeping for a while...")
                    pre()
                    time.sleep(enable_s1_timeout_count)
                    if enable_s1_timeout_count == 10:
                        pass
                        handle_enb_epc_failure()

            if "attach_request_guti" in result:
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
                print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
            
            print("---- RESET DONE ----")
    except socket.error as e:
        print("Error : {}".format(e))



















def symbol_mapping(s):
    # Original string
    # s = "GUTI_reallocation{integrity == 1 & cipher == 1 & replay == 0}"

    packet_int = 0
    packet_cip = 0
    packet_header = 0
    result = "null"

    # TestCase 5_1 : [['s0', 'enable_s1', 'attach_request', 's1'], ['s1', 'auth_request{cipher == 0}', 'auth_response', 's2'], ['s2', 'security_mode_command{integrity == 1}', 'security_mode_complete', 's3'], ['s3', 'attach_accept{integrity == 1 & cipher == 1 & replay == 0}', 'attach_complete', 's4'], ['s4', 'GUTI_reallocation{integrity == 1 & cipher == 1 & replay == 0}', 'GUTI_reallocation_complete', 's4'], ['s4', 'security_mode_command{integrity == 1 & cipher == 1 & replay == 1}', 'null_action', 'hypothetical_state'], ['hypothetical_state', 'GUTI_reallocation{replay == 1}', 'GUTI_reallocation_complete', 'hypothetical_state']]
    # s = "security_mode_command{integrity == 1, cipher == 0}"

    if "{" not in s:
        return s

    # Split by '{' to separate the message name from the conditions
    message_name, conditions = s.split("{", 1)

    # Remove the trailing '}' from the conditions string
    conditions = conditions.rstrip("}")

    # Split conditions by '&'
    segments = conditions.split("&")

    # Add the message name to the beginning of the segments list
    segments = [message_name] + [segment.strip() for segment in segments]
    print(segments)

    if segments[0].startswith("identity_request"):
        print("identity_request!")

        [packet_int, packet_cip, packet_replay, packet_header] = extract_fields(segments)

        if (packet_replay == 1):
            return "identity_request_replay"

        if (packet_cip == 1 and packet_int == 1):
            return "identity_request_protected"
        elif (packet_cip == 1 and packet_int == 0):
            return "identity_request_encrypt"
        elif (packet_cip == 0 and packet_int == 1):
            return "identity_request_mac"
        elif (packet_cip == 0 and packet_int == 0):
            return "identity_request_plain_text"

    if segments[0].startswith("auth_request"):
        print("auth_request!")

        [packet_int, packet_cip, packet_replay, packet_header] = extract_fields(segments)

        if (packet_replay == 1):
            return "auth_request_replay"

        if (packet_cip == 1 and packet_int == 1):
            return "auth_request_protected"
        elif (packet_cip == 1 and packet_int == 0):
            return "auth_request_encrypt"
        elif (packet_cip == 0 and packet_int == 1):
            return "auth_request_mac"
        elif (packet_cip == 0 and packet_int == 0):
            return "auth_request_plain_text"

    if segments[0].startswith("security_mode"):
        print("security_mode_command!")

        [packet_int, packet_cip, packet_replay, packet_header] = extract_fields(segments)

        if (packet_replay == 1):
            return "sm_command_replay"

        if (packet_cip == 1 and packet_int == 1):
            return "sm_command_int_cip"
        elif (packet_cip == 1 and packet_int == 0):
            return "null"
        elif (packet_cip == 0 and packet_int == 1):
            return "sm_command_protected"
        elif (packet_cip == 0 and packet_int == 0):
            return "sm_command_plain_text" # what's the difference between "security_mode_command_no_integrity"?

    if segments[0].startswith("attach_accept"):
        print("attach_accept!")

        [packet_int, packet_cip, packet_replay, packet_header] = extract_fields(segments)

        if (packet_replay == 1):
            return "attach_accept_replay"

        if (packet_cip == 1 and packet_int == 1):
            return "attach_accept_protected"
        elif (packet_cip == 1 and packet_int == 0):
            return "null"
        elif (packet_cip == 0 and packet_int == 1):
            return "attach_accept_mac"
        elif (packet_cip == 0 and packet_int == 0):
            return "attach_accept_plain_text"

    if segments[0].startswith("GUTI_reallocation"):
        print("GUTI_reallocation!")

        [packet_int, packet_cip, packet_replay, packet_header] = extract_fields(segments)

        if (packet_replay == 1):
            return "GUTI_reallocation_replay"

        if (packet_cip == 1 and packet_int == 1):
            return "GUTI_reallocation_protected"
        elif (packet_cip == 1 and packet_int == 0):
            return "null"
        elif (packet_cip == 0 and packet_int == 1):
            return "null"
        elif (packet_cip == 0 and packet_int == 0):
            return "GUTI_reallocation_plain"



def extract_fields(segments):
    packet_cip = 0
    packet_int = 0
    packet_replay = 0
    packet_header = -1

    for segment in segments:
        if "replay" in segment:
            print("replay appear!")
            if "replay == 1" in segment:
                print("replay packet")
                packet_replay = 1
            else:
                print("not replay packet")

        if "integrity" in segment:
            print("int appear!")
            if "integrity == 1" in segment:
                print("integrity protected")
                packet_int = 1
                # result = "sm_command_protected"
            else:
                print("not integrity protected")
                packet_int = 0

        if "cipher" in segment:
            print("cipher appear!")
            if "cipher == 1" in segment:
                print("ciphered!")
                packet_cip = 1
                # result = "sm_command_protected" # wrong
            else:
                print("not ciphered!")
                packet_cip = 0

        if "security_header" in segment:
            print("security_header appear!")
            if "security_header == 3" in segment:
                packet_header = 3
            else:
                print("unknown header type!")

    return [packet_int, packet_cip, packet_replay, packet_header]