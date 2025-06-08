import os
import random

import shutil

import socket
import time
from datetime import datetime

from database_handler import create_table, query_data, insert_data, list_to_str, str_to_list
from testcase_generator import TestCase, TestCaseStore, check_match_with_reference, get_responsiveness_test, \
    get_reference_output
from testcase_sequence_dump_generator import check_symbol_match, get_states_and_tx, \
    FSM
from ble_adpter_controller import pre_initial, step_general, init_ble_controller, init_device_con, collect_cov



rfsm_filename = 'reference_fsm/ble_rfsm_fuzzing_v3.dot'
num_total_tests = 8000
device_name = "oppo"
run_mode = 2  # 0: manual_testcase , 1: automated , 2: all

random.seed(1)
flush_OTA_log = False

log_file_path_deviating = None
log_file_path_deviating_new = None
log_file_path_unresponsive = None
log_file_path_passed = None
log_file_path_statistics = None
log_file_path_inputs = None
log_file_path_ota_time_query = None


init_ble_controller()
init_device_con()

states, transitions, start_state = get_states_and_tx(rfsm_filename)
reference_fsm = FSM(states, start_state, transitions)


def get_substring_up_to_first_colon(input_string):
    return input_string.split(':', 1)[0] + ":"


def create_new_directory_for_current_run(directory, dev_only=False):
    if not dev_only:
        current_datetime = datetime.now()
        formatted_datetime = current_datetime.strftime("%b%d_%I:%M:%S%p")
        os.mkdir(os.path.join(directory, formatted_datetime + "_{}".format(device_name)))
        return formatted_datetime + "_{}".format(device_name)
    else:
        if flush_OTA_log and os.path.exists(os.path.join(directory, "{}".format(device_name))):
            shutil.rmtree(os.path.join(directory, "{}".format(device_name)))
            os.mkdir(os.path.join(directory, "{}".format(device_name)))
        elif not os.path.exists(os.path.join(directory, "{}".format(device_name))):
            os.mkdir(os.path.join(directory, "{}".format(device_name)))
        return "{}".format(device_name)


def delete_files_in_directory_device(directory):
    files = os.listdir(directory)

    for file in files:
        file_path = os.path.join(directory, file)
        if os.path.isfile(file_path) and device_name in file_path:
            os.remove(file_path)
            # print("Deleted:", file_path)


def send_testcase_ota_single_run(test_case: TestCase, concrete_input_sequence, attempt_num):
    pre_initial()
    # client_socket.send('RESET'.encode())
    # client_socket.recv(1024).decode().strip()

    print("SENDING TESTCASE ::: {}\n".format(concrete_input_sequence))

    print("Sending TestCase OTA Attempt {}\n".format(attempt_num))
    response_output_seq = list()
    responsive = False

    for i in range(len(concrete_input_sequence)):
        time.sleep(1)
        response = step_general(concrete_input_sequence[i])

        if ":" not in str(response):
            response = response + ":"

        if "==" not in str(response):
            response = get_substring_up_to_first_colon(response)

        response_output_seq.append(response)

    print("Test Input {}".format(concrete_input_sequence))
    print("Test Response {} ".format(response_output_seq))

    reference_output_symbol_sequence, reference_final_state, deviating_testcase, _ \
        = test_case.check_for_deviation(concrete_input_sequence, response_output_seq, reference_fsm)

    testcase_pass = test_case.check_for_testcase_pass(concrete_input_sequence, response_output_seq)

    responsiveness_input, expected_output = get_responsiveness_test(reference_final_state)

    time.sleep(1)
    response = step_general(responsiveness_input)

    if ":" not in str(response):
        response = response + ":"

    if "==" not in str(response):
        response = get_substring_up_to_first_colon(response)

    response_output_seq.append(response)

    if check_symbol_match(response,
                          expected_output,
                          responsiveness_input) or "s0" in reference_final_state:
        print("Responsiveness Test Input {}".format(responsiveness_input))
        print("Responsiveness Test Output {}".format(response))
        print("Response Followed Reference")
        responsive = True
    else:
        print("Responsiveness Test Input {}".format(responsiveness_input))
        print("Responsiveness Test Output {}".format(response))
        print("Unresponsive.")

    full_input_seq = concrete_input_sequence + [responsiveness_input]

    print("Send TestCase OTA Single Run Done.")
    return full_input_seq, response_output_seq, testcase_pass, deviating_testcase, responsive


def send_testcase_ota(test_case: TestCase, concrete_input_sequence):
    current_match_count = 0
    target_count = 2
    attempt_count = 0

    current_response = ""
    all_responses = dict()

    while current_match_count < target_count and attempt_count < 12:

        if attempt_count % 5 == 0:
            pre_initial()
            pass

        full_input_seq, respond_output_seq, testcase_pass, deviating_testcase, responsive \
            = send_testcase_ota_single_run(test_case, concrete_input_sequence, attempt_count)

        if not testcase_pass and not deviating_testcase and responsive:
            print("Send TestCase OTA Done.")
            return respond_output_seq

        if attempt_count == 0:
            current_response = list_to_str(respond_output_seq)
            current_match_count = 1
            attempt_count += 1
            continue
        else:
            if list_to_str(respond_output_seq) == current_response:
                current_match_count += 1
                if current_match_count == target_count:
                    print("Send TestCase OTA Done.")
                    return respond_output_seq
            else:
                current_match_count = 1
                current_response = list_to_str(respond_output_seq)

        if list_to_str(respond_output_seq) in all_responses.keys():
            all_responses[list_to_str(respond_output_seq)] += 1
        else:
            all_responses[list_to_str(respond_output_seq)] = 1

        attempt_count += 1

    print("ERROR : OTA TESTING FAILING\n")
    with open(os.path.join('failed_testcases', 'failed_testcases_{}.txt'.format(device_name)), 'a') as fw:
        fw.write("{}\n".format(concrete_input_sequence))

    majority_num = 0
    majority_resp = "null_action:"
    for k, v in all_responses.items():
        if v > majority_num:
            majority_resp = str_to_list(k)
            majority_num = v

    print("Send TestCase OTA Done.")
    return majority_resp


def send_testcase(test_case: TestCase, concrete_input_sequence):
    reference_output, ref_final_state = get_reference_output(concrete_input_sequence, reference_fsm)
    responsiveness_input, expected_output = get_responsiveness_test(ref_final_state)

    full_input_seq = concrete_input_sequence + [responsiveness_input]

    in_db, response_output_seq = query_data(full_input_seq, device_name)

    if in_db:
        print("Query Answer Found in Database.")
        print("Test Input {}".format(concrete_input_sequence))
        print("Test Response {} ".format(response_output_seq[:len(concrete_input_sequence)]))

        _, _, deviating_testcase \
            = check_match_with_reference(concrete_input_sequence,
                                         response_output_seq[:len(concrete_input_sequence)], reference_fsm)

        testcase_pass = test_case.check_for_testcase_pass(concrete_input_sequence,
                                                          response_output_seq[:len(concrete_input_sequence)])

        if check_symbol_match(response_output_seq[-1],
                              expected_output,
                              responsiveness_input):
            print("Responsiveness Test Input {}".format(responsiveness_input))
            print("Responsiveness Test Output {}".format(response_output_seq[-1]))
            print("Response Followed Reference")
            responsive = True
        else:
            responsive = False
    else:
        print("Testing OTA.")
        response_output_seq = send_testcase_ota(test_case, concrete_input_sequence)

        _, _, deviating_testcase \
            = check_match_with_reference(concrete_input_sequence,
                                         response_output_seq[:len(concrete_input_sequence)], reference_fsm)

        testcase_pass = test_case.check_for_testcase_pass(concrete_input_sequence,
                                                          response_output_seq[:len(concrete_input_sequence)])

        if check_symbol_match(response_output_seq[-1],
                              expected_output,
                              responsiveness_input):
            responsive = True
        else:
            responsive = False

    print("Send TestCase Done.")

    return full_input_seq, response_output_seq, testcase_pass, deviating_testcase, responsive, in_db, \
        reference_output, responsiveness_input, expected_output, ref_final_state


def send_tests_single_testcase_dump(testcase_dump_filename,
                                    stat_file,
                                    num_tests):
    stat_file.write("File {}\n".format(testcase_dump_filename))
    testcase_store = TestCaseStore(device_name)

    tested_case_count = 0
    test_case_OTA_count = 0
    current_OTA_count = 0
    test_case_db_count = 0
    testcase_passed_count = 0
    deviated_testcase_count = 0
    unresponsive_testcase_count = 0
    not_ok_count = 0

    total_elapsed_time_ota = 0.0
    file_string = testcase_dump_filename.split('.json')[0].strip() + "_time_{}.txt".format(device_name)
    with open(os.path.join(os.path.join('ota_time_testcases', log_file_path_ota_time_query), file_string),
              'r') as fr:
        lines = fr.readlines()
        for line in lines:
            if "." in line:
                e_t = float(line.split("\n")[0].strip())
                total_elapsed_time_ota += e_t

    while not (testcase_store.all_done or tested_case_count >= num_tests):

        if current_OTA_count == 3:
            current_OTA_count = 0

        test_case = None
        concrete_input_sequence = None
        while not testcase_store.all_done:
            test_case = testcase_store.select_testcase()
            if test_case is None:
                print("All Done.")
                break

            ok_to_test_prefix = test_case.check_non_working_prefix(device_name)

            if not ok_to_test_prefix:
                print("Test {} Prefix of Before.".format(test_case.testcase_id))
                not_ok_count += 1
                testcase_store.delete_testcase_hard(test_case.property_id, test_case.testcase_id)
                continue

            ok_to_test, concrete_input_sequence = test_case.get_concrete_input_sequence()

            if not ok_to_test or concrete_input_sequence is None:
                print("Selected testcase {} was done. Selecting Another one.".format(test_case.testcase_id))
            else:
                break

        current_time = time.time()
        full_input_seq, response_output_seq, testcase_pass, deviating_testcase, responsive, in_db, \
            reference_output, responsiveness_input, expected_output, ref_final_state = (
            send_testcase(test_case, concrete_input_sequence))
        elapsed_time_query = time.time() - current_time

        print("Total OTA Elapsed Time : {} Seconds.".format(total_elapsed_time_ota))
        print("Statistics: , {} {} {} {} {} {}".format(test_case_db_count,
                                                       test_case_OTA_count,
                                                       testcase_passed_count,
                                                       deviated_testcase_count,
                                                       unresponsive_testcase_count,
                                                       not_ok_count))

        print("TEST {} PROPERTY {} ID {}".format(tested_case_count,
                                                 test_case.property_id,
                                                 test_case.testcase_id))

        good_response = True
        for i in range(len(response_output_seq)):
            if ("scan_req" in response_output_seq[i] and
                    response_output_seq[i] != "scan_req:"):
                good_response = False

            if ":" in response_output_seq[i]:
                msg, field = response_output_seq[i].split(":")[0], response_output_seq[i].split(":")[1]
                if field != "" and "==" not in field:
                    good_response = False

        if "null_action" in response_output_seq[0] or not good_response:
            attempts = 0
            while attempts < 10:
                good_response = True
                print("Not Good Response, restarting everything....\n")
                pre_initial()
                # reset_ue()
                # time.sleep(1)
                # handle_enb_epc_failure()
                full_input_seq, response_output_seq, testcase_pass, deviating_testcase, responsive, in_db, \
                    reference_output, responsiveness_input, expected_output, ref_final_state \
                    = send_testcase(test_case, concrete_input_sequence)

                for i in range(len(response_output_seq)):
                    if ("scan_req" in response_output_seq[i] and
                            response_output_seq[i] != "scan_req:"):
                        good_response = False

                    if ":" in response_output_seq[i]:
                        msg, field = response_output_seq[i].split(":")[0], response_output_seq[i].split(":")[1]
                        if field != "" and "==" not in field:
                            good_response = False

                if "null_action" not in response_output_seq[0] and good_response:
                    break

                attempts += 1

        if not in_db:
            insert_data(full_input_seq, response_output_seq, device_name)

            file_string = testcase_dump_filename.split('.json')[0].strip() + "_{}.txt".format(device_name)

            with open(os.path.join(os.path.join('ota_time_testcases', log_file_path_ota_time_query), file_string),
                      'a') as fw:
                fw.write("{}\n".format(full_input_seq))

            file_string = testcase_dump_filename.split('.json')[0].strip() + "_time_{}.txt".format(device_name)

            with open(os.path.join(os.path.join('ota_time_testcases', log_file_path_ota_time_query), file_string),
                      'a') as fw:
                fw.write("{}\n".format(elapsed_time_query))

            total_elapsed_time_ota += elapsed_time_query

        tested_case_count += 1

        if testcase_pass and deviating_testcase:
            testcase_passed_count += 1
        if deviating_testcase:
            deviated_testcase_count += 1
        if not responsive:
            unresponsive_testcase_count += 1
        if in_db:
            test_case_db_count += 1
        else:
            test_case_OTA_count += 1
            current_OTA_count += 1

        if testcase_pass and deviating_testcase:
            test_case.report_testcase_pass()
            print("TESTCASE PASSED: Property {} ID {}".format(test_case.property_id,
                                                              test_case.testcase_id))
            file_string = testcase_dump_filename.split('.json')[0].strip() + "_{}.txt".format(device_name)

            with open(os.path.join(os.path.join('passed_testcases', log_file_path_passed), file_string), 'a') as fw:
                fw.write("TEST {} PASSED!! -- Testcase Property {} ID {}\n".format(tested_case_count,
                                                                                   test_case.property_id,
                                                                                   test_case.testcase_id))

                fw.write("Input Seq : {}\n".format(full_input_seq[:-1]))
                fw.write("Response Output Seq : {}\n".format(response_output_seq[:-1]))
                fw.write(
                    "Attacker Expected Output Seq : {}\n".format(test_case.attacker_expectation_output_symbol_sequence))

                fw.write("Reference: {}\n".format(reference_output))
                fw.write("\n\n")

        if deviating_testcase:
            _, _, _, log_dev = (
                test_case.check_for_deviation(full_input_seq[:-1], response_output_seq[:-1], reference_fsm,
                                              report=True))
            print("TESTCASE DEVIATING: Property {} ID {}".format(test_case.property_id,
                                                                 test_case.testcase_id))

            file_string = testcase_dump_filename.split('.json')[0].strip() + "_{}.txt".format(device_name)

            with open(os.path.join(os.path.join('deviating_testcases', log_file_path_deviating), file_string),
                      'a') as fw:

                fw.write("TEST {} DEVIATED!! -- Testcase Property {} ID {}\n".format(tested_case_count,
                                                                                     test_case.property_id,
                                                                                     test_case.testcase_id))

                fw.write("Input Seq : {}\n".format(full_input_seq[:-1]))
                fw.write("Response Output Seq : {}\n".format(response_output_seq[:-1]))
                fw.write("Reference: {}\n".format(reference_output))
                fw.write("\n\n")

            if log_dev:
                print("TESTCASE DEVIATING (NEW): Property {} ID {}".format(test_case.property_id,
                                                                           test_case.testcase_id))

                file_string = testcase_dump_filename.split('.json')[0].strip() + "_{}.txt".format(device_name)

                with open(
                        os.path.join(os.path.join('new_deviating_testcases', log_file_path_deviating_new), file_string),
                        'a') as fw:
                    fw.write("TEST {} DEVIATED!! -- Testcase Property {} ID {}\n".format(tested_case_count,
                                                                                         test_case.property_id,
                                                                                         test_case.testcase_id))

                    fw.write("Input Seq : {}\n".format(full_input_seq[:-1]))
                    fw.write("Response Output Seq : {}\n".format(response_output_seq[:-1]))
                    fw.write("Reference: {}\n".format(reference_output))
                    fw.write("\n\n")

        if (not testcase_pass) and not responsive:
            test_case.report_unresponsive()
            print("TESTCASE RENDERS UNRESPONSIVE: Property{} ID {}".format(test_case.property_id,
                                                                           test_case.testcase_id))
            file_string = testcase_dump_filename.split('.json')[0].strip() + "_{}.txt".format(device_name)

            with open(os.path.join(os.path.join('unresponsive_testcases', log_file_path_unresponsive), file_string),
                      'a') as fw:
                fw.write("TEST {} UNRESPONSIVE!! -- Testcase Property {} ID {}\n".format(tested_case_count,
                                                                                         test_case.property_id,
                                                                                         test_case.testcase_id))

                fw.write("Input Seq : {}\n".format(full_input_seq[:-1]))
                fw.write("Response Output Seq : {}\n".format(response_output_seq[:-1]))
                fw.write("Reference: {}\n".format(reference_output))
                fw.write("\n\n")
                fw.write("Responsiveness Check at {}\n".format(ref_final_state))
                fw.write("Responsiveness Input {}\n".format(responsiveness_input))
                fw.write("\n\n")

        elapsed_time = time.time() - start_time
        file_string = testcase_dump_filename.split('.json')[0].strip() + "_{}.txt".format(device_name)

        with open(os.path.join(os.path.join('log_testcases', log_file_path_inputs), file_string),
                  'a') as fw:
            fw.write("{}\n".format(full_input_seq))

        file_string = testcase_dump_filename.split('.json')[0].strip() + "_time_{}.txt".format(device_name)

        with open(os.path.join(os.path.join('log_testcases', log_file_path_inputs), file_string),
                  'a') as fw:
            fw.write("{}\n".format(elapsed_time))

        print("\n")
        stat_file.write("Tested ID {}, Total Tested : {}, OTA Tested : {}, "
                        "DB : {}, Deviating : {}, Unresponsive : {}, Passed : {}\n".format(
            test_case.testcase_id,
            tested_case_count,
            test_case_OTA_count,
            test_case_db_count,
            deviated_testcase_count,
            unresponsive_testcase_count,
            testcase_passed_count))
        stat_file.flush()

        test_case.process_non_working_prefix(response_output_seq, device_name)
        testcase_store.delete_testcase(test_case.property_id, test_case.testcase_id)

    print("File {}\n".format(testcase_dump_filename))
    print("Total Tested Cases: {}".format(tested_case_count))
    print("Total Passed TestCases: {}".format(testcase_passed_count))
    print("Total Deviating TestCases: {}".format(deviated_testcase_count))
    print("Total TestCases Rendering Unresponsive: {}".format(unresponsive_testcase_count))
    print("Total OTA Tested Cases: {}".format(test_case_OTA_count))
    print("Total TestCases Loaded from Database: {}".format(test_case_db_count))

    stat_file.write("Total Tested Cases: {}\n".format(tested_case_count))
    stat_file.write("Total Passed TestCases: {}\n".format(testcase_passed_count))
    stat_file.write("Total Deviating TestCases: {}\n".format(deviated_testcase_count))
    stat_file.write("Total TestCases Rendering Unresponsive: {}\n".format(unresponsive_testcase_count))
    stat_file.write("Total OTA Tested Cases: {}\n".format(test_case_OTA_count))
    stat_file.write("Total TestCases Loaded from Database: {}\n\n\n".format(test_case_db_count))
    stat_file.flush()


def send_created_testcases():
    if not os.path.exists('failed_testcases'):
        os.mkdir('failed_testcases')

    if not os.path.exists('deviating_testcases'):
        os.mkdir('deviating_testcases')

    if not os.path.exists('new_deviating_testcases'):
        os.mkdir('new_deviating_testcases')

    if not os.path.exists('unresponsive_testcases'):
        os.mkdir('unresponsive_testcases')

    if not os.path.exists('passed_testcases'):
        os.mkdir('passed_testcases')

    if not os.path.exists('log_testcases'):
        os.mkdir('log_testcases')

    global log_file_path_deviating
    global log_file_path_deviating_new
    global log_file_path_unresponsive
    global log_file_path_passed
    global log_file_path_statistics
    global log_file_path_inputs
    global log_file_path_ota_time_query

    log_file_path_deviating = create_new_directory_for_current_run('deviating_testcases')
    log_file_path_deviating_new = create_new_directory_for_current_run('new_deviating_testcases')
    log_file_path_unresponsive = create_new_directory_for_current_run('unresponsive_testcases')
    log_file_path_passed = create_new_directory_for_current_run('passed_testcases')
    log_file_path_statistics = create_new_directory_for_current_run('final_statistics')
    log_file_path_inputs = create_new_directory_for_current_run('log_testcases')
    log_file_path_ota_time_query = create_new_directory_for_current_run('ota_time_testcases') # was True
        # , True)

    create_table(device_name)

    with open(os.path.join(os.path.join('final_statistics', log_file_path_statistics),
                           'all_testcases_{}.txt'.format(device_name)), 'w') as fw:
        send_tests_single_testcase_dump('all_testcases.json', fw, num_total_tests)


start_time = time.time()
send_created_testcases()
