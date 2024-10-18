import json
import math
import os
from pprint import pprint

import numpy as np

from testcase_sequence_dump_generator import get_states_and_tx

states, _, _ = get_states_and_tx(os.path.join('reference_fsm', 'ble_rfsm_fuzzing_v3.dot'))
states = list(set(states))


def extract_prefix(string):
    penultimate_semicolon_index = string.rfind(";", 0, string.rfind(";"))
    if penultimate_semicolon_index != -1:
        extracted_string = string[:penultimate_semicolon_index + 1]
        return extracted_string
    else:
        return None


def extract_last_message(string):
    penultimate_semicolon_index = string.rfind(";", 0, string.rfind(";"))
    if penultimate_semicolon_index != -1:
        extracted_string = str(string[penultimate_semicolon_index + 1:]).strip()
        extracted_string = str(extracted_string).split("<")[1].split(",")[0].strip()
        extracted_string = str(extracted_string).split(":")[2].strip()
        # print(extracted_string)
        return extracted_string
    else:
        return None


def calculate_probability_for_properties():
    qre_files = os.listdir('qre_expressions')
    for qre_exp_file in qre_files:
        if "_p" not in qre_exp_file:
            with open(os.path.join('qre_expressions', qre_exp_file), 'r') as fr:

                property_dict = dict()
                lines = fr.readlines()
                num_properties = 0

                for i, line in enumerate(lines):
                    num_properties += 1
                    if ";" in line:
                        property_exp = line.split("##")[0].strip()
                        property_num = int(line.split('\n')[0].split("##")[1].strip().split(' ')[2].strip())

                        testcase_dump_filename = qre_exp_file.split(".")[0] + '_' + str(i) + '.json'
                        testcase_dump_filename = os.path.join("testcases_dump", testcase_dump_filename)

                        states_visited_list = list()
                        if os.path.exists(testcase_dump_filename):
                            with open(testcase_dump_filename, 'r') as fr:
                                testcase_dump = json.load(fr)
                                min_length = math.inf
                                min_t = testcase_dump["testcases"][0]
                                for testcase in testcase_dump['testcases']:
                                    if testcase['length'] < min_length:
                                        min_length = testcase['length']
                                        min_t = testcase

                                for j in range(len(min_t["testcase"])):
                                    init_state = min_t['testcase'][j]['initial_state']
                                    states_visited_list.append(init_state)

                        states_visited_list = list(set(states_visited_list))

                        if property_num not in property_dict.keys():
                            property_dict[property_num] = dict()
                            property_dict[property_num][num_properties] = [property_exp, len(states_visited_list)]
                        else:
                            property_dict[property_num][num_properties] = [property_exp, len(states_visited_list)]

                c_sum = 0
                prop_probs = dict()
                for k, props in property_dict.items():
                    num_props_k = len(list(props.keys()))
                    avg_states_visited = np.average([prop[1]/len(states) for _, prop in props.items()])
                    prop_probs[k] = avg_states_visited
                    c_sum += prop_probs[k]

                for k, props in property_dict.items():
                    prop_probs[k] /= c_sum

                c_sum = 0
                for k, props in property_dict.items():
                    num_props_k = len(list(props.keys()))
                    for id, prop in props.items():
                        prop[1] = prop_probs[k] / num_props_k
                        c_sum += prop[1]

                for k, props in property_dict.items():
                    for id, prop in props.items():
                        prop[1] /= c_sum

                with open(os.path.join('qre_expressions', qre_exp_file.split(".")[0] + "_p.txt"), 'w') as fw:
                    for k, props in property_dict.items():
                        for id, prop in props.items():
                            fw.write("{} ## {}\n".format(prop[0], prop[1]))