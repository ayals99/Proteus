import json
import math
import os
import random

from popular_mutations_property_assignment import calculate_mutation_probabilities
from testcase_generation_db_handler import create_db_non_working_prefixes, \
    insert_data_prefix, query_data_prefix, create_table_mutation_info, insert_data_mutation_info, query_mutation_info
from testcase_sequence_dump_generator import FSM, Token, extract_message_and_fields, extract_info_from_transition, \
    list_violations
from testcase_sequence_dump_generator import check_symbol_match

random.seed(1)

with open(os.path.join('considered_inputs_dir', 'message_fields_ble.json'), 'r') as fr:
    all_message_format = json.load(fr)

mutation_selection_rate = 0.8


def choose_with_distribution(elements, probabilities):
    total_prob = sum(probabilities)
    if total_prob != 1:
        probabilities = [prob / total_prob for prob in probabilities]

    chosen_index = random.choices(range(len(elements)), weights=probabilities, k=1)[0]
    return elements[chosen_index]


def choose_with_probability(y):
    probability = y / 100
    random_number = random.random()
    if random_number < probability:
        return 1
    else:
        return 0


def get_mutated_message(mutated_inp_symbol, input_seq_prefix):
    valid_messages = [
        "version_req: ll_length == 0 & llid == 0",
        "con_req:interval == 0 & timeout == 0 & ll_length == 0 & channel_map == 0",
        "pair_req:oob == 0 & no_sc == 0 & key == 0 & llid == 0",
        "length_req:ll_length == 0",
        "feature_req:",
        "pri_req:",
        "start_enc_resp:plain == 0",
        "enc_pause_req:plain == 0",
        "enc_pause_resp:plain == 0",
        "pair_confirm:wrong_value == 0",
        "dh_check:invalid == 0",
        "key_exchange:invalid == 0 & ll_length == 0",
        "pair_confirm:wrong_value == 0"
    ]

    inp_msg, inp_field = extract_message_and_fields(mutated_inp_symbol)
    mutation_original_msg = str(inp_msg).split("mutation(")[1].split(",", 1)[0].strip()
    mutation_qre = str(inp_msg).split(",", 1)[1].split(")")[0].strip()
    tok = Token(mutation_qre)

    if not tok.check_token_match("::{}:".format(mutation_original_msg), "::$:")[0]:
        while not tok.check_token_match("::{}:".format(mutation_original_msg), "::$:")[0]:
            mutation_original_msg = random.choice(list(all_message_format.keys()))

    is_in_db, vals_with_prob = query_mutation_info(mutation_original_msg)
    vals = [e[0] for e in vals_with_prob]
    prob = [float(e[1]) for e in vals_with_prob]
    print(mutation_original_msg, vals, prob)

    if is_in_db and len(vals) > 0:
        attempts = 10 * len(vals)
        while True and attempts > 0:

            val = random.choices(vals, weights=prob)[0]
            print(val, mutation_original_msg, tok.token_str)

            ok = True
            if "replay == 1" in val:
                ok = False
                for inp_prev in input_seq_prefix:
                    if mutation_original_msg in inp_prev:
                        ok = True
                        break

            if (tok.check_token_match("::{}".format(val), "::$:") and ok
                    and val not in valid_messages):
                return val, mutation_original_msg
            attempts -= 1
    else:
        print("No mutation for {}".format(mutation_original_msg))
        for vm in valid_messages:
            if mutation_original_msg in vm:
                return vm, mutation_original_msg


def get_reference_output(concrete_input_sequence, reference_fsm: FSM):
    _, reference_output_symbol_sequence, reference_final_state = \
        reference_fsm.generate_fsm_output_sequence_total(concrete_input_sequence)

    return reference_output_symbol_sequence, reference_final_state


def check_match_with_reference(concrete_input_sequence,
                               response_output_seq, reference_fsm):
    deviating = False
    _, reference_output_symbol_sequence, reference_final_state = \
        reference_fsm.generate_fsm_output_sequence_total(concrete_input_sequence)

    for i in range(len(response_output_seq)):
        if not check_symbol_match(response_output_seq[i], reference_output_symbol_sequence[i],
                                  concrete_input_sequence[i]):
            if "null_action" in response_output_seq[i]:
                if ("reject" in reference_output_symbol_sequence[i] or
                        "failure" in reference_output_symbol_sequence[i]):
                    continue

            if (("reject" in response_output_seq[i] or
                 "failure" in response_output_seq[i])
                    and "null_action" in reference_output_symbol_sequence[i]):
                continue

            deviating = True

    return reference_output_symbol_sequence, reference_final_state, deviating


def get_responsiveness_test(final_reference_state):
    if final_reference_state.startswith("s0"):
        return "scan_req:", "scan_resp:"
    elif final_reference_state.startswith("s1"):
        return "scan_req:", "scan_resp:"

    elif final_reference_state.startswith("s2"):
        return "pair_req:oob == 0 & no_sc == 0 & key == 0 & llid == 0", \
            "pair_resp:"
    elif final_reference_state.startswith("s3"):
        return "scan_req:", "scan_resp:"
    elif final_reference_state.startswith("s4"):
        return "key_exchange:invalid == 0 & ll_length == 0", "public_key_response_sm_confirm:"
    elif final_reference_state.startswith("s5"):
        return "sm_random_send:", "sm_random_received:"
    elif final_reference_state.startswith("s6"):
        return "dh_check:invalid == 0", "dh_key_response:"
    elif final_reference_state.startswith("s7"):
        return "mtu_req:ll_length == 0 & llid == 0", "mtu_resp:"
    elif final_reference_state.startswith("s8"):
        return "scan_req:", "scan_resp:"
    elif final_reference_state.startswith("s9"):
        return "scan_req:", "scan_resp:"
    elif final_reference_state.startswith("s10"):
        return "scan_req:", "scan_resp:"
    elif final_reference_state.startswith("s11"):
        return "scan_req:", "scan_resp:"
    elif final_reference_state.startswith("s12"):
        return "scan_req:", "scan_resp:"
    elif final_reference_state.startswith("s13"):
        return "scan_req:", "scan_resp:"
    elif final_reference_state.startswith("s14"):
        return "scan_req:", "scan_resp:"
    elif final_reference_state.startswith("s15"):
        return "scan_req:", "scan_resp:"


def get_original_message_mutated(mutated_inp_symbol):
    inp_msg, inp_field = extract_message_and_fields(mutated_inp_symbol)
    mutation_original_msg = str(inp_msg).split("mutation(")[1].split(",", 1)[0].strip()
    return mutation_original_msg


class TestCase:
    def __init__(self, testcase_dict, property_id, parent_property_store):
        self.reference_output_symbol_sequence = None
        self.final_state_responsive_ios = None
        self.testcase_id = testcase_dict["id"]
        self.property_id = int(property_id)
        self.full_testcase_id = str(property_id) + "-" + str(testcase_dict["id"])
        self.has_mutation = testcase_dict["has_mutation"]
        self.reference_final_state = None

        self.input_combined_start_sequence = []
        self.input_symbol_sequence = []
        self.attacker_expectation_output_symbol_sequence = []
        self.input_next_combined_state_sequence = []

        self.removed = False

        self.use_count = testcase_dict["use_count"]
        self.unresponsive_count = 0

        self.deviation_used_count = 0
        self.mutation_used_count = 0

        self.mutating_messages = list()
        self.message_state_wise = dict()
        self.parent_property_store = parent_property_store

        self.mutation_messages_used = list()

        for elem_dict in testcase_dict["testcase"]:
            self.input_combined_start_sequence.append(elem_dict["initial_state"])
            self.input_symbol_sequence.append(elem_dict["input_symbol"])
            self.attacker_expectation_output_symbol_sequence.append(elem_dict["output_symbol"])
            self.input_next_combined_state_sequence.append(elem_dict["next_state"])

            if "mutation" in elem_dict["input_symbol"]:
                mutation_original_msg = (
                    str(elem_dict["input_symbol"]).split("mutation(")[1].split(",", 1)[0].strip())
                self.mutating_messages.append(mutation_original_msg.strip())
                (self.message_state_wise.setdefault(elem_dict["initial_state"], []).
                 append(mutation_original_msg.strip()))
            else:
                (self.message_state_wise.setdefault(elem_dict["initial_state"], []).
                 append(elem_dict["input_symbol"]))

        # print(self.mutating_messages)

    # def update_num_deviations_match(self):
    #     deviation_count = 0
    #     for k, v in (self.parent_property_store.
    #                 parent_testcase_store.
    #                 deviating_messages_per_state).items():
    #         if k in self.message_state_wise.keys():
    #             messages_state = self.message_state_wise[k]
    #             for msg in list(set(v)):
    #                 for msg_2 in messages_state:
    #                     if msg in msg_2:
    #                         deviation_count += 1
    #     self.deviation_used_count = deviation_count

    def report_unresponsive(self):
        self.unresponsive_count += 1

    def report_testcase_pass(self):
        self.parent_property_store.parent_testcase_store.make_property_done(self.parent_property_store.property_id)

    def make_deviation_changes(self, concrete_input_sequence, response_output_seq,
                               deviating_states, deviating_inputs, deviating_outputs):
        log_deviations = False
        initial_deviating_state = deviating_states[0]
        initial_deviating_input = deviating_inputs[0]
        initial_deviating_output = deviating_outputs[0]

        dev_dict = (self.parent_property_store.
                    parent_testcase_store.
                    deviating_messages_per_state)

        if (initial_deviating_state not in dev_dict.keys() or
                initial_deviating_input not in dev_dict[initial_deviating_state]):
            if not ("null_action" in initial_deviating_output
                    or "reject" in initial_deviating_output
                    or "failure" in initial_deviating_output
                    or "emm_status" in initial_deviating_output):
                log_deviations = True
                dev_dict.setdefault(initial_deviating_state, []).append(initial_deviating_input)
                dev_dict[initial_deviating_state] = list(set(dev_dict[initial_deviating_state]))

            concrete_testcase = list()
            for i in range(len(response_output_seq)):
                concrete_testcase.append([concrete_input_sequence[i], response_output_seq[i]])

            (self.parent_property_store.
             parent_testcase_store.check_property_done_deviation(concrete_testcase, initial_deviating_input))

        for d_s, d_i, d_o in zip(deviating_states, deviating_inputs, deviating_outputs):
            if (d_s not in dev_dict.keys() or
                    d_i not in dev_dict[d_s]):
                if not ("null_action" in d_o
                        or "reject" in d_o
                        or "failure" in d_o
                        or "emm_status" in d_o):
                    log_deviations = True
                    break

        return log_deviations

    def check_for_testcase_pass(self, concrete_input_sequence, response_output_seq):
        attacker_match = True

        for i in range(len(response_output_seq)):
            if not check_symbol_match(response_output_seq[i],
                                      self.attacker_expectation_output_symbol_sequence[i],
                                      concrete_input_sequence[i]):
                if "null_action" in response_output_seq[i]:
                    if ("reject" in self.attacker_expectation_output_symbol_sequence[i] or
                            "fail" in self.attacker_expectation_output_symbol_sequence[i] or
                            "emm_status" in self.attacker_expectation_output_symbol_sequence[i]):
                        continue

                if (("reject" in response_output_seq[i] or
                     "fail" in response_output_seq[i] or
                     "emm_status" in response_output_seq[i])
                        and "null_action" in self.attacker_expectation_output_symbol_sequence[i]):
                    continue

                attacker_match = False

        return attacker_match

    def check_for_deviation(self, concrete_input_sequence,
                            response_output_seq, reference_fsm, report=False):
        deviating = False
        input_transitions, reference_output_symbol_sequence, reference_final_state = \
            reference_fsm.generate_fsm_output_sequence_total(concrete_input_sequence)
        deviating_inputs = list()
        deviating_states = list()
        deviating_outputs = list()
        log_deviations = False

        for i in range(len(response_output_seq)):
            if not check_symbol_match(response_output_seq[i], reference_output_symbol_sequence[i],
                                      concrete_input_sequence[i]):
                if not ("null_action" in str(response_output_seq[i]).lower() or
                        "reject" in str(response_output_seq[i]).lower() or
                        "fail" in str(response_output_seq[i]).lower() or
                        "emm_status" in str(response_output_seq[i]).lower()):

                    if ("reject" in str(reference_output_symbol_sequence[i]).lower() or
                            "fail" in str(reference_output_symbol_sequence[i]).lower() or
                            "null_action" in str(reference_output_symbol_sequence[i]).lower() or
                            "emm_status" in str(reference_output_symbol_sequence[i]).lower()):
                        input_state, input_var_exp, inp_msg, inp_fields = extract_info_from_transition(
                            input_transitions[i])
                        deviating_inputs.append(inp_msg)
                        deviating_states.append(input_state + ":" + input_var_exp)
                        deviating_outputs.append(response_output_seq[i])
                        deviating = True

                if ("null_action" in str(response_output_seq[i]).lower() or
                        "reject" in str(response_output_seq[i]).lower() or
                        "fail" in str(response_output_seq[i]).lower() or
                        "emm_status" in str(response_output_seq[i]).lower()):

                    if not ("reject" in str(reference_output_symbol_sequence[i]).lower() or
                            "fail" in str(reference_output_symbol_sequence[i]).lower() or
                            "null_action" in str(reference_output_symbol_sequence[i]).lower() or
                            "emm_status" in str(reference_output_symbol_sequence[i]).lower()):
                        input_state, input_var_exp, inp_msg, inp_fields = extract_info_from_transition(
                            input_transitions[i])
                        deviating_inputs.append(inp_msg)
                        deviating_states.append(input_state + ":" + input_var_exp)
                        deviating_outputs.append(response_output_seq[i])
                        deviating = True

        if report and deviating:
            log_deviations = self.make_deviation_changes(concrete_input_sequence,
                                                         response_output_seq,
                                                         deviating_states,
                                                         deviating_inputs,
                                                         deviating_outputs)

        return reference_output_symbol_sequence, reference_final_state, deviating, log_deviations

    def check_non_working_prefix(self, device_name):
        inp_list = self.input_symbol_sequence
        out_list = self.attacker_expectation_output_symbol_sequence
        if query_data_prefix(inp_list, out_list, device_name):
            return False
        return True

    def process_non_working_prefix(self, response_output_seq, device_name):
        do_process, inp_list, out_list = self.get_non_working_prefix(response_output_seq)
        if do_process:
            insert_data_prefix(inp_list, out_list, device_name)

    def print_testcase(self):
        print("Testcase {}".format(self.testcase_id))
        print("Input Seq : {}".format(self.input_symbol_sequence))
        print("Output Seq : {}".format(self.attacker_expectation_output_symbol_sequence))
        print("\n\n")

    def get_concrete_input_sequence(self):

        num_attempts = 12
        concrete_input_symbol_sequence = list()
        ok_to_test = False
        while num_attempts > 0:
            curr_msg_mutation_messages = "####"
            concrete_input_symbol_sequence = list()
            concrete_input_symbol_sequence.clear()

            for i in range(len(self.input_symbol_sequence)):
                if "mutation" not in self.input_symbol_sequence[i]:
                    concrete_input_symbol_sequence.append(self.input_symbol_sequence[i])
                else:
                    mutated_message, original_message_mutated = get_mutated_message(self.input_symbol_sequence[i],
                                                                                    self.input_symbol_sequence[:i])

                    curr_msg_mutation_messages += str(mutated_message) + "####"
                    concrete_input_symbol_sequence.append(mutated_message)

            if not self.has_mutation:
                ok_to_test = True
                break

            ok_to_test = True
            for e in self.mutation_messages_used:
                if curr_msg_mutation_messages == e:
                    ok_to_test = False

            if ok_to_test:
                self.mutation_messages_used.append(curr_msg_mutation_messages)
                break

            num_attempts -= 1

        if not ok_to_test:
            self.parent_property_store.delete_testcase_hard(self.testcase_id)

        return ok_to_test, concrete_input_symbol_sequence

    def get_non_working_prefix(self, response_output_seq):
        for i in range(len(self.input_symbol_sequence)):

            if "mutation" in self.input_symbol_sequence[i]:
                break

            if not check_symbol_match(response_output_seq[i],
                                      self.attacker_expectation_output_symbol_sequence[i],
                                      self.input_symbol_sequence[i]):
                if ("null_action" in response_output_seq[i] or
                        "reject" in response_output_seq[i] or "fail" in response_output_seq[i]):
                    if not ("null_action" in self.attacker_expectation_output_symbol_sequence[i] or
                            "reject" in self.attacker_expectation_output_symbol_sequence[i] or
                            "fail" in self.attacker_expectation_output_symbol_sequence[i]):
                        if len(self.input_symbol_sequence[:i + 1]) > 2:
                            return True, \
                                self.input_symbol_sequence[:i + 1], \
                                self.attacker_expectation_output_symbol_sequence[:i + 1]

        return False, [], []


def remove_from_list(store_list, item_id):
    new_list = list()
    for i in range(len(store_list)):
        if int(store_list[i]) != item_id:
            new_list.append(store_list[i])

    return new_list


def populate_popular_mutations():
    print("Inserting Popular Mutations.")
    calculate_mutation_probabilities()
    with open(os.path.join('considered_inputs_dir', 'popular_mutations_with_probabilities.txt'), 'r') as fr:
        lines = fr.readlines()
        for line in lines:
            if "##" in line:
                msg_combined = line.split("\n")[0].strip().split("##")[0].strip()
                prob = line.split("\n")[0].strip().split("##")[1].strip()
                inp_msg, inp_fields = extract_message_and_fields(msg_combined)
                # print(inp_msg, msg_combined)
                insert_data_mutation_info(inp_msg, msg_combined, prob)
    print("Done.\n")


class PropertyStore:

    def __init__(self, json_filename, device_name, parent_testcase_store):
        self.all_testcases = dict()
        self.device_name = device_name

        self.property_id = int(json_filename.split(".")[0].split("_")[1].strip())

        self.testcases_with_mutation = list()
        self.testcases_without_mutation = list()

        self.mutation_messages_id = dict()

        self.property_done = False

        self.mutation_selection_count = dict()
        self.parent_testcase_store = parent_testcase_store

        with open(os.path.join('testcases_dump', json_filename), 'r') as fr:
            all_testcases_dict = json.load(fr)
            for testcase_dict in all_testcases_dict["testcases"]:
                self.all_testcases[testcase_dict["id"]] = TestCase(testcase_dict, self.property_id, self)
                if testcase_dict["has_mutation"]:
                    self.testcases_with_mutation.append(testcase_dict["id"])
                    if len(self.all_testcases[testcase_dict["id"]].mutating_messages) != 0:
                        for m in self.all_testcases[testcase_dict["id"]].mutating_messages:
                            self.mutation_messages_id.setdefault(m, []).append(
                                self.all_testcases[testcase_dict["id"]].testcase_id)
                else:
                    self.testcases_without_mutation.append(testcase_dict["id"])

            # print(json_filename)
            # pprint(self.mutation_messages_id)

        with open(os.path.join('considered_inputs_dir', 'popular_mutations.txt'), 'r') as fr:
            lines = fr.readlines()
            for line in lines:
                if ":" in line:
                    msg_combined = line.split("\n")[0].strip()
                    inp_msg, inp_fields = extract_message_and_fields(msg_combined)
                    self.mutation_selection_count[inp_msg] = 0

    def delete_testcase(self, testcase_id):
        if testcase_id in self.all_testcases.keys():
            if not self.all_testcases[testcase_id].has_mutation:
                if testcase_id in self.all_testcases.keys():
                    self.all_testcases[testcase_id].removed = True
                    del self.all_testcases[testcase_id]

    def delete_testcase_hard(self, testcase_id):
        if testcase_id in self.all_testcases.keys():
            self.all_testcases[testcase_id].removed = True
            if self.all_testcases[testcase_id].has_mutation:
                self.testcases_with_mutation = remove_from_list(self.testcases_with_mutation,
                                                                int(testcase_id))
            del self.all_testcases[testcase_id]

    def num_testcases(self):
        return len(self.all_testcases)

    def check_non_working_prefix(self, testcase_id):
        inp_list = self.all_testcases[testcase_id].input_symbol_sequence
        out_list = self.all_testcases[testcase_id].attacker_expectation_output_symbol_sequence
        if query_data_prefix(inp_list, out_list, self.device_name):
            self.delete_testcase_hard(testcase_id)
            return False

        return True

    def get_selection_order(self):
        m_list = list()
        for k, v in self.mutation_selection_count.items():
            m_list.append([k, v])

        m_list = sorted(m_list, key=lambda x: x[1])
        return [msg for msg, count in m_list]

    def select_testcase_idx(self, store_list):
        lowest_use_count = math.inf
        lowest_used = list()

        for i in range(len(store_list)):
            test_case = self.all_testcases[store_list[i]]
            testcase_count = (test_case.use_count + 2 * test_case.unresponsive_count -
                              test_case.deviation_used_count + test_case.mutation_used_count)
            if lowest_use_count > testcase_count:
                lowest_use_count = testcase_count

        for i in range(len(store_list)):
            test_case = self.all_testcases[store_list[i]]
            testcase_count = (test_case.use_count + 2 * test_case.unresponsive_count -
                              test_case.deviation_used_count + test_case.mutation_used_count)
            if testcase_count == lowest_use_count:
                lowest_used.append(store_list[i])

        random_idx = random.randint(0, len(lowest_used) - 1)

        return lowest_used[random_idx]

    def update_testcase_deviation_mutation_count(self):
        for testcase_id, test_case in self.all_testcases.items():
            dev_count = 0
            for state, input_symbols in self.parent_testcase_store.deviating_messages_per_state.items():
                if state in test_case.message_state_wise.keys():
                    messages_in_state_testcase = test_case.message_state_wise[state]
                    for msg in messages_in_state_testcase:
                        for msg_2 in input_symbols:
                            if msg_2 in msg:
                                dev_count += 1

            test_case.deviation_used_count = dev_count

        # total_mutation_usage_count = 0
        # for k, v in self.mutation_selection_count.items():
        #     total_mutation_usage_count += v

        for testcase_id, test_case in self.all_testcases.items():
            test_case.mutation_used_count = 0
            mutation_count = 0
            for mut_msg in list(set(test_case.mutating_messages)):
                if mut_msg in self.mutation_selection_count.keys():
                    mutation_count += self.mutation_selection_count[mut_msg]
            test_case.mutation_used_count += mutation_count

        total_mutation_usage_count = 0
        for k, v in self.mutation_selection_count.items():
            total_mutation_usage_count += v

        if total_mutation_usage_count != 0:
            for testcase_id, test_case in self.all_testcases.items():
                test_case.mutation_used_count /= total_mutation_usage_count

    def select_testcase_random(self):

        self.update_testcase_deviation_mutation_count()

        while True:
            if len(self.testcases_with_mutation) == 0 and len(self.testcases_without_mutation) == 0:
                self.property_done = True
                return None

            elif len(self.testcases_with_mutation) == 0:
                testcase_id = self.select_testcase_idx(self.testcases_without_mutation)
                self.testcases_without_mutation = remove_from_list(self.testcases_without_mutation,
                                                                   int(testcase_id))
            elif len(self.testcases_without_mutation) == 0:
                testcase_id = self.select_testcase_idx(self.testcases_with_mutation)
                for i in range(len(self.testcases_with_mutation)):
                    if self.testcases_with_mutation[i] == testcase_id:
                        self.all_testcases[self.testcases_with_mutation[i]].use_count += 1
            else:
                x = choose_with_probability(mutation_selection_rate * 100)
                if x or len(self.testcases_without_mutation) == 0:
                    testcase_id = self.select_testcase_idx(self.testcases_with_mutation)
                    for i in range(len(self.testcases_with_mutation)):
                        if self.testcases_with_mutation[i] == testcase_id:
                            self.all_testcases[self.testcases_with_mutation[i]].use_count += 1

                else:
                    testcase_id = self.select_testcase_idx(self.testcases_without_mutation)
                    self.testcases_without_mutation = remove_from_list(self.testcases_without_mutation,
                                                                       int(testcase_id))

            selected_testcase = self.all_testcases[testcase_id]
            if selected_testcase.removed:
                continue

            for i in range(len(selected_testcase.mutating_messages)):
                if selected_testcase.mutating_messages[i] in self.mutation_selection_count:
                    self.mutation_selection_count[selected_testcase.mutating_messages[i]] += 1
                else:
                    self.mutation_selection_count[selected_testcase.mutating_messages[i]] = 1

            # print("Selected TestCase ID {}".format(selected_testcase.testcase_id))
            break

        return selected_testcase


class TestCaseStore:
    def __init__(self, device_name):
        self.all_property_store_dict = dict()
        self.device_name = device_name
        self.all_property_probability = list()
        self.all_done = False

        self.deviating_messages_per_state = dict()
        self.qre_pool = dict()

        prefix_db_file_name = os.path.join('testcase_generator_db_dir',
                                           'non_working_prefixes_{}.db'.format(device_name))
        if os.path.exists(prefix_db_file_name):
            os.remove(prefix_db_file_name)

        mutation_db_file_name = os.path.join('testcase_generator_db_dir',
                                             'working_mutations.db'.format(device_name))
        if os.path.exists(mutation_db_file_name):
            os.remove(mutation_db_file_name)

        create_db_non_working_prefixes(device_name)
        create_table_mutation_info()
        populate_popular_mutations()

        testcase_files = os.listdir('testcases_dump')

        with open(os.path.join('qre_expressions', 'fuzzing_p.txt'), 'r') as fr:
            lines = fr.readlines()
            p_idx = 0
            for line in lines:
                if "##" in line:
                    qre_exp = line.split("##")[0].strip()
                    prob = float(line.split("##")[1].strip())
                    self.qre_pool[p_idx] = qre_exp
                    self.all_property_probability.append([p_idx, prob])
                    p_idx += 1
            # print(self.all_property_probability)

        for testcase_file in testcase_files:
            if "fuzzing" in testcase_file:
                property_store = PropertyStore(testcase_file, self.device_name, self)
                property_idx = int(testcase_file.split(".")[0].split("_")[1].strip())
                self.all_property_store_dict[property_idx] = property_store

    def check_property_done_deviation(self, concrete_testcase, deviation_input):
        done_properties_idx = list_violations(concrete_testcase, self.qre_pool, deviation_input)
        print("Done Properties Idx : {}\n".format(done_properties_idx))
        for property_idx in done_properties_idx:
            if property_idx in self.all_property_store_dict.keys():
                self.all_property_store_dict[property_idx].property_done = True
                del self.all_property_store_dict[property_idx]

    def make_property_done(self, property_idx):
        if property_idx in self.all_property_store_dict.keys():
            self.all_property_store_dict[property_idx].property_done = True
            del self.all_property_store_dict[property_idx]

    def select_property(self):
        done_properties = list()
        for k, v in self.all_property_store_dict.items():
            if (v.property_done
                    or (len(v.testcases_with_mutation) == 0 and len(v.testcases_without_mutation) == 0)):
                v.property_done = True
                done_properties.append(k)

        for dp in done_properties:
            del self.all_property_store_dict[dp]

        all_property_probability_new = list()
        for i in range(len(self.all_property_probability)):
            if self.all_property_probability[i][0] in self.all_property_store_dict.keys():
                all_property_probability_new.append(self.all_property_probability[i])
        self.all_property_probability = all_property_probability_new

        if len(self.all_property_probability) == 0:
            self.all_done = True
            return None

        elements = list()
        probabilities = list()
        for i in range(len(self.all_property_probability)):
            probabilities.append(self.all_property_probability[i][1])
            elements.append(self.all_property_probability[i][0])
        chosen_property = choose_with_distribution(elements, probabilities)
        return chosen_property

    def select_testcase(self):
        select_property_to_test = self.select_property()
        if select_property_to_test is None:
            self.all_done = True
            return None
        selected_property_dict = self.all_property_store_dict[select_property_to_test]

        selected_testcase = selected_property_dict.select_testcase_random()

        return selected_testcase

    def delete_testcase(self, property_id, testcase_id):
        if property_id in self.all_property_store_dict.keys():
            prop_store = self.all_property_store_dict[property_id]
            prop_store.delete_testcase(testcase_id)

    def delete_testcase_hard(self, property_id, testcase_id):
        if property_id in self.all_property_store_dict.keys():
            prop_store = self.all_property_store_dict[property_id]
            prop_store.delete_testcase_hard(testcase_id)

    #
    # ts = TestCaseStore("uesim")
    # for i in range(1000):
    #     s = ts.select_testcase()
    #     print(s.input_symbol_sequence)

    '''
        def get_responsiveness_test(self, final_reference_state):
            if final_reference_state.startswith("s0"):
                return "scan_req:", "scan_resp:"
            elif final_reference_state.startswith("s1"):
                return "scan_req:", "scan_resp:"

            elif final_reference_state.startswith("s2"):
                return "pair_req:oob == 0 & no_sc == 0 & key == 0 & llid == 0", \
                       "pair_resp:"
            elif final_reference_state.startswith("s3"):
                return "scan_req:", "scan_resp:"
            elif final_reference_state.startswith("s4"):
                return "key_exchange:invalid == 0 & ll_length == 0", "public_key_response_sm_confirm:"
            elif final_reference_state.startswith("s5"):
                return "sm_random_send:", "sm_random_received:"
            elif final_reference_state.startswith("s6"):
                return "dh_check:invalid == 0", "dh_key_response:"
            elif final_reference_state.startswith("s7"):
                return "mtu_req:ll_length == 0 & llid == 0", "mtu_resp:"
            elif final_reference_state.startswith("s8"):
                return "scan_req:", "scan_resp:"
            elif final_reference_state.startswith("s9"):
                return "scan_req:", "scan_resp:"
            elif final_reference_state.startswith("s10"):
                return "scan_req:", "scan_resp:"
            elif final_reference_state.startswith("s11"):
                return "scan_req:", "scan_resp:"
            elif final_reference_state.startswith("s12"):
                return "scan_req:", "scan_resp:"
            elif final_reference_state.startswith("s13"):
                return "scan_req:", "scan_resp:"
            elif final_reference_state.startswith("s14"):
                return "scan_req:", "scan_resp:"



    valid_messages = [
            "version_req: ll_length == 0 & llid == 0",
            "con_req:interval == 0 & timeout == 0 & ll_length == 0 & channel_map == 0",
            "pair_req:oob == 0 & no_sc == 0 & key == 0 & llid == 0",
            "length_req:ll_length == 0",
            "start_enc_resp:plain == 0",
            "enc_pause_req:plain == 0",
            "enc_pause_resp:plain == 0",
            "pair_confirm:wrong_value == 0",
            "dh_check:invalid == 0",
            "key_exchange:invalid == 0 & ll_length == 0",
            "pair_confirm:wrong_value == 0"
        ]


            if tok.check_token_match("::{}".format(final_inp_msg), "::$:") and final_inp_msg not in valid_messages:
                return final_inp_msg, mutation_original_msg




    '''
