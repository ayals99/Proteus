import copy
import json
import os
import random
from typing import List

from database_handler import create_table, query_data, insert_data, delete_table

random.seed(1)

from condition_checker import is_subset_condition

corresponding_valid_outputs = dict()

with open("valid_output_dir/corresponding_valid_output.txt", "r") as fr:
    lines = fr.readlines()
    for line in lines:
        if "/" in line:
            key, value = line.split("\n")[0].split("/")
            corresponding_valid_outputs[key.strip()] = value.strip()


def check_condition_match(to_be_checked: str, checker_condition: str):
    tbc_state, tbc_varexp, tbc_msg, tbc_field = extract_info_from_transition(to_be_checked)
    c_state, c_varexp, c_msg, c_field = extract_info_from_transition(checker_condition)

    if not c_state.startswith("^"):
        c1 = tbc_state == c_state or c_state == ""
    else:
        cn_state = c_state.split("^")[1].strip()
        c1 = tbc_state != cn_state

    if not c_varexp.startswith("^"):
        c2 = tbc_varexp == "$" or c_varexp == "$" or is_subset_condition(tbc_varexp, c_varexp)
    else:
        cn_varexp = c_varexp.split("^")[1].strip()
        c2 = tbc_varexp == "$" or cn_varexp == "$" or (not is_subset_condition(tbc_varexp, cn_varexp))

    if not c_msg.startswith("^"):
        if c_msg.startswith("V"):
            c3 = not (tbc_msg == "null_action") and ("reject" not in tbc_msg) and ("failure" not in tbc_msg)
        else:
            c3 = tbc_msg == c_msg or c_msg == "$"
    else:
        cn_msg = c_msg.split("^")[1].strip()
        c3 = tbc_msg != cn_msg or cn_msg == "$"

    if not c_field.startswith("^"):
        c4 = is_subset_condition(tbc_field, c_field)
    else:
        cn_field = c_field.split("^")[1].strip()
        c4 = not is_subset_condition(tbc_field, cn_field)

    if c1 & c2 & c3 & c4:
        return True

    return False


def check_symbol_match(tbc_symbol, c_symbol, corresponding_input_symbol=None):
    if ":" not in tbc_symbol:
        tbc_symbol = tbc_symbol + ":"

    if ":" not in c_symbol:
        c_symbol = c_symbol + ":"

    _, _, tbc_msg, tbc_field = extract_info_from_transition("::{}".format(tbc_symbol))
    _, _, c_msg, c_field = extract_info_from_transition("::{}".format(c_symbol))

    if corresponding_input_symbol is not None:
        if c_msg == "V":
            for k, v in corresponding_valid_outputs.items():
                if check_symbol_match(corresponding_input_symbol, k):
                    c_msg = v.split(":")[0].strip()
                    c_field = v.split(":")[1].strip()

    if not c_msg.startswith("^"):
        c3 = tbc_msg == c_msg or c_msg == "$"
    else:
        cn_msg = c_msg.split("^")[1].strip()
        c3 = tbc_msg != cn_msg or cn_msg == "$"

    if not c_field.startswith("^"):
        c4 = is_subset_condition(tbc_field, c_field)
    else:
        cn_field = c_field.split("^")[1].strip()
        c4 = not is_subset_condition(tbc_field, cn_field)

    if c3 & c4:
        return True

    return False


def check_combined_state_match(tbc_combined_state, c_combined_state):
    tbc_state = tbc_combined_state.split(":")[0].strip()
    tbc_varexp = tbc_combined_state.split(":")[1].strip()

    c_state = c_combined_state.split(":")[0].strip()
    c_varexp = c_combined_state.split(":")[1].strip()

    if not c_state.startswith("^"):
        c1 = tbc_state == c_state
    else:
        cn_state = c_state.split("^")[1].strip()
        c1 = tbc_state != cn_state

    if not c_varexp.startswith("^"):
        c2 = tbc_varexp == "$" or c_varexp == "$" or is_subset_condition(tbc_varexp, c_varexp)
    else:
        cn_varexp = c_varexp.split("^")[1].strip()
        c2 = tbc_varexp == "$" or cn_varexp == "$" or (not is_subset_condition(tbc_varexp, cn_varexp))

    if c1 & c2:
        return True

    return False


def extract_info_from_transition(tx_expression):
    # print(tx_expression)
    c_state, rem = tx_expression.split(":", 1)
    c_state = str(c_state).strip()

    c_varexp, rem_symbol = str(rem).split(":", 1)
    c_varexp = str(c_varexp).strip()

    if str(rem_symbol).startswith("mutation("):
        c_msg = str(rem_symbol).split("):")[0]
        c_msg = c_msg.strip() + ")"

        c_field = str(rem_symbol).split("):")[1]
        c_field = c_field.strip()
    else:
        c_msg = str(rem_symbol).split(":")[0].strip()
        c_field = str(rem_symbol).split(":")[1].strip()

    return c_state, c_varexp, c_msg, c_field


def extract_combined_state(tx_expression):
    c_state = tx_expression.split(":")[0].strip()
    c_varexp = tx_expression.split(":")[1].strip()

    return c_state, c_varexp


def extract_message_and_fields(combined_msg):
    if ":" not in combined_msg:
        combined_msg = combined_msg + ":"

    _, _, c_msg, c_field = extract_info_from_transition("::{}".format(combined_msg))

    return c_msg, c_field


def concat_exp(old_exp, new_exp):
    if old_exp == "":
        return new_exp
    if new_exp == "":
        return old_exp

    if old_exp == "$" or new_exp == "$":
        return "$"

    all_exp_vars = dict()

    if "&" not in str(old_exp):
        if "==" in old_exp:
            all_exp_vars[str(old_exp).split("==")[0].strip()] = str(old_exp).split("==")[1].strip()
    else:
        all_var = str(old_exp).split("&")
        for var_val in all_var:
            if "==" in var_val:
                all_exp_vars[var_val.split("==")[0].strip()] = str(var_val).split("==")[1].strip()

    if "&" not in str(new_exp):
        if "==" in old_exp:
            all_exp_vars[str(new_exp).split("==")[0].strip()] = str(new_exp).split("==")[1].strip()
    else:
        all_var = str(new_exp).split("&")
        for var_val in all_var:
            if "==" in var_val:
                all_exp_vars[var_val.split("==")[0].strip()] = str(var_val).split("==")[1].strip()

    final_exp = ""
    for k, v in sorted(all_exp_vars.items(), key=lambda item: item[0]):
        if final_exp == "":
            final_exp = k + " == " + v
        else:
            final_exp += " & " + k + " == " + v

    return final_exp


class BaseState:
    def __init__(self, name):
        self.state_name = name
        self.outgoing_transitions_dict = dict()
        # expression -- emm_registered : a = 1 & b = 2 : msg : field = 1 & field = 2

    def add_outgoing_transition(self,
                                input_condition: str,
                                output_expression: str):
        self.outgoing_transitions_dict[input_condition] = output_expression

    def get_outgoing_transition_output(self, input_test_condition):
        matched_input_conditions_list = []
        input_state, input_varexp, input_msg, input_field = extract_info_from_transition(input_test_condition)
        for known_input_conditions in self.outgoing_transitions_dict.keys():
            if check_condition_match(input_test_condition, known_input_conditions):
                matched_input_conditions_list.append(known_input_conditions)

        if len(matched_input_conditions_list) == 0:
            return input_state + ":" + input_varexp + ":" + "null_action" + ":"

        matched_final_condition = matched_input_conditions_list[0]
        for matched_condition in matched_input_conditions_list:
            if check_condition_match(matched_condition, matched_final_condition):
                matched_final_condition = matched_condition

        matched_output_condition = self.outgoing_transitions_dict[matched_final_condition]
        output_state, output_varexp, output_msg, output_fields = extract_info_from_transition(matched_output_condition)

        return output_state + ":" + concat_exp(input_varexp, output_varexp) + ":" + output_msg + ":" + output_fields

    def get_outgoing_input_symbols(self):
        all_inp_symbols = []
        for k, v in self.outgoing_transitions_dict.items():
            inp_state, inp_varexp, input_msg, input_field = extract_info_from_transition(k)
            all_inp_symbols.append(input_msg + ":" + input_field)
        return list(set(all_inp_symbols))

    def get_outgoing_combined_states(self):
        all_outgoing_combined_states = []
        for k, v in self.outgoing_transitions_dict.items():
            out_state, out_varexp, _, _ = extract_info_from_transition(v)
            all_outgoing_combined_states.append(out_state + ":" + out_varexp)

        return list(set(all_outgoing_combined_states))


def refine_symbol(symbol):
    msg, fields = extract_message_and_fields(symbol)
    return str(msg).strip() + ":" + str(fields).strip()


def refine_condition(tx_expression):
    if "&" not in tx_expression:
        return tx_expression
    input_state, input_varexp, input_msg, input_fields = extract_info_from_transition(tx_expression)
    input_state = str(input_state).strip()
    input_varexp = str(input_varexp).strip()
    input_msg = str(input_msg).strip()
    input_fields = str(input_fields).strip()

    all_exp_vars = dict()

    all_var = str(input_varexp).split("&")
    for var_val in all_var:
        if "==" in var_val:
            all_exp_vars[var_val.split("==")[0].strip()] = str(var_val).split("==")[1].strip()

    final_varexp = ""
    for k, v in sorted(all_exp_vars.items(), key=lambda item: item[0]):
        if final_varexp == "":
            final_varexp = k + " == " + v
        else:
            final_varexp += " & " + k + " == " + v

    return input_state + ":" + final_varexp + ":" + input_msg + ":" + input_fields


def get_states_and_tx(filename):
    states = []
    transitions = []

    with open(filename, "r") as f:
        rfsm_file_lines = f.readlines()
        for i in range(len(rfsm_file_lines)):
            if 'node' in rfsm_file_lines[i]:
                strg = rfsm_file_lines[i].split(']')[1].split(';')[0].strip()
                states.append(strg.strip())

            elif '//' in rfsm_file_lines[i] and rfsm_file_lines[i].startswith('//'):
                continue

            elif '->' in rfsm_file_lines[i]:
                transition = ''
                strg = rfsm_file_lines[i].split('->')
                start_state = strg[0].strip()
                strg = strg[1].split('[')
                end_state = strg[0].strip()  # str[1]: label = "nas_requested_con_establishment | paging_tmsi /

                if start_state not in states:
                    print('ERROR: start_state is not in the list of states')
                    return

                if end_state not in states:
                    print('ERROR: end_state is not in the list of states')
                    return

                strg = strg[1].split('"')
                if len(strg) == 3:  # transition is written in one line
                    transition = strg[1]

                values = transition.split('/')
                # print 'values = ', values

                input_condition = values[0].strip()
                output_condition = values[1].strip()

                tx_input = refine_condition(start_state + ":" + input_condition)
                tx_output = refine_condition(end_state + ":" + output_condition)

                transitions.append([start_state, tx_input, tx_output, end_state])

    return states, transitions, states[0]


def get_template_qres(filename):
    with open(filename, 'r') as fr:
        lines = fr.readlines()
        temporal_qres = []
        for qre_line in lines:
            temporal_qres.append(qre_line.split("\n")[0].strip())
    return temporal_qres


class Token(object):
    def __init__(self, token_str: str):
        self.inp_tx = []
        self.out_tx = []

        if token_str.startswith("^"):
            if "*" in token_str:
                self.token_type = 4
            else:
                self.token_type = 3
        else:
            if "*" in token_str:
                self.token_type = 2
            else:
                self.token_type = 1

        if '[' in token_str:
            tokens_in_brace = token_str.split('[')[1].split(']')[0].strip()
            if "|" in tokens_in_brace:
                tokens = tokens_in_brace.split("|")
                for token in tokens:
                    if "<" in token:
                        inp = token.split("<")[1].split(",")[0].strip()
                        out = token.split(",")[1].split(">")[0].strip()
                        self.inp_tx.append(inp)
                        self.out_tx.append(out)
            else:
                if "<" in tokens_in_brace:
                    inp = tokens_in_brace.split("<")[1].split(",")[0].strip()
                    out = tokens_in_brace.split(",")[1].split(">")[0].strip()
                    self.inp_tx.append(inp)
                    self.out_tx.append(out)
        else:
            if "<" in token_str:
                inp = token_str.split("<")[1].split(",")[0].strip()
                out = token_str.split(",")[1].split(">")[0].strip()
                self.inp_tx.append(inp)
                self.out_tx.append(out)

        self.token_str = token_str

    def check_token_match(self, tbc_condition_input, tbc_condition_output):

        inp_symbol_match = []
        out_symbol_match = []

        if self.token_type == 1 or self.token_type == 2:

            for i in range(len(self.inp_tx)):
                _, _, token_inp_msg, token_inp_fields = extract_info_from_transition(
                    self.inp_tx[i]
                )
                _, _, token_out_msg, token_out_fields = extract_info_from_transition(
                    self.out_tx[i]
                )

                _, _, tbc_condition_msg, _ = extract_info_from_transition(tbc_condition_input)

                if check_symbol_match(tbc_condition_msg + ":", token_inp_msg + ":"):
                    inp_symbol_match.append(token_inp_msg + ":" + token_inp_fields)
                    out_symbol_match.append(token_out_msg + ":" + token_out_fields)

            for i in range(len(self.inp_tx)):

                # print("Forward Input {} Forward Output {}\n".format(self.inp_tx[i], self.out_tx[i]))
                if (check_condition_match(tbc_condition_input, self.inp_tx[i])
                        and check_condition_match(tbc_condition_output, self.out_tx[i])):
                    # print("Condition match passed {} {}\n".format(tbc_condition_output, self.out_tx[i]))
                    return True, inp_symbol_match, out_symbol_match
            return False, inp_symbol_match, out_symbol_match

        else:
            if self.token_type == 3:
                matched_condition = True
                for i in range(len(self.inp_tx)):
                    _, _, token_inp_msg, token_inp_fields = extract_info_from_transition(
                        self.inp_tx[i]
                    )
                    _, _, token_out_msg, token_out_fields = extract_info_from_transition(
                        self.out_tx[i]
                    )

                    _, _, tbc_condition_msg, _ = extract_info_from_transition(tbc_condition_input)

                    if check_symbol_match(tbc_condition_msg + ":", token_inp_msg + ":"):
                        inp_symbol_match.append(token_inp_msg + ":" + token_inp_fields)
                        out_symbol_match.append(token_out_msg + ":" + token_out_fields)

                    t_inp_state, t_inp_var, t_inp_msg, t_inp_fields = extract_info_from_transition(self.inp_tx[i])
                    t_out_state, t_out_var, t_out_msg, t_out_fields = extract_info_from_transition(self.out_tx[i])

                    inp_cond_match = check_condition_match(tbc_condition_input, self.inp_tx[i])
                    out_cond_match = check_condition_match(tbc_condition_output, self.out_tx[i])

                    if "$" in t_inp_msg:
                        if not out_cond_match:
                            continue
                        else:
                            matched_condition = False
                            break

                    if "$" in t_out_msg:
                        if not inp_cond_match:
                            continue
                        else:
                            matched_condition = False
                            break

                    if (inp_cond_match
                            and not out_cond_match):
                        continue

                if matched_condition:
                    return True, inp_symbol_match, out_symbol_match
                return False, inp_symbol_match, out_symbol_match
            else:
                for i in range(len(self.inp_tx)):
                    _, _, token_inp_msg, token_inp_fields = extract_info_from_transition(
                        self.inp_tx[i]
                    )
                    _, _, token_out_msg, token_out_fields = extract_info_from_transition(
                        self.out_tx[i]
                    )

                    _, _, tbc_condition_msg, _ = extract_info_from_transition(tbc_condition_input)

                    if check_symbol_match(tbc_condition_msg + ":", token_inp_msg + ":"):
                        inp_symbol_match.append(token_inp_msg + ":" + token_inp_fields)
                        out_symbol_match.append(token_out_msg + ":" + token_out_fields)

                    inp_check = check_condition_match(tbc_condition_input, self.inp_tx[i])
                    out_check = check_condition_match(tbc_condition_output, self.out_tx[i])

                    if inp_check and out_check:
                        return False, inp_symbol_match, out_symbol_match

                    # print("Returning True\n")

                return True, inp_symbol_match, out_symbol_match

    def check_token_satisfy_concrete_trace(self, concrete_input_symbol, concrete_output_symbol):

        if self.token_type == 1 or self.token_type == 2:

            for i in range(len(self.inp_tx)):
                _, _, token_inp_msg, token_inp_fields = extract_info_from_transition(
                    self.inp_tx[i]
                )
                _, _, token_out_msg, token_out_fields = extract_info_from_transition(
                    self.out_tx[i]
                )

                if (check_symbol_match(concrete_input_symbol, token_inp_msg + ":" + token_inp_fields)
                        and check_symbol_match(concrete_output_symbol, token_out_msg + ":" + token_out_fields)):
                    return True

            return False

        else:
            if self.token_type == 3:
                matched_condition = True
                for i in range(len(self.inp_tx)):
                    _, _, token_inp_msg, token_inp_fields = extract_info_from_transition(
                        self.inp_tx[i]
                    )
                    _, _, token_out_msg, token_out_fields = extract_info_from_transition(
                        self.out_tx[i]
                    )

                    t_inp_state, t_inp_var, t_inp_msg, t_inp_fields = extract_info_from_transition(self.inp_tx[i])
                    t_out_state, t_out_var, t_out_msg, t_out_fields = extract_info_from_transition(self.out_tx[i])

                    inp_cond_match = check_symbol_match(concrete_input_symbol, token_inp_msg + ":" + token_inp_fields)
                    out_cond_match = check_symbol_match(concrete_output_symbol, token_out_msg + ":" + token_out_fields)

                    if "$" in t_inp_msg:
                        if not out_cond_match:
                            continue
                        else:
                            matched_condition = False
                            break

                    if "$" in t_out_msg:
                        if not inp_cond_match:
                            continue
                        else:
                            matched_condition = False
                            break

                    if (inp_cond_match
                            and not out_cond_match):
                        continue

                if matched_condition:
                    return True
                return False
            else:
                for i in range(len(self.inp_tx)):
                    _, _, token_inp_msg, token_inp_fields = extract_info_from_transition(
                        self.inp_tx[i]
                    )
                    _, _, token_out_msg, token_out_fields = extract_info_from_transition(
                        self.out_tx[i]
                    )

                    inp_check = check_symbol_match(concrete_input_symbol, token_inp_msg + ":" + token_inp_fields)
                    out_check = check_symbol_match(concrete_output_symbol, token_out_msg + ":" + token_out_fields)

                    if inp_check and out_check:
                        return False

                return True


def parse_qre_exp(qre_exp: str) -> List[Token]:
    token_list: List[Token] = list()
    qre_tokens = qre_exp.split(";")
    for qre_tok in qre_tokens:
        qre_tok = qre_tok.strip()
        if "^" in qre_tok or "*" in qre_tok or "<" in qre_tok:
            new_tok = Token(qre_tok)
            token_list.append(new_tok)
    return token_list


def check_output_sequence_match(o_seq_old, o_seq_new):
    if len(o_seq_old) != len(o_seq_new):
        return False
    for i in range(len(o_seq_old)):
        if not check_symbol_match(o_seq_new[i], o_seq_old[i]):
            return False
    return True


class FSM(object):
    def __init__(self, states, start_state, transitions=None):  # transitions = (curr_state,in_cond,out_cond,next_state)
        self.testcases = list()
        self.states_dict = dict()

        self.start_state_name = start_state
        self.start_varexp_value = ""

        self.template_qre = ""
        self.token_list: List[Token] = list()

        self.current_state = self.start_state_name
        self.current_varexp_value = self.start_varexp_value

        self.mutation_list = dict()

        self.next_state_mutations = dict()
        self.statewise_prohibited_mutation_messages = dict()

        for state_name in states:
            if state_name not in list(self.states_dict.keys()):
                self.states_dict[str(state_name).strip()] = BaseState(state_name)

        for transition in transitions:
            curr_state_name = str(transition[0]).strip()
            input_condition = str(transition[1]).strip()
            output_condition = str(transition[2]).strip()
            next_state_name = str(transition[3]).strip()

            if curr_state_name not in list(self.states_dict.keys()):
                print("Error : curr_state {} Not Found".format(curr_state_name))

            if next_state_name not in list(self.states_dict.keys()):
                print("Error : next_state {} Not Found".format(next_state_name))

            self.states_dict[curr_state_name].add_outgoing_transition(input_condition, output_condition)

    def retrieve_next_state_mutations(self):

        for st in self.states_dict.keys():
            self.next_state_mutations[st] = []

        with open(os.path.join('considered_inputs_dir', 'next_state_mutations.txt'), 'r') as fr_nsm:
            lines_ = fr_nsm.readlines()
            for line_ in lines_:
                line_ = line_.split('\n')[0].strip()
                if 's' in line_:
                    states = line_.split(" ")
                    target_state = None
                    for state in states:
                        if 's' in state:
                            if target_state is None and state in self.states_dict.keys():
                                target_state = state
                                continue
                            elif target_state is not None and state in self.states_dict.keys():
                                self.next_state_mutations.setdefault(target_state, []).append(state)

        print(self.next_state_mutations)

    def retrieve_state_wise_prohibited_mutation_messages(self):

        for st in self.states_dict.keys():
            self.statewise_prohibited_mutation_messages[st] = []

        with open(os.path.join('considered_inputs_dir', 'statewise_prohibited_messages.txt'), 'r') as fr_sm:
            lines_ = fr_sm.readlines()
            for line_ in lines_:
                line_ = line_.split('\n')[0].strip()
                if 's' in line_:
                    st, _, msg, fields = extract_info_from_transition(line_)
                    if st in self.states_dict.keys():
                        self.statewise_prohibited_mutation_messages.setdefault(st, []).append(msg + ":" + fields)

        print(self.statewise_prohibited_mutation_messages)

    def check_in_mutation_list(self, combined_state, mutations_rem, tokens_rem, length_rem):
        key = str(combined_state) + "-" + str(mutations_rem) + "-" + str(tokens_rem) + "-" + str(length_rem)

        if key in self.mutation_list.keys():
            return True, self.mutation_list[key]
        else:
            return False, [False, [[], []]]

    def add_to_mutation_list(self, combined_state, exists_sequence, sequences, mutations_rem, tokens_rem, length_rem):
        key = str(combined_state) + "-" + str(mutations_rem) + "-" + str(tokens_rem) + "-" + str(length_rem)

        if key in self.mutation_list.keys():
            if exists_sequence and not self.mutation_list[key][0] or (exists_sequence and self.mutation_list[key][0]
                                                                      and len(self.mutation_list[key][1]) == 0):
                self.mutation_list[key] = [exists_sequence, self.clear_duplicates(sequences)]
            elif exists_sequence and self.mutation_list[key][0]:
                self.mutation_list[key] = [exists_sequence,
                                           self.clear_duplicates(sequences + self.mutation_list[key][1])]
        else:
            if len(sequences) == 0:
                self.mutation_list[key] = [exists_sequence, sequences]
            else:
                self.mutation_list[key] = [exists_sequence, self.clear_duplicates(sequences)]

    def clear_duplicates(self, sequence):
        new_seq = []
        for i in range(len(sequence)):
            add = False
            if len(new_seq) == 0:
                add = True
            for j in range(len(new_seq)):
                if len(new_seq[j][0]) == len(sequence[i][0]):
                    for k in range(len(new_seq[j][0])):
                        if new_seq[j][0][k] != sequence[i][0][k]:
                            add = True
                            break
                else:
                    add = True
                if len(new_seq[j][1]) == len(sequence[i][1]):
                    for k in range(len(new_seq[j][1])):
                        if new_seq[j][1][k] != sequence[i][1][k]:
                            add = True
                            break
                else:
                    add = True
            if add:
                new_seq.append(sequence[i])

        return new_seq

    def clear_mutation_list(self):
        self.mutation_list.clear()

    def set_state(self, state_name):
        self.current_state = state_name

    def set_varexp_value(self, varexp):
        self.current_varexp_value = varexp

    def make_transition(self, input_symbol):  # input_symbol -- input_msg:input_fields
        if input_symbol == 'RESET':
            self.set_state(self.start_state_name)
            self.set_varexp_value(self.start_varexp_value)
            return 'null_action' + ":"

        inp_sym = str(input_symbol).replace("FUZZ", "0")
        inp_tx_expression = self.current_state + ":" + self.current_varexp_value + ":" + inp_sym

        current_state = self.states_dict[self.current_state]
        out_tx_expression = current_state.get_outgoing_transition_output(inp_tx_expression)
        out_state, out_varexp, out_msg, out_fields = extract_info_from_transition(out_tx_expression)

        self.set_state(out_state)
        self.set_varexp_value(out_varexp)
        return out_msg + ":" + out_fields

    def generate_fsm_output_sequence_total(self, input_sequence):
        self.make_transition('RESET')
        output_sequence = []
        input_transitions = []

        for i in range(len(input_sequence)):
            input_symbol = input_sequence[i]
            input_combined_state = self.current_state + ":" + self.current_varexp_value
            input_transitions.append(input_combined_state + ':' + input_symbol)

            out_sym = self.make_transition(input_sequence[i])
            output_sequence.append(out_sym)

        final_state = self.current_state + ":" + self.current_varexp_value
        return input_transitions, output_sequence, final_state

    def get_all_input_symbols(self):
        all_input_symbols = []
        for k, v in self.states_dict.items():
            all_input_symbols = all_input_symbols + self.states_dict[k].get_outgoing_input_symbols()
        all_input_symbols = list(set(all_input_symbols))
        return all_input_symbols

    def get_all_combined_states(self):
        all_combined_states = []
        for node_state_name in self.states_dict.keys():
            node_state = self.states_dict[node_state_name]
            for input_tx, output_tx in node_state.outgoing_transitions_dict.items():
                inp_state, inp_varexp, inp_msg, inp_fields = extract_info_from_transition(input_tx)
                out_state, out_varexp, out_msg, out_fields = extract_info_from_transition(output_tx)
                all_combined_states.append(inp_state + ":" + inp_varexp)
                all_combined_states.append(out_state + ":" + concat_exp(inp_varexp, out_varexp))

        all_combined_states = list(set(all_combined_states))
        return all_combined_states

    def get_all_normal_states(self):
        all_states = []
        for node_state_name in self.states_dict.keys():
            all_states.append(node_state_name)
        return list(set(all_states))

    # TODO: Update Caller Side
    def get_responsive_io(self, current_combined_state_name):
        current_state_name, current_varexp = \
            str(current_combined_state_name).split(":")[0], str(current_combined_state_name).split(":")[1]
        state = self.states_dict[current_state_name]
        responsive_ios = dict()
        for inp_tx, out_tx in state.outgoing_transitions_dict.items():
            if str(inp_tx).startswith(current_state_name + ":" + current_varexp):
                in_state, in_varexp, in_msg, in_fields = extract_info_from_transition(inp_tx)
                out_state, out_varexp, out_msg, out_fields = extract_info_from_transition(out_tx)
                if out_msg != "null_action":
                    responsive_ios[in_msg + ":" + in_fields] = out_msg + ":" + out_fields
        return responsive_ios

    def count_token_remaining(self, token_list: List[Token]):
        total_tokens = 0
        for tok in token_list:
            if tok.token_type == 1 or tok.token_type == 3:
                total_tokens += 1
        return total_tokens

    def get_next_fwd_allowed_tokens(self, token_list: List[Token], token_rem: int):
        forward_idx = -1
        allowed_idx = -1
        rem_count = 0
        for i in range(len(token_list) - 1, -1, -1):
            if token_list[i].token_type == 1 or token_list[i].token_type == 3:
                rem_count += 1
                if rem_count == token_rem:
                    forward_idx = i
                    if (i - 1 >= 0
                            and token_list[i - 1].token_type == 2 or token_list[i - 1].token_type == 4):
                        allowed_idx = i - 1

        fwd_token = None
        if forward_idx >= 0:
            fwd_token = token_list[forward_idx]

        allowed_token = None
        if allowed_idx >= 0:
            allowed_token = token_list[allowed_idx]

        return fwd_token, allowed_token

    def get_forward_transitions(self, node_combined_state_name: str, forward_token: Token,
                                last_token=False):
        forward_transitions = dict()
        mutation_count = dict()

        node_state_name, node_varexp = extract_combined_state(node_combined_state_name)

        node_state = self.states_dict[node_state_name]
        for inp_tx, out_tx in node_state.outgoing_transitions_dict.items():
            if check_combined_state_match(node_combined_state_name, inp_tx):
                inp_state, inp_varexp, inp_msg, inp_fields = extract_info_from_transition(inp_tx)
                new_tx = node_combined_state_name + ":" + inp_msg + ":" + inp_fields

                token_match, inp_symbol_match, out_symbol_match = forward_token.check_token_match(new_tx, out_tx)

                if token_match:
                    out_state, out_varexp, out_msg, out_fields = extract_info_from_transition(out_tx)
                    new_out_tx = \
                        out_state + ":" + concat_exp(node_varexp, out_varexp) + ":" + out_msg + ":" + out_fields

                    forward_transitions.setdefault(new_tx, []).append(new_out_tx)
                    mutation_count.setdefault(new_tx, []).append(0)

                    new_state_count = 0
                    for possible_out_state_combined in node_state.get_outgoing_combined_states():
                        if last_token and new_state_count > 0:
                            break

                        new_out_tx_new_state = possible_out_state_combined + ":" + out_msg + ":" + out_fields

                        forward_transitions.setdefault(new_tx, []).append(new_out_tx_new_state)
                        mutation_count.setdefault(new_tx, []).append(1)

                        new_state_count += 1

                elif not token_match and len(inp_symbol_match) != 0:
                    mutated_inp_symbol = inp_symbol_match[0]
                    mutated_out_symbol = out_symbol_match[0]

                    mutated_tx = node_combined_state_name + ":" + mutated_inp_symbol

                    out_state, out_varexp, out_msg, out_fields = extract_info_from_transition(out_tx)
                    mutated_out_tx = out_state + ":" + concat_exp(node_varexp, out_varexp) + ":" + mutated_out_symbol

                    forward_transitions.setdefault(mutated_tx, []).append(mutated_out_tx)
                    mutation_count.setdefault(mutated_tx, []).append(1)

                    new_state_count = 0
                    for possible_out_state_combined in node_state.get_outgoing_combined_states():

                        if last_token and new_state_count > 0:
                            break

                        mutated_out_tx_new_state = possible_out_state_combined + ":" + mutated_out_symbol

                        forward_transitions.setdefault(mutated_tx, []).append(mutated_out_tx_new_state)
                        mutation_count.setdefault(mutated_tx, []).append(2)

                        new_state_count += 1

        return forward_transitions, mutation_count

    def get_allowed_transitions(self, node_combined_state_name: str, constraint_token: Token):
        allowed_transitions = dict()
        mutation_count = dict()

        node_state_name, node_varexp = extract_combined_state(node_combined_state_name)
        node_state = self.states_dict[node_state_name]

        for inp_tx, out_tx in node_state.outgoing_transitions_dict.items():
            inp_state, inp_var, inp_msg, inp_fields = extract_info_from_transition(inp_tx)
            inp_symbol = inp_msg + ":" + inp_fields
            inp_combined_state = inp_state + ":" + inp_var

            if check_combined_state_match(node_combined_state_name, inp_combined_state) \
                    and ("enable_s1" not in inp_msg and "reset" not in inp_msg):
                new_tx = node_combined_state_name + ":" + inp_msg + ":" + inp_fields
                out_state_name, out_varexp, out_msg, out_fields = \
                    extract_info_from_transition(out_tx)
                concatenated_varexp = concat_exp(node_varexp, out_varexp)

                if out_state_name != node_state_name:
                    if constraint_token.check_token_match(new_tx, out_tx)[0]:
                        new_out_tx = \
                            out_state_name + ":" + concatenated_varexp + ":" + out_msg + ":" + out_fields

                        allowed_transitions.setdefault(new_tx, []).append(new_out_tx)
                        mutation_count.setdefault(new_tx, []).append(0)

                        for possible_next_state in self.next_state_mutations[node_state_name]:
                            mutated_out_tx_new_state = possible_next_state + "::" + out_msg + ":" + out_fields
                            allowed_transitions.setdefault(new_tx, []).append(mutated_out_tx_new_state)
                            mutation_count.setdefault(new_tx, []).append(1)

                new_tx_msg_only = node_combined_state_name + ":" + inp_msg + ":"

                if constraint_token.check_token_match(new_tx_msg_only, out_tx)[0] \
                        and inp_symbol not in self.statewise_prohibited_mutation_messages[node_state_name]:

                    if out_state_name == node_state_name:
                        if constraint_token.check_token_match(new_tx, out_tx)[0]:
                            new_out_tx = \
                                out_state_name + ":" + concatenated_varexp + ":" + out_msg + ":" + out_fields

                            allowed_transitions.setdefault(new_tx, []).append(new_out_tx)
                            mutation_count.setdefault(new_tx, []).append(0)

                        for possible_next_state in self.next_state_mutations[node_state_name]:
                            mutated_out_tx_new_state = possible_next_state + "::" + out_msg + ":" + out_fields
                            allowed_transitions.setdefault(new_tx, []).append(mutated_out_tx_new_state)
                            mutation_count.setdefault(new_tx, []).append(1)

                    mutation_inp_tx = node_combined_state_name + ":" + \
                                      "mutation( " + inp_msg + " , " + constraint_token.token_str + " )" + \
                                      ":" + \
                                      "mutation( " + inp_fields + " , " + constraint_token.token_str + " )"

                    mutation_out_tx_1 = out_state_name + ":" + concatenated_varexp + ":" + "$" + ":"
                    allowed_transitions.setdefault(mutation_inp_tx, []).append(mutation_out_tx_1)
                    mutation_count.setdefault(mutation_inp_tx, []).append(1)

                    for possible_next_state in self.next_state_mutations[node_state_name]:
                        mutated_out_tx_new_state = possible_next_state + "::" + "$" + ":"
                        allowed_transitions.setdefault(mutation_inp_tx, []).append(mutated_out_tx_new_state)
                        mutation_count.setdefault(mutation_inp_tx, []).append(2)

        return allowed_transitions, mutation_count

    def get_transitions(self, node_combined_state, token_rem: int):
        forward_token, allowed_token = self.get_next_fwd_allowed_tokens(self.token_list, token_rem)

        if forward_token is None:
            forward_tx = dict()
            fwd_tx_mutation_count = dict()
        else:
            if token_rem == 1:
                forward_tx, fwd_tx_mutation_count = self.get_forward_transitions(node_combined_state, forward_token,
                                                                                 True)
            else:
                forward_tx, fwd_tx_mutation_count = self.get_forward_transitions(node_combined_state, forward_token)

        if allowed_token is None:
            allowed_tx = dict()
            allowed_tx_mutation_count = dict()
        else:
            allowed_tx, allowed_tx_mutation_count = self.get_allowed_transitions(node_combined_state, allowed_token)

        return forward_tx, fwd_tx_mutation_count, allowed_tx, allowed_tx_mutation_count

    def generate_mutated_sequences(self, dump_filename, template_qre, max_mutation_budget=2, max_test_case_length=7):
        self.retrieve_next_state_mutations()
        self.retrieve_state_wise_prohibited_mutation_messages()

        self.testcases = []
        self.clear_mutation_list()

        self.template_qre = template_qre
        self.token_list = parse_qre_exp(self.template_qre)

        total_tokens = self.count_token_remaining(self.token_list)

        self.generate_fixed_mutation(self.start_state_name + ":" + self.start_varexp_value,
                                     max_mutation_budget,
                                     total_tokens,
                                     max_test_case_length)

        self.testcases = self.expand_testcase(self.start_state_name + ":" + self.start_varexp_value,
                                              max_mutation_budget,
                                              total_tokens,
                                              max_test_case_length)

        print("Here {}".format(len(self.testcases)))
        delete_table("duplication")
        create_table("duplication")

        all_testcases_dict = dict()
        all_testcases_dict["testcases"] = list()

        id_count = 0
        for i in range(len(self.testcases)):
            print(i)
            inp_seq = [j[1] for j in self.testcases[i]]
            in_db, _ = query_data(inp_seq, "duplication")
            valid_replay, has_mutation, num_states = self.check_testcase(self.testcases[i])
            if not in_db and valid_replay:
                id_count += 1
                insert_data(inp_seq, "#", "duplication")
                testcase_list = self.get_json_dict(self.testcases[i])
                testcase_dict = dict()
                testcase_dict["id"] = id_count
                testcase_dict["testcase"] = testcase_list
                testcase_dict["has_mutation"] = has_mutation
                testcase_dict["length"] = len(testcase_list)
                testcase_dict["use_count"] = 0
                testcase_dict["num_states_visited"] = num_states
                all_testcases_dict["testcases"].append(testcase_dict)

        with open(os.path.join('testcases_dump', "{}.json".format(dump_filename.split(".")[0])), 'w') as fw:
            json.dump(all_testcases_dict, fw, indent=4)

        return

    def get_json_dict(self, testcase):
        testcase_dict = list()
        for i in range(len(testcase)):
            element_dict = dict()
            element_dict["initial_state"] = testcase[i][0]
            element_dict["input_symbol"] = testcase[i][1]
            element_dict["output_symbol"] = testcase[i][2]
            element_dict["next_state"] = testcase[i][3]
            testcase_dict.append(element_dict)

        return testcase_dict

    def check_testcase(self, testcase):
        valid_replay = True
        has_mutation = False

        states = list()

        checked_messages = []
        for i in range(len(testcase)):
            states.append(testcase[i][0])
            inp_msg, inp_fields = extract_message_and_fields(testcase[i][1])
            if "replay == 1" in testcase[i][1]:
                if inp_msg not in checked_messages:
                    valid_replay = False

            if "mutation(" in testcase[i][1]:
                has_mutation = True

            checked_messages.append(inp_msg)

        return valid_replay, has_mutation, len(list(set(states)))

    def expand_testcase(self, node_combined_state, mutation_rem, token_rem, length_rem):
        _, results = self.check_in_mutation_list(node_combined_state,
                                                 mutation_rem,
                                                 token_rem,
                                                 length_rem)

        testcases = []
        if results[0]:
            sequences = results[1]
            for i in range(len(sequences)):
                curr_tok = sequences[i][0]
                expand_node = sequences[i][1]
                if len(expand_node) == 4:
                    suffix_seqs = self.expand_testcase(expand_node[0],
                                                       expand_node[1],
                                                       expand_node[2],
                                                       expand_node[3])

                    final_seq = [[curr_tok] + seq for seq in suffix_seqs]
                    for seq in final_seq:
                        testcases.append(seq)

                else:
                    testcases.append([curr_tok])
        return testcases

    def generate_fixed_mutation(self, node_combined_state_name, mutation_rem, token_rem, length_rem):

        if token_rem > length_rem:
            self.add_to_mutation_list(node_combined_state_name, False, [], mutation_rem, token_rem,
                                      length_rem)
            return False, []
        if mutation_rem < 0:
            self.add_to_mutation_list(node_combined_state_name, False, [], mutation_rem, token_rem,
                                      length_rem)
            return False, []
        if length_rem == 0:
            if token_rem > 0:
                self.add_to_mutation_list(node_combined_state_name, False, [], mutation_rem, token_rem,
                                          length_rem)
                return False, []
            else:
                self.add_to_mutation_list(node_combined_state_name, True, [], mutation_rem, token_rem,
                                          length_rem)
                return True, []
        if token_rem == 0:
            self.add_to_mutation_list(node_combined_state_name, True, [], mutation_rem, token_rem,
                                      length_rem)
            return True, []

        fn_exists_seq = False
        fn_seq_list = []

        print(node_combined_state_name, mutation_rem, token_rem, length_rem)
        forward_transitions, forward_tx_mutation_count, \
            allowed_transitions, allowed_tx_mutation_count = self.get_transitions(node_combined_state_name,
                                                                                  token_rem)

        for forward_inp_tx, forward_output_transitions in forward_transitions.items():
            mutation_counts = forward_tx_mutation_count[forward_inp_tx]

            for i in range(len(forward_output_transitions)):
                forward_output_tx = forward_output_transitions[i]
                mutation_count = mutation_counts[i]

                inp_state, inp_varexp, inp_msg, inp_fields = extract_info_from_transition(forward_inp_tx)
                out_state, out_varexp, out_msg, out_fields = extract_info_from_transition(forward_output_tx)

                next_combined_state = out_state + ":" + out_varexp
                input_sym = inp_msg + ":" + inp_fields
                output_sym = out_msg + ":" + out_fields

                calculated, result = self.check_in_mutation_list(next_combined_state,
                                                                 mutation_rem - mutation_count,
                                                                 token_rem - 1,
                                                                 length_rem - 1)

                if calculated:
                    exists, sequences = result
                else:
                    exists, sequences = self.generate_fixed_mutation(next_combined_state,
                                                                     mutation_rem - mutation_count,
                                                                     token_rem - 1, length_rem - 1)
                if exists:
                    fn_exists_seq = True
                    if token_rem == 1:
                        fn_seq_list.append(
                            [[node_combined_state_name, input_sym,
                              output_sym,
                              next_combined_state], []])
                    else:
                        fn_seq_list.append([[node_combined_state_name, input_sym,
                                             output_sym,
                                             next_combined_state],
                                            [next_combined_state, mutation_rem - mutation_count,
                                             token_rem - 1, length_rem - 1]])

        for allowed_inp_tx, allowed_output_transitions in allowed_transitions.items():
            mutation_counts = allowed_tx_mutation_count[allowed_inp_tx]

            for i in range(len(allowed_output_transitions)):
                allowed_output_tx = allowed_output_transitions[i]
                mutation_count = mutation_counts[i]

                inp_state, inp_varexp, inp_msg, inp_fields = extract_info_from_transition(allowed_inp_tx)
                out_state, out_varexp, out_msg, out_fields = extract_info_from_transition(allowed_output_tx)

                next_combined_state = out_state + ":" + out_varexp
                input_sym = inp_msg + ":" + inp_fields
                output_sym = out_msg + ":" + out_fields

                calculated, result = self.check_in_mutation_list(next_combined_state,
                                                                 mutation_rem - mutation_count,
                                                                 token_rem,
                                                                 length_rem - 1)

                if calculated:
                    exists, sequences = result
                else:
                    exists, sequences = self.generate_fixed_mutation(next_combined_state,
                                                                     mutation_rem - mutation_count,
                                                                     token_rem, length_rem - 1)

                if exists:
                    fn_exists_seq = True
                    fn_seq_list.append([[node_combined_state_name, input_sym,
                                         output_sym,
                                         next_combined_state],
                                        [next_combined_state, mutation_rem - mutation_count,
                                         token_rem, length_rem - 1]])

        self.add_to_mutation_list(node_combined_state_name,
                                  fn_exists_seq,
                                  fn_seq_list,
                                  mutation_rem,
                                  token_rem,
                                  length_rem)

        return fn_exists_seq, fn_seq_list


def convert_json_to_dict(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)
        data = handle_circular_references(data)
        return data


def handle_circular_references(obj):
    if isinstance(obj, dict):
        return {key: handle_circular_references(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [handle_circular_references(item) for item in obj]
    else:
        return obj


def modify_raw_testcases(dump_filename, old_input_msg, changed_input, changed_output):
    file_path = os.path.join('testcases_dump', "{}.json".format(dump_filename.split(".")[0]))
    expanded_test_cases = convert_json_to_dict(file_path)

    for t in range(len(expanded_test_cases["testcases"])):
        t_testcase = expanded_test_cases["testcases"][t]
        for i in range(len(t_testcase["testcase"]) - 1, -1, -1):
            inp_msg_element = t_testcase["testcase"][i]["input_symbol"]
            msg, field = extract_message_and_fields(inp_msg_element)
            if old_input_msg == msg:
                t_testcase["testcase"][i]["input_symbol"] = changed_input
                t_testcase["testcase"][i]["output_symbol"] = changed_output
                break

    with open(file_path, "w") as file:
        json.dump(expanded_test_cases, file, indent=4)


def check_testcase_against_qre(testcase, token_list: List[Token]):
    # testcase : list of (input, output)
    if len(token_list) == 0:
        return True

    if len(testcase) == 0 and len(token_list) != 0:
        return False

    matches_allowed = False

    forward_token_idx = -1
    allowed_token_idx = -1

    for i in range(len(token_list)):
        if token_list[i].token_type == 1 or token_list[i].token_type == 3:
            forward_token_idx = i
            break

    for i in range(len(token_list)):
        if token_list[i].token_type == 2 or token_list[i].token_type == 4:
            allowed_token_idx = i
            break

    if forward_token_idx != -1:
        current_forward_token = token_list[forward_token_idx]
    else:
        return True

    if allowed_token_idx != -1:
        current_allowed_token = token_list[allowed_token_idx]
    else:
        current_allowed_token = None

    matches_forward = current_forward_token.check_token_satisfy_concrete_trace(testcase[0][0],
                                                                               testcase[0][1])
    if current_allowed_token is not None:
        matches_allowed = current_allowed_token.check_token_satisfy_concrete_trace(testcase[0][0],
                                                                                   testcase[0][1])

    if matches_forward and matches_allowed:
        return check_testcase_against_qre(testcase[1:],
                                          token_list[
                                          forward_token_idx + 1:]) | check_testcase_against_qre(
            testcase[1:], token_list)

    elif (not matches_forward) and matches_allowed:
        return check_testcase_against_qre(testcase[1:], token_list)

    elif matches_forward and (not matches_allowed):
        return check_testcase_against_qre(testcase[1:], token_list[forward_token_idx + 1:])

    else:
        return False


def list_violations(concrete_testcase, qre_pool, match_string_in_qre=""):
    list_idx = list()
    for k, qre_exp in qre_pool.items():
        if match_string_in_qre != "" and match_string_in_qre in qre_exp:
            token_list = parse_qre_exp(qre_exp)
            if check_testcase_against_qre(concrete_testcase, token_list):
                list_idx.append(k)

    return list_idx


def check_qre_expression(qre_exp: str):
    qre_tokens = qre_exp.split(";")
    qre_tokens_list = []
    for qre_tok in qre_tokens:
        qre_tok = qre_tok.strip()
        if "^" in qre_tok or "*" in qre_tok or "<" in qre_tok:
            qre_tokens_list.append(qre_tok)

    if len(qre_tokens_list) == 3 and ("^[ ]*" in qre_tokens_list[1]):
        return True, qre_tokens_list[2]

    return False, ""


def generate_testcase_dump(dump_filename,
                           input_rfsm_filename,
                           qre_expression,
                           seq_mutation_budget,
                           max_testcase_length):

    states, transitions, start_state = get_states_and_tx(input_rfsm_filename)
    reference_fsm = FSM(states, start_state, transitions)
    test_fsm = copy.deepcopy(reference_fsm)

    ok, tok = check_qre_expression(qre_expression)
    if ok:
        inp = tok.split("<")[1].split(",")[0].strip()
        out = tok.split(",")[1].split(">")[0].strip()
        inp_state, inp_varexp, inp_msg, inp_fields = extract_info_from_transition(inp)
        out_state, out_varexp, out_msg, out_fields = extract_info_from_transition(out)
        print(out_state, out_varexp, out_msg, out_fields)

        modified_inp = inp_state + ":" + inp_varexp + ":" + inp_msg + ":"
        modified_tok = "<" + modified_inp + ", ::$:>"
        modified_qre_expression = "<s0::enable_s1:, s1::attach_request:>; ^[ ]*; " + modified_tok + "; "

        test_fsm.generate_mutated_sequences(dump_filename,
                                            modified_qre_expression,
                                            0,
                                            max_testcase_length)

        modify_raw_testcases(dump_filename, inp_msg, inp_msg + ":" + inp_fields,
                             out_msg + ":" + out_fields)

    else:
        test_fsm.generate_mutated_sequences(dump_filename,
                                            qre_expression,
                                            seq_mutation_budget,
                                            max_testcase_length)

    return reference_fsm
