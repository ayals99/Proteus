from typing import Dict, List


class State:
    def __init__(self, name):  # outgoing_tx = (in_sym,out_sym,next_state)
        self.state_name = name
        self.outgoing_transitions_dict = dict()
        self.is_accepting = False
        self.add_outgoing_transition("other", "s_reject")

    def add_outgoing_transition(self, token, next_state_name):
        self.outgoing_transitions_dict[token] = next_state_name

    def get_outgoing_transition_output(self, input_symbol):
        if input_symbol not in self.outgoing_transitions_dict.keys():
            input_symbol = "other"

        return self.outgoing_transitions_dict[input_symbol]

    def get_outgoing_input_symbols(self):
        return list(self.outgoing_transitions_dict.keys())

    def get_name(self):
        return self.state_name

    def print(self):
        print("State : {}, {}".format(self.state_name, self.is_accepting))
        print("Transitions : {}".format(self.outgoing_transitions_dict))


class DFA:
    def __init__(self, qre_expression: str):
        self.qre_expression = qre_expression
        state_counter = 0
        self.start_state_name = "s" + str(state_counter)
        self.states_dict: Dict[str, State] = dict()

        self.states_dict[self.start_state_name] = State(self.start_state_name)
        state_counter += 1

        self.states_dict["s_reject"] = State("s_reject")

        tokens = qre_expression.split(";")
        tokens = [tok.strip() for tok in tokens if tok.strip() != '']

        current_state_name = self.start_state_name
        cursor = 0
        while cursor != len(tokens):
            current_state = self.states_dict[current_state_name]
            if "^" in tokens[cursor]:
                neg_currtok_set = tokens[cursor].split("^")[1].strip()
                if "]*" in tokens[cursor]:
                    inside_neg_currtok_set = neg_currtok_set.split("[")[1].split("]*")[0].strip()
                    current_state.add_outgoing_transition("other", current_state_name)
                    inside_neg_currtok_set = inside_neg_currtok_set.split("|")
                    inside_neg_currtok_set = [tok.strip() for tok in inside_neg_currtok_set]
                    for tok in inside_neg_currtok_set:
                        if tok != '':
                            current_state.add_outgoing_transition(tok, "s_reject")
                else:
                    if "[" in neg_currtok_set:
                        inside_neg_currtok_set = neg_currtok_set.split("[")[1].split("]")[0].strip()
                    else:
                        inside_neg_currtok_set = neg_currtok_set

                    new_state_name = "s" + str(state_counter)
                    self.states_dict[new_state_name] = State(new_state_name)
                    state_counter += 1

                    inside_neg_currtok_set = inside_neg_currtok_set.split("|")
                    inside_neg_currtok_set = [tok.strip() for tok in inside_neg_currtok_set]
                    for tok in inside_neg_currtok_set:
                        current_state.add_outgoing_transition(tok,
                                                              current_state.get_outgoing_transition_output("other"))

                    current_state.add_outgoing_transition("other", new_state_name)
                    current_state_name = new_state_name

            else:
                if "]*" in tokens[cursor]:
                    inside_currtok_set = tokens[cursor].split("[")[1].split("]*")[0].strip()
                    current_state.add_outgoing_transition("other", "s_reject")
                    inside_pos_currtok_set = inside_currtok_set.split("|")
                    inside_pos_currtok_set = [tok.strip() for tok in inside_pos_currtok_set]
                    for tok in inside_pos_currtok_set:
                        current_state.add_outgoing_transition(tok, current_state_name)
                else:
                    if "[" in tokens[cursor]:
                        tokens[cursor] = tokens[cursor].split("[")[1].split("]")[0].strip()

                    new_state_name = "s" + str(state_counter)
                    self.states_dict[new_state_name] = State(new_state_name)
                    state_counter += 1

                    inside_pos_currtok_set = tokens[cursor].split("|")
                    inside_pos_currtok_set = [tok.strip() for tok in inside_pos_currtok_set]
                    for tok in inside_pos_currtok_set:
                        current_state.add_outgoing_transition(tok, new_state_name)
                    current_state_name = new_state_name

            if cursor == len(tokens) - 1:
                self.states_dict[current_state_name].is_accepting = True
            cursor += 1


def dfa_relation(dfa_1: DFA, dfa_2: DFA):
    reachable_state_names: List[str] = list()
    visited_state_names: List[str] = list()
    bfs_queue: List[str] = list()

    reachable_state_names.append(dfa_1.start_state_name + ":" + dfa_2.start_state_name)
    bfs_queue.append(dfa_1.start_state_name + ":" + dfa_2.start_state_name)

    while len(bfs_queue) != 0:
        curr_state_name = bfs_queue.pop(0)
        if curr_state_name in visited_state_names:
            continue

        fsm_1_statename, fsm_2_statename = curr_state_name.split(":")

        input_symbols_1 = dfa_1.states_dict[fsm_1_statename].get_outgoing_input_symbols()
        input_symbols_2 = dfa_2.states_dict[fsm_2_statename].get_outgoing_input_symbols()

        tokens_to_consider = input_symbols_1 + input_symbols_2
        tokens_to_consider = list(set(tokens_to_consider))
        for tok in tokens_to_consider:
            if tok != "other":
                if tok in input_symbols_1 and tok in input_symbols_2:
                    next_state_1_name = dfa_1.states_dict[fsm_1_statename].get_outgoing_transition_output(tok)
                    next_state_2_name = dfa_2.states_dict[fsm_2_statename].get_outgoing_transition_output(tok)
                elif tok in input_symbols_1 and tok not in input_symbols_2:
                    next_state_1_name = dfa_1.states_dict[fsm_1_statename].get_outgoing_transition_output(tok)
                    next_state_2_name = dfa_2.states_dict[fsm_2_statename].get_outgoing_transition_output("other")
                else:
                    next_state_1_name = dfa_1.states_dict[fsm_1_statename].get_outgoing_transition_output("other")
                    next_state_2_name = dfa_2.states_dict[fsm_2_statename].get_outgoing_transition_output(tok)
            else:
                next_state_1_name = dfa_1.states_dict[fsm_1_statename].get_outgoing_transition_output("other")
                next_state_2_name = dfa_2.states_dict[fsm_2_statename].get_outgoing_transition_output("other")

            reachable_state_names.append(next_state_1_name + ":" + next_state_2_name)
            bfs_queue.append(next_state_1_name + ":" + next_state_2_name)

        visited_state_names.append(curr_state_name)

    reachable_state_names = list(set(reachable_state_names))

    is_universal = True
    is_disjoint = True
    latter_not_subset_former = False
    former_not_subset_latter = False
    # print(reachable_state_names)
    for reachable_state_name in reachable_state_names:
        state_1_name, state_2_name = reachable_state_name.split(":")

        state_1 = dfa_1.states_dict[state_1_name]
        state_2 = dfa_2.states_dict[state_2_name]

        if state_1.is_accepting and state_2.is_accepting:
            is_disjoint = False
        elif not state_1.is_accepting and state_2.is_accepting:
            latter_not_subset_former = True
        elif state_1.is_accepting and not state_2.is_accepting:
            former_not_subset_latter = True
        else:
            is_universal = False

    if not latter_not_subset_former and former_not_subset_latter:
        latter_subset_former = True
    else:
        latter_subset_former = False

    if not former_not_subset_latter and latter_not_subset_former:
        former_subset_latter = True
    else:
        former_subset_latter = False

    return is_universal, is_disjoint, former_subset_latter, latter_subset_former


def qre_relation(qre_1: str, qre_2: str):
    dfa_1 = DFA(qre_1)
    dfa_2 = DFA(qre_2)

    # for st in dfa_1.states_dict.values():
    #     st.print()
    #
    # print("\n")
    #
    # for st in dfa_2.states_dict.values():
    #     st.print()
    #
    # print("\n")

    return dfa_relation(dfa_1, dfa_2)[2], dfa_relation(dfa_1, dfa_2)[3]


# print(qre_relation("^[<q>]*;  <p>;  ^[ ]*;  <r>;",
#                    "^[<q>]*;  <p>;  ^[<q>]*;  <r>;"))
