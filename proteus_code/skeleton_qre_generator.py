import os
import pprint
import random
from typing import List, Dict
from qre_to_fsm import qre_relation

AND = 1
OR = 2
NOT = 3

YESTERDAY = 4
SINCE = 5
HISTORICALLY = 6
ONCE = 10

IMPLIES = 7

OPERATOR = 8
OPERAND = 9

binary_ops = [SINCE, AND, OR, IMPLIES]
unary_ops = [NOT, YESTERDAY, HISTORICALLY, ONCE]
num_to_operator = {1: "AND", 2: "OR", 3: "NOT", 4: "YESTERDAY", 5: "SINCE", 6: "HISTORICALLY",
                   7: "IMPLIES", 10: "ONCE", 8: "OPERATOR", 9: "OPERAND"}

ltl_property_filename = 'automated_lte_properties.txt'


def delete_files_in_directory(directory):
    if not os.path.exists(directory):
        os.mkdir(directory)
        return
    files = os.listdir(directory)

    for file in files:
        file_path = os.path.join(directory, file)
        if os.path.isfile(file_path):
            if "manual" not in file_path:
                os.remove(file_path)
            # print("Deleted:", file_path)


class Proposition:
    def __init__(self, token):
        self.token = token
        self.polarity_type = 0  # 0 unassinged, 1 s, 2 s*, 3 v, 4 v*

    def set_polarity(self, polarity):
        self.polarity_type = polarity


class TraceToken:
    def __init__(self):
        self.token_set: List[str] = list()

        self.token_set_once: List[str] = list()
        self.token_set_everywhere: List[str] = list()

        self.once_polarity_type = 0  # 1 satisfy, 2 violate
        self.everywhere_polarity_type = 0

    def print(self):
        pp = pprint.PrettyPrinter(indent=4)
        print("Token set once: ")
        pp.pprint(self.token_set_once)
        print("Once Polarity Type : {}".format(self.once_polarity_type))
        print("Token set everywhere: ")
        pp.pprint(self.token_set_everywhere)
        print("Everywhere Polarity Type : {}".format(self.everywhere_polarity_type))
        print("\n")


class Node:
    def __init__(self):
        self.node_type = None
        self.node_value = None
        self.unary_type = False

        self.node_left = None
        self.node_right = None


class Tree:
    def __init__(self, pltl_expression):
        self.pltl_expression = pltl_expression
        self.root = Node()
        self.precedence_order = {NOT: 5, YESTERDAY: 6, ONCE: 6, SINCE: 4, HISTORICALLY: 6,
                                 AND: 3, IMPLIES: 1, OR: 2}
        self.operator_symbol = {NOT: '!', YESTERDAY: 'Y', ONCE: 'O', SINCE: 'S', HISTORICALLY: 'H',
                                AND: '&', IMPLIES: '->', OR: '|'}

        self.postfix: List[Node] = list()
        self.infix_to_postfix(self.pltl_expression)

        self.create_ast()

    def infix_to_postfix(self, pltl_expression):
        operator_stack = []
        self.postfix = []
        i = 0
        token = ""
        in_tok = False
        while i < len(pltl_expression):
            if in_tok:
                if pltl_expression[i] != ">":
                    token += pltl_expression[i]
                else:
                    token += pltl_expression[i]
                    pp = Proposition(token)
                    nn = Node()
                    nn.node_type = OPERAND
                    nn.node_value = pp
                    self.postfix.append(nn)

                    in_tok = False
            else:
                if pltl_expression[i] == "<":
                    token = "<"
                    in_tok = True
                elif pltl_expression[i] == "(":
                    operator_stack.append(pltl_expression[i])
                elif pltl_expression[i] == ")":
                    while (len(operator_stack) != 0
                           and operator_stack[-1] != '('):
                        popped_operator = operator_stack.pop()
                        nn = Node()
                        nn.node_type = OPERATOR
                        nn.node_value = popped_operator
                        self.postfix.append(nn)
                    if len(operator_stack) != 0 and operator_stack[-1] == '(':
                        operator_stack.pop()
                else:
                    current_operator = -1
                    if pltl_expression[i] == "Y":
                        current_operator = YESTERDAY
                    elif pltl_expression[i] == "H":
                        current_operator = HISTORICALLY
                    elif pltl_expression[i] == "S":
                        current_operator = SINCE
                    elif pltl_expression[i] == "O":
                        current_operator = ONCE
                    elif pltl_expression[i] == "&":
                        current_operator = AND
                    elif pltl_expression[i] == "|":
                        current_operator = OR
                    elif pltl_expression[i] == "!":
                        current_operator = NOT
                    elif pltl_expression[i] == "-" and pltl_expression[i + 1] == ">":
                        current_operator = IMPLIES
                    if current_operator in self.precedence_order.keys():
                        while (len(operator_stack) != 0
                               and operator_stack[-1] != '('
                               and self.precedence_order[operator_stack[-1]] > self.precedence_order[current_operator]):
                            popped_operator = operator_stack.pop()
                            nn = Node()
                            nn.node_type = OPERATOR
                            nn.node_value = popped_operator
                            self.postfix.append(nn)
                        operator_stack.append(current_operator)

            i += 1

        while len(operator_stack) != 0:
            popped_operator = operator_stack.pop()
            nn = Node()
            nn.node_type = OPERATOR
            nn.node_value = popped_operator
            self.postfix.append(nn)

    def create_ast(self):
        node_stack: List[Node] = list()
        for i in range(len(self.postfix)):
            if self.postfix[i].node_type == OPERAND:
                node_stack.append(self.postfix[i])
            else:
                operator = self.postfix[i].node_value
                if operator in unary_ops and len(node_stack) >= 1:
                    operand_1 = node_stack.pop()
                    self.postfix[i].node_left = operand_1
                    self.postfix[i].unary_type = True
                elif operator in binary_ops and len(node_stack) >= 2:
                    operand_1 = node_stack.pop()
                    operand_2 = node_stack.pop()
                    self.postfix[i].node_left = operand_2
                    self.postfix[i].node_right = operand_1
                    self.postfix[i].unary_type = False
                node_stack.append(self.postfix[i])

        self.root = node_stack.pop()

    def print_node(self, node: Node):
        print("Node Type: {}".format(node.node_type))
        if node.node_type == OPERAND:
            print("Proposition {}".format(node.node_value.token))
        elif node.node_type == OPERATOR:
            print("Operator {}".format(num_to_operator[node.node_value]))
        print("\n")

    def print_ast_infix(self, node: Node):
        print("In Node {}".format(node.node_value))
        if node.node_left is not None:
            print("Left of {}".format(node.node_value))
            self.print_ast_infix(node.node_left)
        print("Center")
        self.print_node(node)
        if node.node_right is not None:
            print("Right of {}".format(node.node_value))
            self.print_ast_infix(node.node_right)

    def print_trace(self, trace_dict):
        print("Trace :")
        for k, v in trace_dict.items():
            print("{}".format(k))
            v.print()
        print("---\n")

    def generate_skeletons(self, polarity, target_num_traces, max_trace_size):
        current_num_traces = 0
        final_traces = []

        max_tries = 1000
        num_tries = 0
        while current_num_traces < target_num_traces and num_tries < max_tries:
            trace_size = random.randint(1, max_trace_size)
            result, trace = self.high_level_generate_trace(polarity, trace_length=trace_size)
            if result:
                generated_qre = self.generate_qre(self.refine_trace(trace))
                if generated_qre not in final_traces:

                    new_traces = []
                    put_generated_qre = True
                    for existing_qre in final_traces:
                        former_subset_latter, latter_subset_former = qre_relation(existing_qre, generated_qre)
                        if not former_subset_latter:
                            new_traces.append(existing_qre)
                        if latter_subset_former:
                            put_generated_qre = False
                            break
                    if put_generated_qre:
                        new_traces.append(generated_qre)

                    final_traces = new_traces
                    current_num_traces += 1

            num_tries += 1

        final_traces = sorted(final_traces, key=lambda item: len(str(item).split(";")))

        return final_traces

    def refine_trace(self, trace_dict: Dict[int, TraceToken]):
        keys = sorted(trace_dict.keys(), reverse=True)
        keys_to_be_removed = []
        seen_first_nonempty_token = False
        for k in keys:
            curr_token = trace_dict[k]
            if curr_token.once_polarity_type == 0 and curr_token.everywhere_polarity_type == 0:
                if not seen_first_nonempty_token:
                    keys_to_be_removed.append(k)
                elif k > 0:
                    if trace_dict[k - 1].once_polarity_type == 0 and trace_dict[k - 1].everywhere_polarity_type == 0:
                        keys_to_be_removed.append(k)
            else:
                seen_first_nonempty_token = True

        for k in keys_to_be_removed:
            if k in trace_dict.keys():
                del trace_dict[k]

        return trace_dict

    def list_to_string(self, print_list, neg=False):
        str_to_append = ""
        if neg:
            str_to_append = "^"
        str_to_append += "["
        for i in range(len(print_list)):
            str_to_append += print_list[i]
            if i != len(print_list) - 1:
                str_to_append += "| "
        str_to_append += "]"
        return str_to_append

    def generate_qre(self, trace_dict: Dict[int, TraceToken]):
        keys = sorted(trace_dict.keys())
        final_qre = ""
        for k in keys:
            curr_token = trace_dict[k]
            if curr_token.everywhere_polarity_type == 2 and len(curr_token.token_set_everywhere) != 0:
                str_to_append = self.list_to_string(curr_token.token_set_everywhere, True)
                final_qre += str_to_append + "*; "
            elif curr_token.everywhere_polarity_type == 1 and len(curr_token.token_set_everywhere) != 0:
                str_to_append = self.list_to_string(curr_token.token_set_everywhere, False)
                final_qre += str_to_append + "*; "

            if curr_token.once_polarity_type == 1 and len(curr_token.token_set_once) != 0:
                if len(curr_token.token_set_once) == 1:
                    str_to_append = curr_token.token_set_once[0]
                    final_qre += str_to_append + "; "
                else:
                    str_to_append = self.list_to_string(curr_token.token_set_once, False)
                    final_qre += str_to_append + "; "
            elif curr_token.once_polarity_type == 2 and len(curr_token.token_set_once) != 0:
                if len(curr_token.token_set_once) == 1:
                    str_to_append = "^" + curr_token.token_set_once[0]
                    final_qre += str_to_append + "; "
                else:
                    str_to_append = self.list_to_string(curr_token.token_set_once, True)
                    final_qre += str_to_append + "; "

            if curr_token.once_polarity_type == 0 and curr_token.everywhere_polarity_type == 0:
                str_to_append = "^[ ]*; "
                final_qre += str_to_append

        return self.refine_qre(final_qre)

    def refine_qre(self, original_qre: str):
        # print(original_qre)
        tokens = original_qre.strip().split(";")
        prev_tok = ""
        prev_tok_added = False
        final_qre = ""
        for i in range(len(tokens)):
            if not ("[" in tokens[i] or "<" in tokens[i]):
                continue

            curr_tok = tokens[i].strip()

            if "]*" not in curr_tok:

                if "]*" in prev_tok:
                    if "^" in prev_tok and "^" in curr_tok:
                        tokens_list_prevtok_str = prev_tok.split("^[")[1].split("]*")[0].strip()
                        if "|" in tokens_list_prevtok_str:
                            tokens_list_prevtok_list = tokens_list_prevtok_str.split("|")
                        else:
                            tokens_list_prevtok_list = [tokens_list_prevtok_str]
                        if "[" in curr_tok:
                            tokens_list_currtok_str = curr_tok.split("^[")[1].split("]")[0].strip()
                            if "|" in tokens_list_currtok_str:
                                tokens_list_currtok_list = tokens_list_currtok_str.split("|")
                            else:
                                tokens_list_currtok_list = [tokens_list_currtok_str]
                        else:
                            tokens_list_currtok_list = [curr_tok.split("^")[1].strip()]

                        for tok_curr in tokens_list_currtok_list:
                            if tok_curr not in tokens_list_prevtok_list:

                                if not prev_tok_added and prev_tok != "":
                                    final_qre += prev_tok + "; "

                                final_qre += curr_tok + "; "
                                prev_tok = curr_tok
                                prev_tok_added = True

                                break

                    elif ("^" not in prev_tok) and ("^" not in curr_tok):

                        tokens_list_prevtok_str = prev_tok.split("[")[1].split("]*")[0].strip()
                        if "|" in tokens_list_prevtok_str:
                            tokens_list_prevtok_list = tokens_list_prevtok_str.split("|")
                        else:
                            tokens_list_prevtok_list = [tokens_list_prevtok_str]
                        if "[" in curr_tok:
                            tokens_list_currtok_str = curr_tok.split("[")[1].split("]")[0].strip()
                            if "|" in tokens_list_currtok_str:
                                tokens_list_currtok_list = tokens_list_currtok_str.split("|")
                            else:
                                tokens_list_currtok_list = [tokens_list_currtok_str]
                        else:
                            tokens_list_currtok_list = [curr_tok]

                        for tok_curr in tokens_list_currtok_list:
                            if tok_curr not in tokens_list_prevtok_list:

                                if not prev_tok_added and prev_tok != "":
                                    final_qre += prev_tok + "; "

                                final_qre += curr_tok + "; "
                                prev_tok = curr_tok
                                prev_tok_added = True
                                break

                    else:
                        if not prev_tok_added and prev_tok != "":
                            final_qre += prev_tok + "; "

                        final_qre += curr_tok + "; "
                        prev_tok = curr_tok
                        prev_tok_added = True
                else:
                    if not prev_tok_added and prev_tok != "":
                        final_qre += prev_tok + "; "

                    final_qre += curr_tok + "; "
                    prev_tok = curr_tok
                    prev_tok_added = True

            else:
                if "]*" in prev_tok:
                    if "^" in prev_tok and "^" in curr_tok:
                        all_tok = []
                        tokens_list_prevtok_str = prev_tok.split("^[")[1].split("]*")[0].strip()
                        if "|" in tokens_list_prevtok_str:
                            tokens_list_prevtok_list = tokens_list_prevtok_str.split("|")
                        else:
                            tokens_list_prevtok_list = [tokens_list_prevtok_str]

                        tokens_list_currtok_str = curr_tok.split("^[")[1].split("]")[0].strip()
                        if "|" in tokens_list_currtok_str:
                            tokens_list_currtok_list = tokens_list_currtok_str.split("|")
                        else:
                            tokens_list_currtok_list = [tokens_list_currtok_str]

                        for tok_curr in tokens_list_currtok_list:
                            if "<" in tok_curr:
                                all_tok.append(tok_curr)

                        for tok_prev in tokens_list_prevtok_list:
                            if "<" in tok_prev:
                                all_tok.append(tok_prev)

                        all_tok = list(set(all_tok))

                        new_tok_str = "^["
                        for j in range(len(all_tok)):
                            if j == 0:
                                new_tok_str += all_tok[j]
                            else:
                                new_tok_str += "|" + all_tok[j]
                        new_tok_str += "]*"

                        prev_tok = new_tok_str
                        prev_tok_added = False

                    elif "^" not in prev_tok and "^" not in tokens[i]:
                        all_tok = []
                        tokens_list_prevtok_str = prev_tok.split("[")[1].split("]*")[0].strip()
                        if "|" in tokens_list_prevtok_str:
                            tokens_list_prevtok_list = tokens_list_prevtok_str.split("|")
                        else:
                            tokens_list_prevtok_list = [tokens_list_prevtok_str]

                        tokens_list_currtok_str = curr_tok.split("[")[1].split("]")[0].strip()
                        if "|" in tokens_list_currtok_str:
                            tokens_list_currtok_list = tokens_list_currtok_str.split("|")
                        else:
                            tokens_list_currtok_list = [tokens_list_currtok_str]

                        for tok_curr in tokens_list_currtok_list:
                            all_tok.append(tok_curr)

                        for tok_prev in tokens_list_prevtok_list:
                            all_tok.append(tok_prev)

                        all_tok = list(set(all_tok))

                        new_tok_str = "["
                        for j in range(len(all_tok)):
                            if j == 0:
                                new_tok_str += all_tok[j]
                            else:
                                new_tok_str += "|" + all_tok[j]
                        new_tok_str += "]*"

                        prev_tok = new_tok_str
                        prev_tok_added = False
                    else:
                        if "^" in prev_tok:
                            prev_tok = curr_tok
                            prev_tok_added = False

                else:
                    prev_tok = curr_tok
                    prev_tok_added = False

        # print("Refined {}".format(final_qre))
        return final_qre

    def high_level_generate_trace(self, polarity=3, trace_length=7, max_tries=50):
        global total_success
        trace: Dict[int, TraceToken] = dict()
        for k in range(trace_length):
            trace[k] = TraceToken()
        result = False

        num_tries = 0
        while not result and num_tries < max_tries:
            trace: Dict[int, TraceToken] = dict()
            for k in range(trace_length):
                trace[k] = TraceToken()
            if polarity == 1 or polarity == 3:
                trace_position = random.randint(0, trace_length - 1)
                result, trace_new = self.generate_trace_fixed_position(polarity, self.root, trace_position, trace)

                if result:
                    return result, trace_new

            num_tries += 1

        return result, trace

    def generate_trace_fixed_position(self, polarity: int, node: Node, trace_position: int,
                                      trace_dict: Dict[int, TraceToken]):
        result = False
        if node.node_type == OPERAND:
            trace_token = trace_dict[trace_position]

            if polarity == 1:
                if trace_token.once_polarity_type == 1:
                    if node.node_value.token in trace_token.token_set_once:
                        result = True
                    else:
                        result = False
                elif trace_token.once_polarity_type == 2:
                    if node.node_value.token not in trace_token.token_set_once:
                        trace_token.token_set_once.clear()
                        trace_token.token_set_once.append(node.node_value.token)
                        trace_token.once_polarity_type = 1
                        trace_dict[trace_position] = trace_token
                        result = True
                else:
                    trace_token.token_set_once.clear()
                    trace_token.token_set_once.append(node.node_value.token)
                    trace_token.once_polarity_type = 1
                    trace_dict[trace_position] = trace_token
                    result = True

                if trace_token.everywhere_polarity_type == 1:
                    if node.node_value.token in trace_token.token_set_everywhere:
                        result = True
                    else:
                        result = False
                elif trace_token.everywhere_polarity_type == 2:
                    if node.node_value.token in trace_token.token_set_everywhere:
                        result = False

            elif polarity == 2:

                if trace_token.once_polarity_type == 1:
                    if node.node_value.token not in trace_token.token_set_once:
                        result = False

                elif trace_token.once_polarity_type == 2:
                    if node.node_value.token not in trace_token.token_set_once:
                        trace_token.token_set_once.clear()
                        trace_token.once_polarity_type = 0
                        trace_dict[trace_position] = trace_token
                    else:
                        result = False

                if trace_token.everywhere_polarity_type == 1:
                    if node.node_value.token in trace_token.token_set_everywhere:
                        result = True
                    else:
                        result = False
                elif trace_token.everywhere_polarity_type == 2:
                    if node.node_value.token in trace_token.token_set_everywhere:
                        result = False
                    else:
                        trace_token.token_set_everywhere.clear()
                        trace_token.token_set_everywhere.append(node.node_value.token)
                        trace_token.everywhere_polarity_type = 1
                        trace_dict[trace_position] = trace_token
                        result = True
                else:
                    trace_token.token_set_everywhere.clear()
                    trace_token.token_set_everywhere.append(node.node_value.token)
                    trace_token.everywhere_polarity_type = 1
                    trace_dict[trace_position] = trace_token
                    result = True

            elif polarity == 3:

                if trace_token.once_polarity_type == 1:
                    if node.node_value.token not in trace_token.token_set_once:
                        result = True
                    else:
                        result = False

                elif trace_token.once_polarity_type == 2:
                    if node.node_value.token not in trace_token.token_set_once:
                        trace_token.token_set_once.append(node.node_value.token)
                        trace_dict[trace_position] = trace_token
                        result = True
                    else:
                        result = True

                else:
                    trace_token.token_set_once.clear()
                    trace_token.token_set_once.append(node.node_value.token)
                    trace_token.once_polarity_type = 2
                    trace_dict[trace_position] = trace_token
                    result = True

                if trace_token.everywhere_polarity_type == 1:
                    if node.node_value.token in trace_token.token_set_everywhere:
                        result = False
                    else:
                        result = True

                elif trace_token.everywhere_polarity_type == 2:
                    if node.node_value.token in trace_token.token_set_everywhere:
                        result = True

            elif polarity == 4:

                if trace_token.once_polarity_type == 1:
                    if node.node_value.token in trace_token.token_set_once:
                        result = False

                if trace_token.everywhere_polarity_type == 1:
                    if node.node_value.token not in trace_token.token_set_everywhere:
                        result = False
                    else:
                        result = True
                elif trace_token.everywhere_polarity_type == 2:
                    if node.node_value.token in trace_token.token_set_everywhere:
                        result = True
                    else:
                        trace_token.token_set_everywhere.append(node.node_value.token)
                        trace_dict[trace_position] = trace_token
                        result = True
                else:
                    trace_token.token_set_everywhere.append(node.node_value.token)
                    trace_token.everywhere_polarity_type = 2
                    trace_dict[trace_position] = trace_token
                    result = True

        else:
            if node.node_type == OPERATOR and node.node_value == AND:
                if polarity == 1 or polarity == 2:
                    result_1, trace_dict_new = \
                        self.generate_trace_fixed_position(polarity, node.node_left, trace_position, trace_dict)
                    result_2, trace_dict_new = \
                        self.generate_trace_fixed_position(polarity, node.node_right, trace_position, trace_dict_new)
                    result = result_1 & result_2
                    if result:
                        trace_dict = trace_dict_new

                elif polarity == 3 or polarity == 4:
                    rand = random.randint(0, 1)
                    if rand == 0:
                        result, trace_dict_new = \
                            self.generate_trace_fixed_position(polarity, node.node_left, trace_position, trace_dict)
                        if result:
                            trace_dict = trace_dict_new

                    elif rand == 1:
                        result, trace_dict_new = \
                            self.generate_trace_fixed_position(polarity, node.node_right, trace_position, trace_dict)
                        if result:
                            trace_dict = trace_dict_new

                # elif polarity == 4:
                #     result = True
                #     # for i in range(0, trace_position + 1):
                #     #     result_1, trace_dict = self.generate_trace(3, node, i, trace_dict)
                #     #     result = result_1
                #     #     if not result_1:
                #     #         break

                # p 2: You have to satisfy p form now until the next positive token
                # p 4: You have to violate p from now until the next positive token

            elif node.node_type == OPERATOR and node.node_value == OR:
                # (p | q)
                if polarity == 1 or polarity == 2:
                    rand = random.randint(0, 1)
                    if rand == 0:
                        result, trace_dict_new = \
                            self.generate_trace_fixed_position(polarity, node.node_left, trace_position, trace_dict)

                    elif rand == 1:
                        result, trace_dict_new = \
                            self.generate_trace_fixed_position(polarity, node.node_right, trace_position, trace_dict)

                # elif polarity == 2:
                #     for i in range(0, trace_position + 1):
                #         result_1, trace_dict = self.generate_trace(1, node, i, trace_dict)
                #         result = result_1
                #         if not result_1:
                #             break

                elif polarity == 3 or polarity == 4:
                    result_1, trace_dict_new = \
                        self.generate_trace_fixed_position(polarity, node.node_left, trace_position, trace_dict)
                    if result_1:
                        result_2, trace_dict_new = \
                            self.generate_trace_fixed_position(polarity, node.node_right, trace_position,
                                                               trace_dict_new)
                        result = result_1 & result_2
                        if result_2:
                            trace_dict = trace_dict_new

            elif node.node_type == OPERATOR and node.node_value == NOT:

                if polarity == 1:
                    result, trace_dict_new = \
                        self.generate_trace_fixed_position(3, node.node_left, trace_position, trace_dict)

                elif polarity == 2:
                    result, trace_dict_new = \
                        self.generate_trace_fixed_position(4, node.node_left, trace_position, trace_dict)

                elif polarity == 3:
                    result, trace_dict_new = \
                        self.generate_trace_fixed_position(1, node.node_left, trace_position, trace_dict)

                else:
                    result, trace_dict_new = \
                        self.generate_trace_fixed_position(2, node.node_left, trace_position, trace_dict)

                if result:
                    trace_dict = trace_dict_new

            elif node.node_type == OPERATOR and node.node_value == IMPLIES:
                if polarity == 1:  # (p -> q) = !p | q
                    rand = random.randint(0, 1)
                    if rand == 0:
                        result, trace_dict_new = \
                            self.generate_trace_fixed_position(3, node.node_left, trace_position, trace_dict)
                    else:
                        result, trace_dict_new = \
                            self.generate_trace_fixed_position(polarity, node.node_right, trace_position, trace_dict)

                    if result:
                        trace_dict = trace_dict_new

                elif polarity == 2:  # from now until the next token, satisfy p -> q
                    rand = random.randint(0, 1)
                    if rand == 0:
                        result, trace_dict_new = \
                            self.generate_trace_fixed_position(4, node.node_left, trace_position, trace_dict)
                    else:
                        result, trace_dict_new = \
                            self.generate_trace_fixed_position(polarity, node.node_right, trace_position, trace_dict)

                    if result:
                        trace_dict = trace_dict_new

                elif polarity == 3:  # Issue? Check
                    result_1, trace_dict_new = \
                        self.generate_trace_fixed_position(1, node.node_left, trace_position, trace_dict)
                    if result_1:
                        result_2, trace_dict_new = \
                            self.generate_trace_fixed_position(polarity, node.node_right, trace_position,
                                                               trace_dict_new)
                        result = result_1 & result_2
                        if result:
                            trace_dict = trace_dict_new

                elif polarity == 4:  # from now until the next positive token, violate p -> q
                    result_1, trace_dict_new = \
                        self.generate_trace_fixed_position(2, node.node_left, trace_position, trace_dict)
                    if result_1:
                        result_2, trace_dict_new = \
                            self.generate_trace_fixed_position(polarity, node.node_right, trace_position,
                                                               trace_dict_new)
                        result = result_1 & result_2
                        if result:
                            trace_dict = trace_dict_new

            elif node.node_type == OPERATOR and node.node_value == SINCE:

                if polarity == 1:
                    if trace_position == 0:
                        result = False
                    else:
                        num_tries = 0
                        while not result and num_tries < 2 * trace_position + 1:
                            time_to_satisfy = random.randint(0, trace_position - 1)
                            result, trace_dict_new = self.generate_trace_fixed_position(polarity, node.node_right,
                                                                                        time_to_satisfy, trace_dict)
                            if result:
                                for i in range(time_to_satisfy + 1, trace_position):
                                    result_1, trace_dict_new = \
                                        self.generate_trace_fixed_position(2, node.node_left, i, trace_dict_new)
                                    result = result_1
                                    if not result_1:
                                        break
                            if result:
                                result, trace_dict_new = \
                                    self.generate_trace_fixed_position(1, node.node_left, trace_position,
                                                                       trace_dict_new)

                            if result:
                                trace_dict = trace_dict_new

                            num_tries += 1

                elif polarity == 2:  # from now until next token, satisfy p S q
                    if trace_position == 0:
                        result = False
                    else:
                        num_tries = 0
                        while not result and num_tries < 2 * trace_position + 1:
                            time_to_satisfy = random.randint(0, trace_position - 1)
                            result, trace_dict_new = self.generate_trace_fixed_position(polarity, node.node_right,
                                                                                        time_to_satisfy, trace_dict)
                            if result:
                                for i in range(time_to_satisfy + 1, trace_position + 1):
                                    result_1, trace_dict_new = \
                                        self.generate_trace_fixed_position(2, node.node_left, i, trace_dict_new)
                                    result = result_1
                                    if not result_1:
                                        break

                            if result:
                                trace_dict = trace_dict_new

                            num_tries += 1

                # !(p S q) = once q, then violate p once ; or never satisfy q
                elif polarity == 3:
                    rand = 1
                    if rand == 0:
                        trace_dict_new = trace_dict
                        for i in range(0, trace_position):
                            result_1, trace_dict_new = self.generate_trace_fixed_position(4, node.node_right, i,
                                                                                          trace_dict_new)
                            result = result_1
                            if not result_1:
                                break

                        if result:
                            result, trace_dict_new = \
                                self.generate_trace_fixed_position(3, node.node_right, trace_position, trace_dict_new)

                        if result:
                            trace_dict = trace_dict_new

                    else:
                        if trace_position > 0:
                            num_tries = 0
                            while not result and num_tries < 2 * trace_position + 1:
                                time_to_satisfy = random.randint(0, trace_position - 1)
                                result_1, trace_dict_new = self.generate_trace_fixed_position(1, node.node_right,
                                                                                              time_to_satisfy,
                                                                                              trace_dict)

                                if result_1:

                                    num_tries_violate = 0
                                    while not result and num_tries_violate < 2 * (trace_position - time_to_satisfy):
                                        time_to_violate = random.randint(time_to_satisfy + 1, trace_position)
                                        result, trace_dict_new_2 = \
                                            self.generate_trace_fixed_position(3, node.node_left, time_to_violate,
                                                                               trace_dict_new)

                                        if result:
                                            trace_dict = trace_dict_new_2

                                        num_tries_violate += 1

                                num_tries += 1
                        else:
                            result = False

                # from now until next positive token, violate p S q
                elif polarity == 4:
                    rand = random.randint(0, 1)
                    if rand == 0:
                        trace_dict_new = trace_dict
                        for i in range(0, trace_position + 1):
                            result_1, trace_dict_new = self.generate_trace_fixed_position(4, node.node_right, i,
                                                                                          trace_dict_new)
                            result = result_1
                            if not result_1:
                                break

                        if result:
                            trace_dict = trace_dict_new

                    else:
                        if trace_position > 0:
                            num_tries = 0
                            while not result and num_tries < 2 * trace_position + 1:
                                time_to_satisfy = random.randint(0, trace_position - 1)
                                result_1, trace_dict_new = self.generate_trace_fixed_position(1, node.node_right,
                                                                                              time_to_satisfy,
                                                                                              trace_dict)

                                if result_1:

                                    num_tries_violate = 0
                                    while not result and num_tries_violate < 2 * (trace_position - time_to_satisfy):
                                        time_to_violate = random.randint(time_to_satisfy + 1, trace_position)
                                        result, trace_dict_new_2 = \
                                            self.generate_trace_fixed_position(3, node.node_left, time_to_violate,
                                                                               trace_dict_new)

                                        if result:
                                            trace_dict = trace_dict_new_2

                                        num_tries_violate += 1

                                num_tries += 1
                        else:
                            result = False

            elif node.node_type == OPERATOR and node.node_value == YESTERDAY:
                # Y(p); H(Y(p)); !Y(p) = Y(!p); H(!Y(p)) = H(Y(!p))
                if trace_position > 0:
                    result, trace_dict_new = \
                        self.generate_trace_fixed_position(polarity, node.node_left, trace_position - 1, trace_dict)
                    if result:
                        trace_dict = trace_dict_new
                else:
                    if polarity == 1 or polarity == 2:
                        result = False
                    else:
                        result = True

            elif node.node_type == OPERATOR and node.node_value == ONCE:

                if polarity == 1:
                    num_tries = 0
                    while not result and num_tries < 2 * trace_position + 1:
                        time_to_satisfy = random.randint(0, trace_position)
                        result, trace_dict_new = self.generate_trace_fixed_position(polarity, node.node_left,
                                                                                    time_to_satisfy, trace_dict)

                        if result:
                            trace_dict = trace_dict_new

                        num_tries += 1

                elif polarity == 2:  # from now until next positive token, satisfy O(p)
                    num_tries = 0
                    while not result and num_tries < 2 * trace_position + 1:
                        time_to_satisfy = random.randint(0, trace_position)
                        result, trace_dict_new = self.generate_trace_fixed_position(polarity, node.node_left,
                                                                                    time_to_satisfy, trace_dict)

                        if result:
                            trace_dict = trace_dict_new

                        num_tries += 1

                elif polarity == 3:

                    trace_dict_new = trace_dict
                    for i in range(0, trace_position):
                        result_1, trace_dict_new = self.generate_trace_fixed_position(4, node.node_left, i,
                                                                                      trace_dict_new)
                        result = result_1
                        if not result_1:
                            break

                    if result:
                        result, trace_dict_new = \
                            self.generate_trace_fixed_position(3, node.node_left, trace_position, trace_dict_new)

                    if result:
                        trace_dict = trace_dict_new

                elif polarity == 4:
                    trace_dict_new = trace_dict
                    for i in range(0, trace_position + 1):
                        result_1, trace_dict_new = self.generate_trace_fixed_position(4, node.node_left, i,
                                                                                      trace_dict_new)
                        result = result_1
                        if not result_1:
                            break

                    if result:
                        trace_dict = trace_dict_new

            elif node.node_type == OPERATOR and node.node_value == HISTORICALLY:
                # H(p), H(H(p)), !H(p) = O(!p), H(!H(p)) = H(O(!p))
                if polarity == 1:
                    trace_dict_new = trace_dict
                    for i in range(0, trace_position):
                        result_1, trace_dict_new = self.generate_trace_fixed_position(2, node.node_left, i,
                                                                                      trace_dict_new)
                        result = result_1
                        if not result_1:
                            break

                    if result:
                        result, trace_dict_new = \
                            self.generate_trace_fixed_position(1, node.node_left, trace_position, trace_dict_new)

                    if result:
                        trace_dict = trace_dict_new

                elif polarity == 2:
                    trace_dict_new = trace_dict
                    for i in range(0, trace_position + 1):
                        result_1, trace_dict_new = self.generate_trace_fixed_position(2, node.node_left, i,
                                                                                      trace_dict_new)
                        result = result_1
                        if not result_1:
                            break

                    if result:
                        trace_dict = trace_dict_new

                elif polarity == 3:
                    num_tries = 0
                    while not result and num_tries < 2 * trace_position + 1:
                        time_to_violate = random.randint(0, trace_position)
                        result, trace_dict_new = self.generate_trace_fixed_position(polarity, node.node_left,
                                                                                    time_to_violate, trace_dict)

                        if result:
                            trace_dict = trace_dict_new

                        num_tries += 1

                elif polarity == 4:
                    num_tries = 0
                    while not result and num_tries < 2 * trace_position + 1:
                        time_to_violate = random.randint(0, trace_position)
                        result, trace_dict_new = self.generate_trace_fixed_position(polarity, node.node_left,
                                                                                    time_to_violate, trace_dict)

                        if result:
                            trace_dict = trace_dict_new

                        num_tries += 1

        return result, trace_dict


def create_qre_expressions(ltl_property_filename):
    delete_files_in_directory('qre_expressions')
    with open(os.path.join('ltl_properties', ltl_property_filename), 'r') as fr:
        lines = fr.readlines()
        for i, line in enumerate(lines):
            if "##" in line:
                ltl_property = line.split("##")[0].strip()
                p1_parameters = line.split("\n")[0].split("##")[1].strip()
                ltl_tree = Tree(ltl_property)
                qre_traces = ltl_tree.generate_skeletons(3, 10000, 50)

                with open(os.path.join('qre_expressions', ltl_property_filename.split('.')[0] + '_{}.txt'.format(i)),
                        'w') as fw:
                    for tr in qre_traces:
                        # print(tr)
                        fw.write(tr + " ## " + p1_parameters +"\n")


create_qre_expressions(ltl_property_filename)
