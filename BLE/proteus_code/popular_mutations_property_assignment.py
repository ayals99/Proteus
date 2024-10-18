import math
import os.path
from pprint import pprint
from testcase_sequence_dump_generator import extract_message_and_fields
import math


def entropy(probabilities):
    entropy_value = 0
    for prob in probabilities:
        if prob != 0:  # Ignore zero probabilities to avoid logarithm of zero
            entropy_value -= prob * math.log2(prob)
    return entropy_value


def field_wise_probability(all_symbols_msg, symbol_field_val_list, field_probability_dict_msg):
    if len(symbol_field_val_list) == 0:
        return 1.0

    curr_field = symbol_field_val_list[0][0]
    curr_field_symbol_val = symbol_field_val_list[0][1]
    field_val_probabilities_dict = field_probability_dict_msg[curr_field]
    num_vals = len(field_val_probabilities_dict.keys())
    max_prob = (1 / float(num_vals) + 1) / 2

    p_sum = 0
    for k, v in field_val_probabilities_dict.items():
        v = min(max_prob, v)
        field_val_probabilities_dict[k] = v
        p_sum += v

    for k, v in field_val_probabilities_dict.items():
        field_val_probabilities_dict[k] = v / p_sum

    curr_field_val_prob = field_val_probabilities_dict[curr_field_symbol_val]

    new_all_sym_msg = list()
    for new_sym in all_symbols_msg:
        if curr_field + " == " + curr_field_symbol_val in new_sym:
            new_all_sym_msg.append(new_sym)

    new_field_count_dict = dict()
    for symbol_ in new_all_sym_msg:
        msg_part_, field_part_ = extract_message_and_fields(symbol_)
        fields_and_values_ = field_part_.split("&")
        fields_ = [f.split("==")[0].strip() for f in fields_and_values_]
        values_ = [f.split("==")[1].strip() for f in fields_and_values_]
        for f, v in zip(fields_, values_):
            if f in new_field_count_dict.keys():
                if v in new_field_count_dict[f].keys():
                    new_field_count_dict[f][v] += 1
                else:
                    new_field_count_dict[f][v] = 1
            else:
                new_field_count_dict[f] = dict()
                new_field_count_dict[f][v] = 1

    for field_, value_dict_ in new_field_count_dict.items():
        c_sum_ = 0
        for val_, count_ in value_dict_.items():
            c_sum_ += count_
        for val_, count_ in value_dict_.items():
            value_dict_[val_] /= c_sum_

    return curr_field_val_prob * field_wise_probability(new_all_sym_msg,
                                                        symbol_field_val_list[1:], new_field_count_dict)


def calculate_mutation_probabilities():
    symbols_per_message = dict()
    with open(os.path.join('considered_inputs_dir', 'popular_mutations.txt'), 'r') as fr:
        lines = fr.readlines()
        for line in lines:
            if ":" in line:
                symbol = line.split("\n")[0].strip()
                msg_part, _ = extract_message_and_fields(symbol)
                symbols_per_message.setdefault(msg_part.strip(), []).append(symbol)

    msg_per_field_probability_dict = dict()

    symbol_probability_dict = dict()

    for msg, symbols in symbols_per_message.items():
        field_count_dict = dict()
        for symbol in symbols:
            msg_part, field_part = extract_message_and_fields(symbol)
            fields_and_values = field_part.split("&")
            if "==" in fields_and_values[0]:
                fields = [f.split("==")[0].strip() for f in fields_and_values]
                values = [f.split("==")[1].strip() for f in fields_and_values]
                for f, v in zip(fields, values):
                    if f in field_count_dict.keys():
                        if v in field_count_dict[f].keys():
                            field_count_dict[f][v] += 1
                        else:
                            field_count_dict[f][v] = 1
                    else:
                        field_count_dict[f] = dict()
                        field_count_dict[f][v] = 1

        for field, value_dict in field_count_dict.items():
            c_sum = 0
            for val, count in value_dict.items():
                c_sum += count
            for val, count in value_dict.items():
                value_dict[val] /= c_sum

        # pprint(field_count_dict)
        field_entropy_list = list()

        for field, value_dict in field_count_dict.items():
            count_list = list()
            for val, count in value_dict.items():
                count_list.append(count)
            e = entropy(count_list)
            field_entropy_list.append([field, e])

        field_order = list()
        for field_e in sorted(field_entropy_list, key=lambda x: x[1]):
            field_order.append(field_e[0])

        for symbol in symbols:
            msg_part, field_part = extract_message_and_fields(symbol)
            fields_and_values = field_part.split("&")
            if "==" in fields_and_values[0]:
                fields = [f.split("==")[0].strip() for f in fields_and_values]
                values = [f.split("==")[1].strip() for f in fields_and_values]

                entropy_ordered_field_vals_symbol = list()

                for curr_f in field_order:
                    for i in range(len(fields)):
                        if fields[i] == curr_f:
                            entropy_ordered_field_vals_symbol.append([curr_f, values[i]])

                symbol_prob = field_wise_probability(symbols, entropy_ordered_field_vals_symbol, field_count_dict)
                symbol_probability_dict[symbol] = symbol_prob
            else:
                symbol_probability_dict[symbol] = 1.0

    with open(os.path.join('considered_inputs_dir', 'popular_mutations_with_probabilities.txt'), 'w') as fw:
        for symbol, prob in symbol_probability_dict.items():
            fw.write("{} ## {}\n".format(symbol, prob))
