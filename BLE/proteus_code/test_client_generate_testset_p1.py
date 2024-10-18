import os

from testcase_sequence_dump_generator import generate_testcase_dump
from property_probability_assignment import calculate_probability_for_properties

rfsm_filename = 'reference_fsm/ble_rfsm_fuzzing_v3.dot'
considered_interesting_input_filename = 'considered_inputs_dir/considered_inputs_ble.txt'
max_testcase_per_property = 10000
mutation_budget = 1
length_budget = 7


def delete_files_in_directory(directory):
    if not os.path.exists(directory):
        os.mkdir(directory)
        return
    files = os.listdir(directory)

    for file in files:
        file_path = os.path.join(directory, file)
        if os.path.isfile(file_path):
            os.remove(file_path)
            # print("Deleted:", file_path)


def run_tests(input_rfsm_filename):
    delete_files_in_directory('testcases_dump')
    delete_files_in_directory('deviating_testcases')
    delete_files_in_directory('passed_testcases')
    delete_files_in_directory('unresponsive_testcases')

    # create_qre_expressions(input_property_filename)
    qre_files = os.listdir('qre_expressions')
    for qre_exp_file in qre_files:

        if "_p" in qre_exp_file:
            continue

        with open(os.path.join('qre_expressions', qre_exp_file), 'r') as fr:
            lines = fr.readlines()
            for i, line in enumerate(lines):
                if "##" in line:
                    qre_exp_part = line.split('##')[0]
                    print(qre_exp_part)
                    param_part = line.split('##')[1].split("\n")[0].strip()
                    mutation_budget_for_exp = int(param_part.split(" ")[0].strip())
                    length_budget_for_exp = int(param_part.split(" ")[1].strip())
                    print(mutation_budget_for_exp, length_budget_for_exp)
                    qre_exp = qre_exp_part
                    testcase_dump_filename = '{}_{}.txt'.format(qre_exp_file.split('.')[0], i)
                    generate_testcase_dump(testcase_dump_filename,
                                           input_rfsm_filename,
                                           qre_exp,
                                           mutation_budget_for_exp,
                                           length_budget_for_exp)

    calculate_probability_for_properties()


run_tests(rfsm_filename)
