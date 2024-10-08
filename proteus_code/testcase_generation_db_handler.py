import os
import sqlite3
from typing import List


def list_to_str(s1: List[str]):
    s1_str = ""
    for i in range(len(s1)):
        s1_str += s1[i]
        if i != len(s1) - 1:
            s1_str += "####"
    return s1_str


def str_to_list(s1: str):
    sym_list = s1.split("####")
    return sym_list


def create_table_mutation_info():
    if not os.path.exists('testcase_generator_db_dir'):
        os.mkdir('testcase_generator_db_dir')

    if os.path.exists(os.path.join('testcase_generator_db_dir', 'working_mutations.db')):
        os.remove(os.path.join('testcase_generator_db_dir', 'working_mutations.db'))

    conn = sqlite3.connect(os.path.join('testcase_generator_db_dir', 'working_mutations.db'))
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS mutation_table (s1 TEXT,s2 TEXT,s3 TEXT)")
    conn.commit()
    conn.close()


def insert_data_mutation_info(input_message, mutated_message, mutated_msg_prob):
    conn = sqlite3.connect(os.path.join('testcase_generator_db_dir', 'working_mutations.db'))
    cursor = conn.cursor()
    cursor.execute("INSERT INTO mutation_table (s1, s2, s3) VALUES (?, ?, ?)", (input_message,
                                                                                mutated_message, mutated_msg_prob))
    conn.commit()
    conn.close()


def query_mutation_info(input_message):
    conn = sqlite3.connect(os.path.join('testcase_generator_db_dir', 'working_mutations.db'))
    cursor = conn.cursor()
    cursor.execute("SELECT s2, s3 FROM mutation_table WHERE (s1 = ?)",
                   (input_message, ))
    rows = cursor.fetchall()
    conn.close()
    if len(rows) == 0:
        return False, []
    vals = [[row[0], row[1]] for row in rows]

    new_vals = list()
    for i in range(len(vals)):
        found = False
        for j in range(len(vals)):
            if i != j:
                if vals[i][0] == vals[j][0]:
                    found = True
                    break
            else:
                continue
        if not found:
            new_vals.append(vals[i])

    return True, new_vals


def create_db_non_working_prefixes(device_name):
    if not os.path.exists('testcase_generator_db_dir'):
        os.mkdir('testcase_generator_db_dir')

    conn = sqlite3.connect(os.path.join('testcase_generator_db_dir', 'non_working_prefixes_{}.db'.format(device_name)))
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS prefixes (s1 TEXT, s2 TEXT)')
    conn.commit()
    return conn


def insert_data_prefix(input_list, output_list, device_name):
    input_prefix = list_to_str(input_list)
    output_prefix = list_to_str(output_list)

    conn = sqlite3.connect(os.path.join('testcase_generator_db_dir', 'non_working_prefixes_{}.db'.format(device_name)))
    cursor = conn.cursor()
    cursor.execute('INSERT INTO prefixes (s1, s2) VALUES (?, ?)', (input_prefix, output_prefix))
    conn.commit()


def query_data_prefix(input_list, output_list, device_name):
    input_string = list_to_str(input_list)
    output_string = list_to_str(output_list)

    conn = sqlite3.connect(os.path.join('testcase_generator_db_dir', 'non_working_prefixes_{}.db'.format(device_name)))
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM prefixes WHERE (? LIKE (s1 || '%') AND ? LIKE (s2 || '%'))", (input_string,
                                                                                                output_string))

    rows = cursor.fetchall()
    print(rows)
    if len(rows) != 0:
        return True
    return False
    #  cursor.fetchone() is not None
