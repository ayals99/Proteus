import sqlite3
from typing import List


def create_table(device_name_str):
    conn = sqlite3.connect('database_dir/query_storage_{}.db'.format(device_name_str))
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS testcase_io_" + device_name_str + " (s1 TEXT,s2 TEXT)")
    conn.commit()
    conn.close()


def insert_data(s1_list, s2_list, device_name_str):
    sl1 = list_to_str(s1_list)
    sl2 = list_to_str(s2_list)
    conn = sqlite3.connect('database_dir/query_storage_{}.db'.format(device_name_str))
    cursor = conn.cursor()
    cursor.execute("INSERT INTO testcase_io_{} (s1, s2) VALUES (?, ?)".format(device_name_str), (sl1, sl2))
    conn.commit()
    conn.close()

def query_data(s1_list, device_name_str):
    sl1 = list_to_str(s1_list)
    conn = sqlite3.connect('database_dir/query_storage_{}.db'.format(device_name_str))
    cursor = conn.cursor()
    cursor.execute("SELECT s2 FROM testcase_io_{} WHERE s1 LIKE ?".format(device_name_str), (sl1 + "%",))
    rows = cursor.fetchall()
    conn.close()
    if len(rows) == 0:
        return False, []
    max_len_row = str_to_list(rows[-1][0])
    for row in rows:
        row_list = str_to_list(row[0])
        if len(row_list) > len(max_len_row):
            max_len_row = row_list
    list_val = max_len_row
    return True, list_val[:len(s1_list)]


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


def get_all_rows(device_name_str):
    conn = sqlite3.connect('database_dir/query_storage_{}.db'.format(device_name_str))
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM testcase_io_{}".format(device_name_str))
    rows = cursor.fetchall()
    print("Rows :: {}".format(rows))


def delete_table(device_name_str):
    conn = sqlite3.connect('database_dir/query_storage_{}.db'.format(device_name_str))
    cursor = conn.cursor()
    table_name = "testcase_io_{}".format(device_name_str)
    cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
    conn.commit()
    conn.close()
