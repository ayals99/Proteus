import json
import os

all_messages = dict()
with open(os.path.join('considered_inputs_dir', 'message_fields_ble.txt'), 'r') as fr:
    lines = fr.readlines()
    in_message = False
    message_dict = dict()
    current_message_name = ""

    for line in lines:
        line = line.split("\n")[0].strip().split("//")[0].strip()
        if line.startswith("--"):
            message_name = line.split("--", 1)[1].strip()
            if current_message_name != "":
                all_messages[current_message_name] = message_dict.copy()

            message_dict = dict()
            current_message_name = message_name

        elif line.startswith("|"):
            if ":->" in line:
                field_name = line.split("|")[1].split(":->")[0].strip()
                field_values = []
                field_values_seq = line.split(":->")[1].strip()
                values = field_values_seq.split(",")
                for tok in values:
                    tok_s = tok.strip()
                    if "-" in tok_s:
                        start_val = int(tok_s.split("-")[0].strip())
                        end_val = int(tok_s.split("-")[1].strip())
                        for i in range(start_val, end_val+1):
                            field_values.append(i)
                    else:
                        val = int(tok_s.strip())
                        field_values.append(val)
                message_dict[field_name] = field_values

if current_message_name != "":
    all_messages[current_message_name] = message_dict.copy()

with open(os.path.join('considered_inputs_dir', 'message_fields_ble.json'), 'w') as fw:
    json.dump(all_messages, fw, indent=4)

