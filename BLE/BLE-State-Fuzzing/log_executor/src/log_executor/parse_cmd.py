class MessageField:
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __repr__(self):
        return f"{self.name}={self.value}"

class Message:
    def __init__(self, name, fields=None):
        self.name = name
        self.fields = fields if fields is not None else []

    def __repr__(self):
        fields_str = ', '.join(map(str, self.fields))
        return f"{self.name}: {fields_str}"


def parse_cmd(cmd_str):
    cmd_str = cmd_str.strip()
    
    if cmd_str == "RESET":
        return Message("RESET")
    
    if ':' not in cmd_str:
        print("Format error!!!")
        exit(1)
    
    message_name, fields_str = cmd_str.split(':', 1)
    fields_str = fields_str.strip()
    
    if not fields_str:
        return Message(message_name)
    
    fields = [field.split('==') for field in fields_str.split('&')]
    
    if not all(len(field) == 2 for field in fields):
        print("Format error!!!")
        exit(1)
    
    message_fields = [MessageField(name, int(value)) for name, value in fields]
    return Message(message_name, message_fields)



# Example usage:
cmd_str = "version_req :ll_version==1&hh_version==2\n"
message = parse_cmd(cmd_str)
print(message.fields[0].name)
print(message.fields[0].value)
# print("Message Name:", message.name)
# for field in message.fields:
#     print("Field Name:", field.name, "Value:", field.value)