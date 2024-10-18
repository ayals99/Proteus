from __future__ import print_function, division, unicode_literals
import sys
import subprocess
class MessageField:
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __repr__(self):
        return u"{}={}".format(self.name, self.value)

class Message:
    def __init__(self, name, fields=None):
        self.name = name
        self.fields = fields if fields is not None else []

    def __repr__(self):
        fields_str = ', '.join(map(unicode, self.fields))
        return u"{}: {}".format(self.name, fields_str)

def parse_cmd(cmd_str):
    try:
        cmd_str = cmd_str.strip()
        
        if cmd_str == "RESET":
            return Message("RESET")
        
        if ':' not in cmd_str:
            print("Format error!!!")
            unknown_message = Message(name="unknown")
            return unknown_message
            sys.exit(1)
        
        message_name, fields_str = cmd_str.split(':', 1)
        fields_str = fields_str.strip()
        
        if not fields_str:
            return Message(message_name)
        
        fields = [field.strip().split('==') for field in fields_str.split('&')]
        fields = [(name.strip(), value.strip()) for name, value in fields]
        
        if not all(len(field) == 2 for field in fields):
            print("Format error!!!")
            sys.exit(1)
        
        message_fields = [MessageField(name, int(value)) for name, value in fields]
        return Message(message_name, message_fields)
    except Exception as e:
        print(e)
        print("wrong concatenation!!!")
        #create a new message with name unknown
        unknown_message = Message(name="unknown")
        return unknown_message

