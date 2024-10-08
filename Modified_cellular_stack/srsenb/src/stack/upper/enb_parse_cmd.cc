// message_parser.cc
#include "srsenb/hdr/stack/upper/enb_parse_cmd.h"
#include <string>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <algorithm>

namespace enb {

Message parseMessage(const uint8_t *data, size_t length) {
    Message message = {};  // Zero-initialize the struct
    std::string input(data, data + length);  // Convert uint8_t* to std::string
    std::stringstream ss(input);

    // Parse the message name
    std::string temp;
    std::getline(ss, temp, ':');
    if (ss.fail() || temp.empty()) {
        std::cerr << "Debug: Missing ':' or message name." << std::endl;
        return message;  // Return an empty message
    }

    strncpy(message.messageName, temp.c_str(), sizeof(message.messageName) - 1);  // Copy message name with safety

    // If the right side is missing or only contains spaces, just return the message with the name
    if (ss.peek() == EOF || std::all_of(std::istreambuf_iterator<char>(ss), std::istreambuf_iterator<char>(), ::isspace)) {
        return message;  // Return message with only the name
    }

    // Parse each field-value pair
    std::string fieldStr;
    while (std::getline(ss, fieldStr, '&') && message.numberOfFields < 10) {
        MessageField field = {};  // Zero-initialize
        
        // Clean up spaces
        fieldStr = fieldStr.substr(fieldStr.find_first_not_of(' '), fieldStr.find_last_not_of(' ') - fieldStr.find_first_not_of(' ') + 1);

        // Split the fieldStr into name and value using "==" as delimiter
        size_t delimiterPos = fieldStr.find("==");
        if (delimiterPos == std::string::npos) {
            std::cerr << "Debug: Missing '==' in field definition: " << fieldStr << std::endl;
            continue;  // Skip this field and continue with the next
        }
        // Extract and trim field name and value
        std::string fieldName = fieldStr.substr(0, delimiterPos);
        fieldName = fieldName.substr(fieldName.find_first_not_of(' '), fieldName.find_last_not_of(' ') - fieldName.find_first_not_of(' ') + 1);
        strncpy(field.messageFieldName, fieldName.c_str(), sizeof(field.messageFieldName) - 1);  // Copy field name with safety

        std::string valueStr = fieldStr.substr(delimiterPos + 2);
        field.messageFieldValue = std::stoi(valueStr.substr(valueStr.find_first_not_of(' ')));

        message.messageFields[message.numberOfFields] = field;
        message.numberOfFields++;
    }
    return message;
}

void printMessage(const Message& message) {
    std::cout << "Message Name: " << message.messageName << std::endl;
    
    for (int i = 0; i < message.numberOfFields; i++) {
        std::cout << "\tField Name: " << message.messageFields[i].messageFieldName 
                  << " Value: " << message.messageFields[i].messageFieldValue << std::endl;
    }
}

uint8_t* constructMessage(const char* messageName, const MessageField* fields, int numFields) {
    std::ostringstream oss;
    oss << messageName << ":";

    if (fields && numFields > 0) {
        for (int i = 0; i < numFields; ++i) {
            oss << " " << fields[i].messageFieldName << " == " << fields[i].messageFieldValue;
            if (i != numFields - 1) {  // not the last field
                oss << " &";
            }
        }
    }
    
    std::string resultStr = oss.str();
    uint8_t* result = new uint8_t[resultStr.length() + 1];  // +1 for null terminator
    std::copy(resultStr.begin(), resultStr.end(), result);
    result[resultStr.length()] = '\0';  // null-terminate

    return result;
}

uint8_t* handleNullAction() {
    uint8_t* message = constructMessage("null_action", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleRRCSecurityModeComplete() {
    uint8_t* message = constructMessage("rrc_security_mode_complete", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleRRCUECapInfo() {
    uint8_t* message = constructMessage("rrc_ue_cap_info", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleCounterCheckResponse() {
    uint8_t* message = constructMessage("counter_check_response", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleUEInformationResponse() {
    uint8_t* message = constructMessage("ue_information_response", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleRRCReconfComplete() {
    uint8_t* message = constructMessage("rrc_reconf_complete", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleRRCSecurityModeFailure() {
    uint8_t* message = constructMessage("rrc_security_mode_failure", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

} // namespace enb