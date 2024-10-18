// //
// // Created by ishtiaq on 9/19/23.
// //

#include "srsepc/hdr/mme/nas.h"
// message_parser.cc

#include "srsepc/hdr/mme/parse_cmd.h"
#include <string>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <algorithm>

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

void handleMessageCmd(Message message, srsepc::nas* myNasInstance){
    bool ret = false;
    if(strcmp(message.messageName, "authentication_request") == 0){
        int cipher = 0;
        int integrity = 0;
        int replay = 0;
        int separation_bit = 1;
        int sqn = 0;
        int security_header_type = 0;

        

        for(int i=0; i<message.numberOfFields; i++){
            if (strcmp(message.messageFields[i].messageFieldName, "cipher") == 0) {
                cipher = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "integrity") == 0){
                integrity =  message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "replay") == 0){
                replay =  message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "separation_bit") == 0){
                separation_bit =  message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "sqn") == 0){
                sqn =  message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "security_header_type") == 0){
                security_header_type =  message.messageFields[i].messageFieldValue;
                if (security_header_type == 4) {
                    security_header_type = 5 + rand()%11;
                }
            }
        }
        std::cout << "cipher: " << cipher << std::endl;
        std::cout << "integrity: " << integrity << std::endl;
        std::cout << "replay: " << replay << std::endl;
        std::cout << "separation_bit: " << separation_bit << std::endl;
        std::cout << "sqn: " << sqn << std::endl;
        std::cout << "security_header_type: " << security_header_type << std::endl;

        ret = myNasInstance->handle_statelearner_query_authentication_request_custom(integrity, integrity, replay, separation_bit, sqn, security_header_type);
    }
     else if(strcmp(message.messageName, "auth_request_plain_text") == 0){
        ret = myNasInstance->handle_statelearner_query_authentication_request();
    }
    else if(strcmp(message.messageName, "identity_request") == 0){
        int cipher = 0;
        int integrity = 0;
        int replay = 0;
        int identity_type = 1;
        int security_header_type = 0;
 

        for(int i=0; i<message.numberOfFields; i++){
            if(strcmp(message.messageFields[i].messageFieldName, "cipher") == 0){
                cipher = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "integrity") == 0){
                integrity = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "replay") == 0){
                replay = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "identity_type") == 0){
                identity_type = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "security_header_type") == 0){
                security_header_type = message.messageFields[i].messageFieldValue;
                if (security_header_type == 4) {
                    security_header_type = 5 + rand()%11;
                }
            }
        }

        ret = myNasInstance->handle_statelearner_query_identity_request_custom(cipher, integrity, replay, identity_type, security_header_type);
    }
    else if(strcmp(message.messageName, "security_mode_command") == 0){
        int cipher = 0;
        int integrity = 1;
        int replay = 0;
        int auth_parameter = 1;
        int EIA = 1;
        int EEA = 1;
        int security_header_type = 3;
 

        for(int i=0; i<message.numberOfFields; i++){
            if(strcmp(message.messageFields[i].messageFieldName, "cipher") == 0){
                cipher = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "integrity") == 0){
                integrity = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "replay") == 0){
                replay = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "auth_parameter") == 0){
                auth_parameter = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "EIA") == 0){
                EIA = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "EEA") == 0){
                EEA = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "security_header_type") == 0){
                security_header_type = message.messageFields[i].messageFieldValue;
                if (security_header_type == 4) {
                    security_header_type = 5 + rand()%11;
                }
            }
        }

        ret = myNasInstance->handle_statelearner_query_security_mode_command_custom(cipher, integrity, replay, auth_parameter, EIA, EEA, security_header_type);
    }
    else if(strcmp(message.messageName, "attach_accept") == 0){
        int cipher = 1;
        int integrity = 1;
        int replay = 0;
        int security_header_type = 2;

        printf("received attach_accept!\n");
 

        for(int i=0; i<message.numberOfFields; i++){
            if(strcmp(message.messageFields[i].messageFieldName, "cipher") == 0){
                cipher = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "integrity") == 0){
                integrity = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "replay") == 0){
                replay = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "security_header_type") == 0){
                security_header_type = message.messageFields[i].messageFieldValue;
                if (security_header_type == 4) {
                    security_header_type = 5 + rand()%11;
                }       
            }
        }

       ret = myNasInstance->handle_statelearner_query_attach_accept_custom(cipher, integrity, replay, security_header_type);
    }
    else if(strcmp(message.messageName, "GUTI_reallocation") == 0){
        int cipher = 1;
        int integrity = 1;
        int replay = 0;
        int security_header_type = 2;
 

        for(int i=0; i<message.numberOfFields; i++){
            if(strcmp(message.messageFields[i].messageFieldName, "cipher") == 0){
                cipher = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "integrity") == 0){
                integrity = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "replay") == 0){
                replay = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "security_header_type") == 0){
                security_header_type = message.messageFields[i].messageFieldValue;
                if (security_header_type == 4) {
                    security_header_type = 5 + rand()%11;
                }
            }
        }

        ret = myNasInstance->handle_statelearner_query_guti_rellocation_custom(cipher, integrity, replay, security_header_type);
    }
    else if(strcmp(message.messageName, "dl_nas_transport") == 0){
        int cipher = 1;
        int integrity = 1;
        int replay = 0;
        int security_header_type = 2;
 

        for(int i=0; i<message.numberOfFields; i++){
            if(strcmp(message.messageFields[i].messageFieldName, "cipher") == 0){
                cipher = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "integrity") == 0){
                integrity = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "replay") == 0){
                replay = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "security_header_type") == 0){
                security_header_type = message.messageFields[i].messageFieldValue;
                if (security_header_type == 4) {
                    security_header_type = 5 + rand()%11;
                }
            }
        }
        if(cipher == -1 || integrity == -1 || replay == -1 || security_header_type == -1){
            printf("Undefined value!!!\n");
            exit(1);
        }
        ret = myNasInstance->handle_statelearner_query_dl_nas_transport_custom(cipher, integrity, replay, security_header_type);
    }
    else if(strcmp(message.messageName, "service_reject") == 0){
        int emm_cause = 10; //LIBLTE_MME_EMM_CAUSE_IMPLICITLY_DETACHED
        int security_header_type = 0;
 

        for(int i=0; i<message.numberOfFields; i++){
            if(strcmp(message.messageFields[i].messageFieldName, "emm_cause") == 0){
                emm_cause = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "security_header_type") == 0){
                security_header_type = message.messageFields[i].messageFieldValue;
                if (security_header_type == 4) {
                    security_header_type = 5 + rand()%11;
                }
            }
        }

        ret = myNasInstance->handle_statelearner_query_service_reject_custom(emm_cause, security_header_type);
    }
    else if(strcmp(message.messageName, "attach_reject") == 0){
        int emm_cause = 11;  //LIBLTE_MME_EMM_CAUSE_PLMN_NOT_ALLOWED

 
        for(int i=0; i<message.numberOfFields; i++){
            if(strcmp(message.messageFields[i].messageFieldName, "emm_cause") == 0){
                emm_cause = message.messageFields[i].messageFieldValue;
            }
        }

        ret = myNasInstance->handle_statelearner_query_attach_reject_custom(emm_cause);
    }
    else if(strcmp(message.messageName, "auth_reject") == 0){

        ret = myNasInstance->handle_statelearner_query_authentication_reject_custom();

    }
    else if(strcmp(message.messageName, "emm_information") == 0){

        ret = myNasInstance->handle_statelearner_query_emm_information();

    }
    else if(strcmp(message.messageName, "detach_request") == 0){
        int integrity = 1;
        int cipher = 1;
        int reattach_required = -1;
        int security_header_type = 2;
        int emm_cause = -1;
 

        for(int i=0; i<message.numberOfFields; i++){
            if(strcmp(message.messageFields[i].messageFieldName, "integrity") == 0){
                integrity = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "cipher") == 0){
                cipher = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "reattach_required") == 0){
                reattach_required = message.messageFields[i].messageFieldValue;
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "security_header_type") == 0){
                security_header_type = message.messageFields[i].messageFieldValue;
                printf("detach_request: security_header_type: %d\n", security_header_type);
                if (security_header_type == 4) {
                    security_header_type = 5 + rand()%11;
                }
            }
            else if(strcmp(message.messageFields[i].messageFieldName, "emm_cause") == 0){
                emm_cause = message.messageFields[i].messageFieldValue;
            }
        }
        myNasInstance->handle_statelearner_query_detach_request_custom(integrity, cipher,  security_header_type);
    }
    else if(strcmp(message.messageName, "wait") == 0){

       int time = 10;
      
 

        for(int i=0; i<message.numberOfFields; i++){
            if(strcmp(message.messageFields[i].messageFieldName, "time") == 0){
                time = message.messageFields[i].messageFieldValue;
            }
        }

        printf("Waiting for %d minutes\n", time);
        sleep(60*time);
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


uint8_t* handleSecurityModeComplete(int nas_msg_container_IE){
    uint8_t* message = constructMessage("security_mode_complete", nullptr, 0);
    std::cout << message << std::endl;
    return message;
    // int numberOfFields = 1;
    // MessageField fields[1];
    // strcpy(fields[0].messageFieldName, "nas_msg_container_IE");
    // fields[0].messageFieldValue = nas_msg_container_IE;
    // uint8_t* message = constructMessage("security_mode_complete", fields, numberOfFields);
    // std::cout << message << std::endl;
    // return message;  // delete[] message;
}


uint8_t* handleAuthenticationFailure(int emm_cause){
    int numberOfFields = 1;
    MessageField fields[1];
    strcpy(fields[0].messageFieldName, "emm_cause");
    fields[0].messageFieldValue = emm_cause;
    uint8_t* message = constructMessage("authentication_failure", fields, numberOfFields);
    std::cout << message << std::endl;
    return message;  // delete[] message;
}


uint8_t* handleAuthenticationResponse(){
    uint8_t* message = constructMessage("authentication_response", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}


uint8_t* handleAttachRequest(int emergency){

    uint8_t* message = constructMessage("attach_request", nullptr, 0);
    std::cout << message << std::endl;
    return message;
    // int numberOfFields = 1;
    // MessageField fields[1];
    // strcpy(fields[0].messageFieldName, "emergency");
    // fields[0].messageFieldValue = emergency;
    // uint8_t* message = constructMessage("attach_request", fields, numberOfFields);
    // std::cout << message << std::endl;
    // return message;
}

uint8_t* handleAttachComplete(){
    uint8_t* message = constructMessage("attach_complete", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t *handleUlNasTransport(){
    uint8_t* message = constructMessage("ul_nas_transport", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t *handleGutiReallocationComplete(){
    uint8_t* message = constructMessage("GUTI_reallocation_complete", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t *handleEmmStatus(){
    uint8_t* message = constructMessage("emm_status", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t *handleDetachRequest(){
    uint8_t* message = constructMessage("detach_request", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t *handleDetachAccept(){
    uint8_t* message = constructMessage("detach_accept", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleSecurityModeReject(int emm_cause){
    int numberOfFields = 1;
    MessageField fields[1];
    strcpy(fields[0].messageFieldName, "emm_cause");
    fields[0].messageFieldValue = emm_cause;
    uint8_t* message = constructMessage("security_mode_reject", fields, numberOfFields);
    std::cout << message << std::endl;
    return message;  // delete[] message;
}

uint8_t* handleAttachRequestGUTI(){
    uint8_t* message = constructMessage("attach_request_guti", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleServiceRequest(){
    uint8_t* message = constructMessage("service_request", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleTauRequest(){
    uint8_t* message = constructMessage("tau_request", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleAuthResponseRejected(){
    uint8_t* message = constructMessage("auth_response_rejected", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleTauComplete(){
    uint8_t* message = constructMessage("tau_complete", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleEsmInfoResponse(){
    uint8_t* message = constructMessage("esm_info_request", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleIdentityResponse(){
    uint8_t* message = constructMessage("identity_response", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleNullAction(){
    uint8_t* message = constructMessage("null_action", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}



uint8_t* handleRRCSecurityModeComplete(){
    uint8_t* message = constructMessage("rrc_security_mode_complete", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleRRCUECapInfo(){
    uint8_t* message = constructMessage("rrc_ue_cap_info", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

uint8_t* handleRRCReconfComplete(){
    uint8_t* message = constructMessage("rrc_reconf_complete", nullptr, 0);
    std::cout << message << std::endl;
    return message;
}

