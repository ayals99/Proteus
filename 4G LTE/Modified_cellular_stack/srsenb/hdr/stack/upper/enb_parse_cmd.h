#pragma once

#ifndef ENB_PARSE_CMD_H
#define ENB_PARSE_CMD_H

#include <cstdint>
#include <vector>
#include <string>
// #include "srsepc/hdr/mme/nas.h"
namespace enb {
    typedef struct {
        char messageFieldName[50];
        int messageFieldValue;
    } MessageField;

    typedef struct {
        char messageName[256];
        MessageField messageFields[10];
        int numberOfFields;
    } Message;

    Message parseMessage(const uint8_t *data, size_t length);
    void printMessage(const Message& message);
    // void handleMessageCmd(Message message, srsepc::nas* myNasInstance);


    uint8_t *handleNullAction();

    uint8_t* handleRRCSecurityModeComplete();
    uint8_t* handleRRCUECapInfo();
    uint8_t* handleCounterCheckResponse();
    uint8_t* handleRRCSecurityModeComplete();
    uint8_t* handleUEInformationResponse();
    uint8_t* handleRRCReconfComplete();
    uint8_t* handleRRCSecurityModeFailure();
}

#endif // ENB_PARSE_CMD_H