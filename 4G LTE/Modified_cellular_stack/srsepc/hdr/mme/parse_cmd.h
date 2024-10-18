#pragma once

#ifndef PARSE_CMD_H
#define PARSE_CMD_H

#include <cstdint>
#include <vector>
#include <string>
#include "srsepc/hdr/mme/nas.h"

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
void handleMessageCmd(Message message, srsepc::nas* myNasInstance);



uint8_t *handleSecurityModeComplete(int nas_msg_container_IE);
uint8_t *handleAuthenticationFailure(int emm_cause);
uint8_t *handleAuthenticationResponse();
uint8_t *handleAttachRequest(int emergency); 
uint8_t *handleAttachComplete();
uint8_t *handleUlNasTransport();
uint8_t *handleGutiReallocationComplete();
uint8_t *handleEmmStatus();
uint8_t *handleDetachRequest();
uint8_t *handleDetachAccept();
uint8_t *handleSecurityModeReject(int emm_cause);

uint8_t *handleAttachRequestGUTI();
uint8_t *handleServiceRequest();
uint8_t *handleTauRequest();
uint8_t *handleAuthResponseRejected();
uint8_t *handleTauComplete();
uint8_t *handleEsmInfoResponse();
uint8_t *handleIdentityResponse();

uint8_t *handleNullAction();

uint8_t* handleRRCSecurityModeComplete();
uint8_t* handleRRCUECapInfo();
uint8_t* handleRRCReconfComplete();



#endif // PARSE_CMD_H