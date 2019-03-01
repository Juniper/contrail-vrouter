/*
 * ksync_response.h
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __KSYNC_RESPONSE_H__
#define __KSYNC_RESPONSE_H__

#include <windows_types.h>

#define KSYNC_MAX_BUFFER_SIZE 4096

typedef struct _KSYNC_RESPONSE KSYNC_RESPONSE;
typedef struct _KSYNC_RESPONSE *PKSYNC_RESPONSE;
struct _KSYNC_RESPONSE {
    PKSYNC_RESPONSE next;
    size_t message_len;
    uint8_t buffer[KSYNC_MAX_BUFFER_SIZE];
};

PKSYNC_RESPONSE KsyncResponseCreate();

VOID KsyncResponseDelete(PKSYNC_RESPONSE resp);

#endif // __KSYNC_RESPONSE_H__
