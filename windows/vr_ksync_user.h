/*
 * vr_ksync_user.h -- ksync functions that can be used in user space
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _VR_KSYNC_USER_H_
#define _VR_KSYNC_USER_H_

#include "ksync/ksync_device_context.h"

typedef struct _RESULT_STATUS_INFO RESULT_STATUS_INFO;
typedef struct _RESULT_STATUS_INFO *PRESULT_STATUS_INFO;
struct _RESULT_STATUS_INFO {
    NTSTATUS Status;
    ULONG Information;
};

RESULT_STATUS_INFO KsyncParseAndHandleWrite(PKSYNC_DEVICE_CONTEXT ctx,
                                            PCHAR userBuffer,
                                            ULONG userBufferSize);

#endif // _VR_KSYNC_USER_H_
