/*
 * vr_ksync_user.h -- ksync functions that can be used in user space
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _VR_KSYNC_USER_H_
#define _VR_KSYNC_USER_H_

#include "ksync_device_context.h"

typedef struct _PairStatusInformation {
    NTSTATUS Status;
    ULONG Information;
} PairStatusInformation, *PPairStatusInformation;

PairStatusInformation KsyncParseAndHandleWrite(PKSYNC_DEVICE_CONTEXT ctx,
                                               PCHAR userBuffer,
                                               ULONG userBufferSize);

#endif // _VR_KSYNC_USER_H_
