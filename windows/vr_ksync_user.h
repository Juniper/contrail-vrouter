/*
 * vr_ksync_user.h -- ksync functions that can be used in user space
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _VR_KSYNC_USER_H_
#define _VR_KSYNC_USER_H_

#include "vr_ksync_kernel.h"

PKSYNC_DEVICE_CONTEXT
KSyncAllocContext();

VOID
KsyncContextResetWriteBuffer(PKSYNC_DEVICE_CONTEXT ctx);

VOID
KsyncCopyUserBufferToContext(PKSYNC_DEVICE_CONTEXT ctx,
                             ULONG bytesNeeded,
                             PCHAR *userBuffer,
                             ULONG *userBufferSize,
                             ULONG *writtenBytes);

PairStatusInformation
KsyncParseAndHandleWrite(PKSYNC_DEVICE_CONTEXT ctx,
                         PCHAR userBuffer,
                         ULONG userBufferSize);

#endif // _VR_KSYNC_USER_H_
