/*
 * vr_ksync_kernel.h -- ksync functions that need to be redefined to
 *                   be appropriate for unit testing in user space
 * 
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _VR_KSYNC_KERNEL_H_
#define _VR_KSYNC_KERNEL_H_

#include <windows_types.h>
#include <windows_ksync.h>

typedef struct _PairStatusInformation PairStatusInformation,
                                      *PPairStatusInformation;

struct _PairStatusInformation {
    NTSTATUS Status;
    ULONG Information;
};

#define NLA_DATA(nla)   ((char *)nla + NLA_HDRLEN)
#define NLA_LEN(nla)    (nla->nla_len - NLA_HDRLEN)

extern ULONG KsyncAllocationTag;

PKSYNC_RESPONSE
KsyncResponseCreate();

VOID
KsyncAppendResponse(PKSYNC_DEVICE_CONTEXT ctx, PKSYNC_RESPONSE resp);

NTSTATUS
KsyncHandleWrite(PKSYNC_DEVICE_CONTEXT ctx,
                 uint8_t *buffer,
                 size_t buffer_size);

#endif // _VR_KSYNC_KERNEL_H_