/* 
 * ksync_response.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#include "ksync_response.h"
#include "win_memory.h"
#include "win_assert.h"

ULONG KsyncAllocationTag = 'NYSK';

PKSYNC_RESPONSE
KsyncResponseCreate()
{
    PKSYNC_RESPONSE resp;

    resp = WinRawAllocateWithTag(sizeof(*resp), KsyncAllocationTag);
    if (resp != NULL) {
        WinRawZeroMemory(resp, sizeof(*resp));
    }

    return resp;
}

VOID KsyncResponseDelete(PKSYNC_RESPONSE resp)
{
    WinAssert(resp != NULL);

    WinRawFree(resp);
}