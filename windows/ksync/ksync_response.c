/*
 * ksync_response.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#include "ksync_response.h"
#include "ksync_allocation.h"
#include "win_memory.h"
#include "win_assert.h"

PKSYNC_RESPONSE
KsyncResponseCreate()
{
    PKSYNC_RESPONSE resp;

    resp = KsyncAllocateMemory(sizeof(*resp));
    if (resp != NULL) {
        WinRawZeroMemory(resp, sizeof(*resp));
    }

    return resp;
}

VOID KsyncResponseDelete(PKSYNC_RESPONSE resp)
{
    WinAssert(resp != NULL);

    KsyncFreeMemory(resp);
}