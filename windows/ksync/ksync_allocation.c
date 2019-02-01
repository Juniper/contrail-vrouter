/*
 * ksync_allocation.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#include "ksync_allocation.h"
#include "win_memory.h"

ULONG KsyncAllocationTag = 'NYSK';

PVOID
KsyncAllocateMemory(size_t bytes)
{
    return WinRawAllocateWithTag(bytes, KsyncAllocationTag);
}

VOID
KsyncFreeMemory(PVOID obj)
{
    WinRawFree(obj);
}
