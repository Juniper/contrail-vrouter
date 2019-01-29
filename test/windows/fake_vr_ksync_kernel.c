/*
 * fake_vr_ksync_kernel.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_ksync_kernel.h"

static ULONG counter = 0;

NTSTATUS
KsyncHandleWrite(PKSYNC_DEVICE_CONTEXT ctx,
                 uint8_t *buffer,
                 size_t buffer_size)
{
    ++counter;
    return STATUS_SUCCESS;
}

ULONG GetHandleWriteCounter()
{
    return counter;
}

void ResetHandleWriteCounter()
{
    counter = 0;
}