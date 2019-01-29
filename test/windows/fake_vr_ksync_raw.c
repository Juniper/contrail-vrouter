/*
 * fake_vr_ksync_raw.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_ksync_raw.h"

NTSTATUS
KSyncCompleteIrpRaw(PIRP_DOLL IrpRaw,
                    NTSTATUS Status,
                    ULONG Information)
{
    IrpRaw->Status = Status;
    IrpRaw->Information = Information;
    return Status;
}

NTSTATUS
KsyncHandleWrite(PKSYNC_DEVICE_CONTEXT ctx,
                 uint8_t *buffer,
                 size_t buffer_size)
{
    return STATUS_SUCCESS;
}
