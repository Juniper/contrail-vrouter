/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"
#include "windows_mem.h"

#include "vrouter.h"
#include "vr_flow.h"

static ULONG FlowMemoryAllocationTag = 'MEMS';

/* `FlowMemoryInit` need to populate these pointers in vRouter with pointers to
   allocated the flow table
*/
extern void *vr_flow_table;
extern void *vr_oflow_table;

static PVOID  FlowTable = NULL;
static size_t FlowTableSize = 0;

static PMDL  FlowMemoryMdl = NULL;

PMDL
GetFlowMemoryMdl(VOID)
{
    return FlowMemoryMdl;
}

NTSTATUS
FlowMemoryInit(VOID)
{
    ASSERT(FlowTable == NULL);
    ASSERT(FlowMemoryMdl == NULL);

    NDIS_STATUS status;

    /* `vr_oflow_entries` and `vr_flow_entries` are defined in dp-core/vr_flow.c */
    vr_compute_size_oflow_table(&vr_oflow_entries, vr_flow_entries);

    FlowTableSize = VR_FLOW_TABLE_SIZE + VR_OFLOW_TABLE_SIZE;
    FlowTable = ExAllocatePoolWithTag(NonPagedPoolNx, FlowTableSize, FlowMemoryAllocationTag);
    if (FlowTable == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    FlowMemoryClean();

    FlowMemoryMdl = IoAllocateMdl(FlowTable, FlowTableSize, FALSE, FALSE, NULL);
    if (FlowMemoryMdl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    MmBuildMdlForNonPagedPool(FlowMemoryMdl);

    vr_flow_table = FlowTable;
    vr_oflow_table = (uint8_t *)FlowTable + VR_FLOW_TABLE_SIZE;

    return STATUS_SUCCESS;

Cleanup:
    FlowMemoryExit();
    return status;
}

VOID
FlowMemoryExit(VOID)
{
    vr_oflow_table = NULL;
    vr_flow_table = NULL;

    if (FlowMemoryMdl != NULL) {
        IoFreeMdl(FlowMemoryMdl);
        FlowMemoryMdl = NULL;
    }

    if (FlowTable != NULL) {
        ExFreePool(FlowTable);
        FlowTable = NULL;
    }
}

VOID
FlowMemoryClean(VOID)
{
    ASSERT(FlowTable != NULL);
    ASSERT(FlowTableSize > 0);

    RtlZeroMemory(FlowTable, FlowTableSize);
}
