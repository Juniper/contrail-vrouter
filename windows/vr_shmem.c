/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"
#include "windows_shmem.h"

#include "vrouter.h"
#include "vr_flow.h"

static ULONG FlowMemoryAllocationTag = 'MSRV';

extern void *vr_flow_table, *vr_oflow_table;
static PVOID  FlowShmemBlock = NULL;
static size_t FlowShmemSize = 0;
static PMDL FlowShmemMdl = NULL;

extern void *vr_bridge_table, *vr_bridge_otable;
static PVOID  BridgeShmemBlock = NULL;
static size_t BridgeShmemSize = 0;
static PMDL BridgeShmemMdl = NULL;

static NTSTATUS SingularShmemInit(const size_t, const size_t, size_t *, PVOID *, PMDL *, PVOID *, PVOID *);
static VOID SingularShmemExit(PVOID *, PMDL *, PVOID *, PVOID *);
static VOID SingularShmemClean(PVOID, size_t);

static NTSTATUS
SingularShmemInit(const size_t VrouterTableSize, const size_t VrouterOtableSize, size_t *ShmemSize, PVOID *ShmemBlock, PMDL *ShmemMdl, PVOID *VrouterTable, PVOID *VrouterOtable)
{
    ASSERT(*ShmemBlock == NULL);
    ASSERT(*ShmemMdl == NULL);

    NDIS_STATUS status;

    *ShmemSize = VrouterTableSize + VrouterOtableSize;
    *ShmemBlock = ExAllocatePoolWithTag(NonPagedPoolNx, *ShmemSize, FlowMemoryAllocationTag);
    if (*ShmemBlock == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    SingularShmemClean(*ShmemBlock, *ShmemSize);

    *ShmemMdl = IoAllocateMdl(*ShmemBlock, *ShmemSize, FALSE, FALSE, NULL);
    if (*ShmemMdl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    MmBuildMdlForNonPagedPool(*ShmemMdl);

    *VrouterTable = *ShmemBlock;
    *VrouterOtable = (uint8_t *)*ShmemBlock + VrouterTableSize;

    return STATUS_SUCCESS;

Cleanup:
    SingularShmemExit(ShmemBlock, ShmemMdl, VrouterTable, VrouterOtable);
    return status;
}

static VOID
SingularShmemExit(PVOID *ShmemBlock, PMDL *ShmemMdl, PVOID *VrouterTable, PVOID *VrouterOtable)
{
    *VrouterTable = NULL;
    *VrouterOtable = NULL;

    if (*ShmemMdl != NULL) {
        IoFreeMdl(*ShmemMdl);
        *ShmemMdl = NULL;
    }

    if (*ShmemBlock != NULL) {
        ExFreePool(*ShmemBlock);
        *ShmemBlock = NULL;
    }
}

static VOID
SingularShmemClean(PVOID ShmemBlock, size_t ShmemSize)
{
    ASSERT(ShmemBlock != NULL);
    ASSERT(ShmemSize > 0);

    RtlZeroMemory(ShmemBlock, ShmemSize);
}

PMDL
GetFlowMemoryMdl(VOID)
{
    return FlowShmemMdl;
}

PMDL
GetBridgeMemoryMdl(VOID)
{
    return BridgeShmemMdl;
}

NTSTATUS
ShmemInit(VOID)
{
    NDIS_STATUS status;

    vr_compute_size_oflow_table();
    status = SingularShmemInit(VR_FLOW_TABLE_SIZE, VR_OFLOW_TABLE_SIZE, &FlowShmemSize, &FlowShmemBlock, &FlowShmemMdl, &vr_flow_table, &vr_oflow_table);
    if (status != STATUS_SUCCESS)
        return status;

    vr_compute_size_bridge_otable();
    return SingularShmemInit(VR_BRIDGE_TABLE_SIZE, VR_BRIDGE_OFLOW_TABLE_SIZE, &BridgeShmemSize, &BridgeShmemBlock, &BridgeShmemMdl, &vr_bridge_table, &vr_bridge_otable);
}

VOID
ShmemExit(VOID)
{
    SingularShmemExit(&FlowShmemBlock, &FlowShmemMdl,  &vr_flow_table, &vr_oflow_table);
    SingularShmemExit(&BridgeShmemBlock, &BridgeShmemMdl,  &vr_bridge_table, &vr_bridge_otable);
}

VOID
ShmemClean(VOID)
{
    SingularShmemClean(FlowShmemBlock, FlowShmemSize);
    SingularShmemClean(BridgeShmemBlock, BridgeShmemSize);
}
