/*
 * win_work_item.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */

#include "win_work_item.h"
#include "win_memory.h"
#include "vr_os.h"
#include "vr_windows.h"

struct _WIN_WORK_ITEM {
    KSPIN_LOCK Lock;
    NDIS_HANDLE WorkItem;
    BOOLEAN Exiting;
    volatile BOOLEAN Pending;
    volatile UINT RunningCount;
    WinWorkFunc Func;
    PVOID Context;
};

static NDIS_IO_WORKITEM_FUNCTION WinWorkRoutine;

static VOID
WinWorkRoutine(PVOID Context, NDIS_HANDLE NdisIoWorkItemHandle)
{
    PWIN_WORK_ITEM Work = (PWIN_WORK_ITEM)Context;

    InterlockedIncrement(&Work->RunningCount);
    Work->Pending = FALSE;
    vr_sync_synchronize();

    Work->Func(Work->Context);

    InterlockedDecrement(&Work->RunningCount);
}

PWIN_WORK_ITEM
WinWorkItemCreate(WinWorkFunc Func, void *Context)
{
    PWIN_WORK_ITEM work = WinRawAllocate(sizeof(*work));
    if (work == NULL) {
        return NULL;
    }

    work->Exiting = FALSE;
    work->Pending = FALSE;
    work->RunningCount = 0;

    work->Func = Func;
    work->Context = Context;

    KeInitializeSpinLock(&work->Lock);

    work->WorkItem = NdisAllocateIoWorkItem(VrDriverHandle);
    if (work->WorkItem == NULL) {
        goto fail;
    }

    return work;

fail:
    WinRawFree(work);
    return NULL;
}

void
WinWorkItemWaitDestroy(PWIN_WORK_ITEM Work)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&Work->Lock, &oldIrql);
    Work->Exiting = TRUE;
    KeReleaseSpinLock(&Work->Lock, oldIrql);

    while (Work->Pending) {
        vr_sync_synchronize();
    }

    while (Work->RunningCount) {
        vr_sync_synchronize();
    }

    NdisFreeIoWorkItem(Work->WorkItem);
    WinRawFree(Work);
}

void
WinWorkItemQueueWork(PWIN_WORK_ITEM Work)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&Work->Lock, &oldIrql);
    if (!Work->Exiting) {
        if (vr_sync_bool_compare_and_swap_8u(&Work->Pending, FALSE, TRUE)) {
            NdisQueueIoWorkItem(Work->WorkItem, WinWorkRoutine, Work);
        }
    }
    KeReleaseSpinLock(&Work->Lock, oldIrql);
}
