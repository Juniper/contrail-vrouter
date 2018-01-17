/*
 * windows_shmem.h -- definitions used in shared memory handling on Windows
 *
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WINDOWS_MEM_H__
#define __WINDOWS_MEM_H__

#include "vr_windows.h"

PMDL GetFlowMemoryMdl(VOID);
PMDL GetBridgeMemoryMdl(VOID);

NTSTATUS ShmemInit(VOID);
VOID ShmemExit(VOID);
VOID ShmemClean(VOID);

#endif /* __WINDOWS_SHMEM_H__ */
