/*
 * windows_mem.h -- definitions used in shared memmory handling on Windows
 *
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WINDOWS_MEM_H__
#define __WINDOWS_MEM_H__

#include "vr_windows.h"

PMDL GetFlowMemoryMdl(VOID);

NTSTATUS FlowMemoryInit(VOID);
VOID FlowMemoryExit(VOID);

VOID FlowMemoryClean(VOID);

#endif /* __WINDOWS_MEM_H__ */
