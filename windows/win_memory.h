/*
 * win_memory.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _WIN_MEMORY_H_
#define _WIN_MEMORY_H_

#include "vr_os.h"
#include <ndis.h>

void* WinRawAllocate(size_t size);
void WinRawFree(void *buffer);

#endif //_WIN_MEMORY_H_