/*
 * ksync_allocation.h
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __KSYNC_ALLOCATION_H__
#define __KSYNC_ALLOCATION_H__

#include <windows_types.h>

PVOID KsyncAllocateMemory(size_t bytes);

VOID KsyncFreeMemory(PVOID obj);

#endif __KSYNC_ALLOCATION_H__