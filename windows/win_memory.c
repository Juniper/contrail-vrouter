/*
 * win_memory.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_memory.h"
#include <ndis.h>
#include <ntddk.h>

void*
WinRawAllocate(size_t size)
{
    return ExAllocatePoolWithTag(NonPagedPoolNx, size, VrAllocationTag);
}

void
WinRawFree(void* buffer)
{
    ExFreePool(buffer);
}

void*
WinRawAllocateWithTag(size_t size, ULONG tag)
{
    return ExAllocatePoolWithTag(NonPagedPoolNx, size, tag);
}

void *
WinRawMemCpy(void *dst, void *src, size_t n)
{
    return RtlCopyMemory(dst, src, n);
}

void *
WinRawZeroMemory(void *str, size_t n)
{
    return RtlZeroMemory(str, n);
}