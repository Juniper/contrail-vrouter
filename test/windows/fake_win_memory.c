/*
 * fake_win_memory.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "win_memory.h"

#include <stdarg.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

void
WinRawFree(void *buffer)
{
    test_free(buffer);
}

void *(*WinRawAllocate_Callback)(size_t size);

void *
WinRawAllocate(size_t size)
{
    return WinRawAllocate_Callback(size);
}

void*
WinRawAllocateWithTag(size_t size, ULONG tag)
{
    return test_malloc(size);
}

void *
WinRawMemCpy(void *dst, void *src, size_t n)
{
    return memcpy(dst, src, n);
}

void *
WinRawZeroMemory(void *str, size_t n)
{
    return memset(str, 0, n);
}