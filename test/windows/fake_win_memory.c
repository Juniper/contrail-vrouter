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