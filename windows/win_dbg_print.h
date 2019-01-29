/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _WIN_DBG_PRINT_H_
#define _WIN_DBG_PRINT_H_

#ifdef __KERNEL__
#include <wdm.h>
#define WinDbgPrint(format, ...) DbgPrint(format, ##__VA_ARGS__)
#else
#include <cmocka.h>
#define WinDbgPrint(format, ...) print_message(format, ##__VA_ARGS__)
#endif

#endif // _WIN_DBG_PRINT_H_
