/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _WIN_DBG_PRINT_H_
#define _WIN_DBG_PRINT_H_

#include <windows_types.h>

// This is not so universal function, it's been defined just for the 
// purpose of testing one vr_ksync function
ULONG WinRawDbgPrintFunctionStatus(PSTR Msg,
                                   PSTR FunctionName,
                                   NTSTATUS Status);

#endif // _WIN_DBG_PRINT_H_
