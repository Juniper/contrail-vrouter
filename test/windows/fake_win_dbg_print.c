/* 
 * fake_win_dbg_print.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#include "win_dbg_print.h"

ULONG WinRawDbgPrintFunctionStatus(PSTR Msg,
                                   PSTR FunctionName,
                                   NTSTATUS Status)
{
    return 0;
}
