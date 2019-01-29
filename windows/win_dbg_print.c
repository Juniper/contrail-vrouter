/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_dbg_print.h"
#include <wdm.h>

ULONG WinRawDbgPrintFunctionStatus(PSTR Msg,
                                   PSTR FunctionName,
                                   NTSTATUS Status)
{
    return DbgPrint(Msg, FunctionName, Status);
}