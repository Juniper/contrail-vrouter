/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "ntddk.h"

ULONG KeGetCurrentProcessorNumberEx(
  PPROCESSOR_NUMBER ProcNumber
) {
    return 42;
}

PHYSICAL_ADDRESS MmGetPhysicalAddress(
  PVOID BaseAddress
) {
    assert(0);
    PHYSICAL_ADDRESS addr;
    memset(&addr, 0, sizeof(addr));
    return addr;
}
