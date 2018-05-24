/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "ntddk.h"

ULONG KeGetCurrentProcessorNumberEx(
  PPROCESSOR_NUMBER ProcNumber
) {
    return 42;
}
