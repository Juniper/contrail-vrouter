/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "wdm.h"

#include <stdlib.h>
#include <winsock2.h>
#include <setjmp.h>
#include <cmocka.h>


PVOID ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag) {
    return test_malloc(NumberOfBytes);
}

VOID ExFreePool(PVOID P) {
    test_free(P);
}

USHORT RtlUshortByteSwap(USHORT Source) {
    return ntohs(Source);
}

ULONG RtlUlongByteSwap(ULONG Source) {
    return ntohl(Source);
}
