/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <wdm.h>
#include <stdlib.h>
#include <winsock2.h>

PVOID ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag) {
    return malloc(NumberOfBytes);
}

VOID ExFreePool(PVOID P) {
    free(P);
}

USHORT RtlUshortByteSwap(USHORT Source) {
    return ntohs(Source);
}

ULONG RtlUlongByteSwap(ULONG Source) {
    return ntohl(Source);
}
