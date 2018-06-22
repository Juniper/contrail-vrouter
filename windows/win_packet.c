/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"

#include "win_packet.h"
#include <ndis.h>

struct _WIN_PACKET {
    PNET_BUFFER_LIST NetBufferList;
};

PWIN_PACKET
WinPacketAllocateStruct(const ULONG Tag)
{
    PWIN_PACKET Packet = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*Packet), Tag);

    if (Packet) {
        RtlZeroMemory(Packet, sizeof(*Packet));
    }

    return Packet;
}

VOID
WinPacketFreeStruct(PWIN_PACKET Packet)
{
    ExFreePool(Packet);
}

PNET_BUFFER_LIST
WinPacketGetNBL(PWIN_PACKET Packet)
{
    return Packet->NetBufferList;
}

VOID
WinPacketSetNBL(PWIN_PACKET Packet, PNET_BUFFER_LIST NetBufferList)
{
    Packet->NetBufferList = NetBufferList;
}
