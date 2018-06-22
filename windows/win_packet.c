/*
 * win_packet.c -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"
#include "win_packet.h"

#include <ndis.h>

struct _WIN_PACKET {
    NET_BUFFER_LIST NetBufferList;
};

PNET_BUFFER_LIST
WinPacketToNBL(PWIN_PACKET Packet)
{
    return &Packet->NetBufferList;
}

PWIN_PACKET
WinPacketFromNBL(PNET_BUFFER_LIST NetBufferList)
{
    return (PWIN_PACKET)NetBufferList;
}
