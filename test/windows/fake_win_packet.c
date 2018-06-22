/*
 * fake_win_packet.c -- test double for vRouter OS layer unit testing
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet.h"

struct _WIN_PACKET {
    // TODO: Added temporarily, to fix unit test compilation
    void *ptr;
};

// TODO: Added temporarily, to fix unit test compilation
PNET_BUFFER_LIST
WinPacketToNBL(PWIN_PACKET Packet)
{
    return Packet->ptr;
}
