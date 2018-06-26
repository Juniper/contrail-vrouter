/*
 * fake_win_packet.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _FAKE_WIN_PACKET_H_
#define _FAKE_WIN_PACKET_H_

#include "win_packet.h"

PWIN_PACKET Fake_WinPacketAllocate();
VOID Fake_WinPacketFree(PWIN_PACKET Packet);

#endif // _FAKE_WIN_PACKET_H_
