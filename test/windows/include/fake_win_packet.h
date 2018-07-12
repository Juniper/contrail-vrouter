/*
 * fake_win_packet.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _FAKE_WIN_PACKET_H_
#define _FAKE_WIN_PACKET_H_

#include "win_packet.h"
#include "win_packet_raw.h"

PWIN_PACKET Fake_WinPacketAllocateOwned();
PWIN_PACKET Fake_WinPacketAllocateNonOwned();
VOID Fake_WinPacketFree(PWIN_PACKET Packet);

PWIN_MULTI_PACKET Fake_WinMultiPacketAllocateWithSubPackets(size_t SubPacketsCount);
void Fake_WinMultiPacketFree(PWIN_MULTI_PACKET Packet);

long Fake_WinSubPacketGetData(PWIN_SUB_PACKET SubPacket);

// TODO: change to production?
void Fake_WinPacketListRawFree(PWIN_PACKET_LIST List);

extern PWIN_PACKET_RAW (*WinPacketRawAllocateClone_Callback)(PWIN_PACKET_RAW Packet);
extern void (*WinPacketRawComplete_Callback)(PWIN_PACKET_RAW Packet);
extern void (*WinPacketRawFreeCreated_Callback)(PWIN_PACKET_RAW Packet);
extern void (*WinPacketRawFreeClone_Callback)(PWIN_PACKET_RAW Packet);
extern PWIN_PACKET_LIST (*WinPacketListRawAllocateElement_Callback)();

#endif // _FAKE_WIN_PACKET_H_
