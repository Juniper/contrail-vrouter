/*
 * fake_win_packet.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _FAKE_WIN_PACKET_H_
#define _FAKE_WIN_PACKET_H_

#include "win_packet.h"
#include "win_packet_raw.h"

PWIN_PACKET Fake_WinPacketAllocateMultiFragment();
PWIN_PACKET Fake_WinPacketAllocateOwned();
PWIN_PACKET Fake_WinPacketAllocateNonOwned();
VOID Fake_WinPacketFree(PWIN_PACKET Packet);

PWIN_MULTI_PACKET Fake_WinMultiPacketAllocateWithSubPackets(size_t SubPacketsCount);
void Fake_WinMultiPacketFree(PWIN_MULTI_PACKET Packet);

void *Fake_WinSubPacketGetData(PWIN_SUB_PACKET SubPacket);
size_t Fake_WinSubPacketGetDataSize(PWIN_SUB_PACKET SubPacket);
void Fake_WinSubPacketSetData(PWIN_SUB_PACKET SubPacket, void *Data, size_t Size);

void Fake_WinPacketListRawFree(PWIN_PACKET_LIST List, bool OwnsPacket);

extern PWIN_PACKET_RAW (*WinPacketRawAllocateClone_Callback)(PWIN_PACKET_RAW Packet);
extern void (*WinPacketRawComplete_Callback)(PWIN_PACKET_RAW Packet);
extern void (*WinPacketRawFreeCreated_Callback)(PWIN_PACKET_RAW Packet);
extern void (*WinPacketRawFreeClone_Callback)(PWIN_PACKET_RAW Packet);
extern void (*WinPacketRawFreeMultiFragment_Callback)(PWIN_PACKET_RAW Packet);
extern PWIN_PACKET_LIST (*WinPacketListRawAllocateElement_Callback)();

#endif // _FAKE_WIN_PACKET_H_
