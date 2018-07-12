/*
 * win_packet_raw.h -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_PACKET_RAW_H__
#define __WIN_PACKET_RAW_H__

#include "vr_os.h"
#include <ndis.h>

typedef struct _WIN_PACKET WIN_PACKET, *PWIN_PACKET;
// TODO: move?
typedef struct _WIN_PACKET_LIST WIN_PACKET_LIST, *PWIN_PACKET_LIST;
struct _WIN_PACKET_LIST {
    PWIN_PACKET_LIST Next;
    PWIN_PACKET WinPacket;
};
typedef struct _WIN_SUB_PACKET WIN_SUB_PACKET, *PWIN_SUB_PACKET;
typedef struct _WIN_MULTI_PACKET WIN_MULTI_PACKET, *PWIN_MULTI_PACKET;

PWIN_PACKET WinPacketRawGetParentOf(PWIN_PACKET Packet);
void WinPacketRawSetParentOf(PWIN_PACKET Packet, PWIN_PACKET Parent);

long WinPacketRawGetChildCountOf(PWIN_PACKET Packet);
long WinPacketRawIncrementChildCountOf(PWIN_PACKET Packet);
long WinPacketRawDecrementChildCountOf(PWIN_PACKET Packet);

bool WinPacketRawIsOwned(PWIN_PACKET Packet);
void WinPacketRawComplete(PWIN_PACKET Packet);
void WinPacketRawFreeCreated(PWIN_PACKET Packet);

PWIN_PACKET WinPacketRawAllocateClone(PWIN_PACKET Packet);
void WinPacketRawFreeClone(PWIN_PACKET Packet);

PWIN_PACKET WinMultiPacketRawToWinPacket(PWIN_MULTI_PACKET MultiPacket);
PWIN_PACKET_LIST WinPacketListRawAllocateElement();
void WinPacketListRawFreeElement(PWIN_PACKET_LIST List);
PWIN_SUB_PACKET WinMultiPacketRawGetFirstSubPacket(PWIN_MULTI_PACKET MultiPacket);
void WinMultiPacketRawSetFirstSubPacket(PWIN_MULTI_PACKET MultiPacket, PWIN_SUB_PACKET SubPacket);
PWIN_SUB_PACKET WinSubPacketRawGetNext(PWIN_SUB_PACKET SubPacket);
void WinSubPacketRawSetNext(PWIN_SUB_PACKET SubPacket, PWIN_SUB_PACKET Next);

// TODO: Remove this declaration and change the definition to `static inline`
// when callback layer is independent of NDIS
PNET_BUFFER_LIST WinPacketToNBL(PWIN_PACKET Packet);
PWIN_PACKET WinPacketFromNBL(PNET_BUFFER_LIST NetBufferList);

#endif /* __WIN_PACKET_RAW_H__ */
