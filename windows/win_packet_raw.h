/*
 * win_packet_raw.h -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_PACKET_RAW_H__
#define __WIN_PACKET_RAW_H__

#include "vr_os.h"
#include <ndis.h>

typedef struct _WIN_PACKET_RAW WIN_PACKET_RAW, *PWIN_PACKET_RAW;

PWIN_PACKET_RAW WinPacketRawGetParentOf(PWIN_PACKET_RAW Packet);
void WinPacketRawSetParentOf(PWIN_PACKET_RAW Packet, PWIN_PACKET_RAW Parent);

long WinPacketRawGetChildCountOf(PWIN_PACKET_RAW Packet);
long WinPacketRawIncrementChildCountOf(PWIN_PACKET_RAW Packet);
long WinPacketRawDecrementChildCountOf(PWIN_PACKET_RAW Packet);

bool WinPacketRawIsOwned(PWIN_PACKET_RAW Packet);
void WinPacketRawComplete(PWIN_PACKET_RAW Packet);
void WinPacketRawFreeCreated(PWIN_PACKET_RAW Packet);

PWIN_PACKET_RAW WinPacketRawAllocateClone(PWIN_PACKET_RAW Packet);
void WinPacketRawFreeClone(PWIN_PACKET_RAW Packet);

// TODO: Remove this declaration and change the definition to `static inline`
// when callback layer is independent of NDIS
PNET_BUFFER_LIST WinPacketRawToNBL(PWIN_PACKET_RAW Packet);
PWIN_PACKET_RAW WinPacketRawFromNBL(PNET_BUFFER_LIST NetBufferList);

#endif /* __WIN_PACKET_RAW_H__ */
