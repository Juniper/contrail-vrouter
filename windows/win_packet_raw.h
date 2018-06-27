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

// TODO: Move elsewhere?
extern void *(*WinRawAllocate)(size_t size);
void WinRawFree(void *buffer);

// TODO: Remove when callback layer is independent of NDIS
PNET_BUFFER_LIST WinPacketToNBL(PWIN_PACKET Packet);
PWIN_PACKET WinPacketFromNBL(PNET_BUFFER_LIST NetBufferList);

#endif /* __WIN_PACKET_RAW_H__ */
