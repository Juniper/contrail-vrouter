/*
 * win_packet.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_PACKET_H__
#define __WIN_PACKET_H__

struct _NET_BUFFER_LIST;
typedef struct _NET_BUFFER_LIST *PNET_BUFFER_LIST;

struct _WIN_PACKET;
typedef struct _WIN_PACKET   WIN_PACKET;
typedef struct _WIN_PACKET *PWIN_PACKET;

PWIN_PACKET WinPacketAllocateStruct(const ULONG Tag);
VOID WinPacketFreeStruct(PWIN_PACKET Packet);

PNET_BUFFER_LIST WinPacketGetNBL(PWIN_PACKET Packet);
VOID WinPacketSetNBL(PWIN_PACKET Packet, PNET_BUFFER_LIST NetBufferList);

#endif /* __WIN_PACKET_H__ */
