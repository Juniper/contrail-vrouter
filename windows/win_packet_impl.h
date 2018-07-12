/*
 * win_packet_impl.h -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_PACKET_IMPL_H__
#define __WIN_PACKET_IMPL_H__

typedef struct _WIN_PACKET WIN_PACKET, *PWIN_PACKET;
typedef struct _WIN_MULTI_PACKET WIN_MULTI_PACKET, *PWIN_MULTI_PACKET;
typedef struct _WIN_PACKET_RAW WIN_PACKET_RAW, *PWIN_PACKET_RAW;

static inline PWIN_PACKET_RAW
WinPacketToRawPacket(PWIN_PACKET Packet)
{
    return (PWIN_PACKET_RAW)Packet;
}

static inline PWIN_PACKET_RAW
WinMultiPacketToRawPacket(PWIN_MULTI_PACKET Packet)
{
    return (PWIN_PACKET_RAW)Packet;
}

#endif /* __WIN_PACKET_IMPL_H__ */
