/*
 * types.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _WIN_TX_TYPES_H_
#define _WIN_TX_TYPES_H_

#include <win_packet.h>

typedef void(*PHEADERFILLERFUNCTION)(struct PacketHeaders *headers, size_t dataSize);
typedef void(*PGENERATEPAYLOADFUNCTION)(uint8_t* buffer, size_t payloadSize);
typedef void(*PVRPACKETFILLERFUNCTION)(struct vr_packet* packet, struct PacketHeaders* headers);
typedef bool(*PCHECKHEADERSAREVALIDFUNCTION)(PWIN_SUB_PACKET subPacket, PHEADERFILLERFUNCTION headerFiller, size_t dataSize);
typedef void (*PASSERTFUNCTION)(struct vr_packet *originalVrPacket, struct vr_packet *processedVrPacket, PWIN_MULTI_PACKET result);

typedef enum
{
    NO_OFFLOADS   = 0,
    IPCHKSUM_OFFLOADED  = 1 << 0,
    UDPCHKSUM_OFFLOADED = 1 << 1,
    TCPPCHKSUM_OFFLOADED = 1 << 2,
    SEG_OFFLOADED = 1 << 3,
} OffloadFlag;

#endif // _WIN_TX_TYPES_H_
