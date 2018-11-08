/*
 * common.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _PACKETS_GENERATOR_UTILS_H_
#define _PACKETS_GENERATOR_UTILS_H_

#include <win_packet.h>
#include <fake_win_packet.h>

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

void GenerateAZPayload(uint8_t* buffer, size_t payloadSize);

void GenerateEmptyPayload(uint8_t* buffer, size_t payloadSize);

void* GetBufferFromMultiPacket(PWIN_MULTI_PACKET packet);

struct vr_packet* CreateVrPacket(size_t headersSize,
                                 size_t dataSize,
                                 PHEADERFILLERFUNCTION headerFiller,
                                 PGENERATEPAYLOADFUNCTION payloadGenerator,
                                 PVRPACKETFILLERFUNCTION vrPacketFiller,
                                 OffloadFlag offload);

void Test(PHEADERFILLERFUNCTION inputPacketHeaderFiller,
          size_t dataSize,
          size_t headersSize,
          PGENERATEPAYLOADFUNCTION payloadGenerator,
          PVRPACKETFILLERFUNCTION vrPacketFiller,
          OffloadFlag inputPacketOffloadFlags,
          PHEADERFILLERFUNCTION* outputPacketHeaderFillers,
          size_t outputPacketsNumber,
          PASSERTFUNCTION Assert);

#define CountPacketLengthFromHeader(headers, ipHeader, dataSize) (((uint8_t*)headers) + sizeof(*headers) - ((uint8_t*)(&(headers->ipHeader))) + dataSize)

#define CountHeaderOffset(headers, header) (((uint8_t*)(&(headers->header))) - ((uint8_t*)(headers)))

#endif // _PACKETS_GENERATOR_UTILS_H_
