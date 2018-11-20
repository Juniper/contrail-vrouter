/*
 * common.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _WIN_TX_COMMON_H_
#define _WIN_TX_COMMON_H_

#include <win_packet.h>
#include <fake_win_packet.h>
#include <types.h>

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

#endif // _WIN_TX_COMMON_H_
