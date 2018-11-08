/*
 * asserts.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _WIN_TX_ASSERTS_H_
#define _WIN_TX_ASSERTS_H_

#include <win_packet.h>
#include <common.h>

void AssertMultiPktOffloadStatus(PWIN_MULTI_PACKET packet, OffloadFlag offload);

void AssertVrPktOffloadStatus(struct vr_packet *vrPacket, OffloadFlag offload);

void AssertPayloadMatch(struct vr_packet *originalPacket, PWIN_MULTI_PACKET resultPacket, size_t headersSize);

void AssertSubpacketsNumber(PWIN_MULTI_PACKET segments, size_t expectedPacketsNumber);

#endif // _WIN_TX_ASSERTS_H_
