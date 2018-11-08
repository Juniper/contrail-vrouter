/*
 * allocation.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _WIN_TX_ALLOCATION_H_
#define _WIN_TX_ALLOCATION_H_

#include <win_packet.h>

PVOID Fake_WinRawAllocate(size_t size);

struct vr_packet* AllocateVrPacketNonOwned(VOID);

VOID FreeVrPacket(struct vr_packet * vrPkt);

struct vr_interface* AllocateFakeInterface();

VOID FreeFakeInterface(struct vr_interface *vif);

void FreePacket(struct vr_packet *vrPacket);

void FreeWinMultiPacket(PWIN_MULTI_PACKET packet);

#endif // _WIN_TX_ALLOCATION_H_
