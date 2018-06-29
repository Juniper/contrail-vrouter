/*
 * win_packet.h -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_PACKET_H__
#define __WIN_PACKET_H__

#include <ndis.h>

#include "vr_packet.h"

typedef struct _WIN_PACKET WIN_PACKET, *PWIN_PACKET;

// NOTE: VrPacket should **always** be a first field in VR_PACKET_WRAPPER struct.
typedef struct _VR_PACKET_WRAPPER {
    struct vr_packet VrPacket;

    PWIN_PACKET WinPacket;
} VR_PACKET_WRAPPER, *PVR_PACKET_WRAPPER;

static inline PVR_PACKET_WRAPPER
GetWrapperFromVrPacket(struct vr_packet *VrPacket)
{
    return (PVR_PACKET_WRAPPER)(VrPacket);
}

static inline PWIN_PACKET
GetWinPacketFromVrPacket(struct vr_packet *VrPacket)
{
    PVR_PACKET_WRAPPER wrapper = GetWrapperFromVrPacket(VrPacket);
    return wrapper->WinPacket;
}

PWIN_PACKET WinPacketClone(PWIN_PACKET Packet);

VOID WinPacketFree(PWIN_PACKET Packet);
VOID WinPacketFreeClonedPreservingParent(PWIN_PACKET Packet);

PWIN_PACKET WinPacketRawGetParentOf(PWIN_PACKET Packet);
VOID WinPacketRawSetParentOf(PWIN_PACKET Packet, PWIN_PACKET Parent);

LONG WinPacketRawGetChildCountOf(PWIN_PACKET Packet);
VOID WinPacketRawIncrementChildCountOf(PWIN_PACKET Packet);
LONG WinPacketRawDecrementChildCountOf(PWIN_PACKET Packet);

BOOL WinPacketRawIsOwned(PWIN_PACKET Packet);
extern VOID (*WinPacketRawComplete)(PWIN_PACKET Packet);
extern VOID (*WinPacketRawFreeCreated)(PWIN_PACKET Packet);

extern PWIN_PACKET (*WinPacketRawAllocateClone)(PWIN_PACKET Packet);
VOID WinPacketRawFreeClone(PWIN_PACKET Packet);

// TODO: Remove when callback layer is independent of NDIS
PNET_BUFFER_LIST WinPacketToNBL(PWIN_PACKET Packet);
PWIN_PACKET WinPacketFromNBL(PNET_BUFFER_LIST NetBufferList);

#endif /* __WIN_PACKET_H__ */
