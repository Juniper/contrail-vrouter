/*
 * win_packet.h -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_PACKET_H__
#define __WIN_PACKET_H__

#include "vr_packet.h"

typedef struct _WIN_PACKET WIN_PACKET, *PWIN_PACKET;
typedef struct _WIN_MULTI_PACKET WIN_MULTI_PACKET, *PWIN_MULTI_PACKET;

typedef struct _WIN_PACKET_LIST WIN_PACKET_LIST, *PWIN_PACKET_LIST;
struct _WIN_PACKET_LIST {
    PWIN_PACKET_LIST Next;
    PWIN_PACKET WinPacket;
};

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
VOID WinPacketFreeClonedPreservingParent(PWIN_PACKET Packet);

void WinPacketFreeRecursive(PWIN_PACKET Packet);
void WinPacketFreeClonedPreservingParent(PWIN_PACKET Packet);

PWIN_PACKET_LIST WinPacketSplitMultiPacket(PWIN_MULTI_PACKET WinMultiPacket);

#endif /* __WIN_PACKET_H__ */
