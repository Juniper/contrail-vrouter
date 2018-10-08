/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet_impl.h"
#include "win_packet_raw.h"
#include "win_packet.h"

void *
win_data_at_offset(struct vr_packet *pkt, unsigned short offset)
{
    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(pkt);
    PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(winPacket);
    return WinPacketRawDataAtOffset(rawPacket, offset);
}
