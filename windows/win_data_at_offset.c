/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_packet.h"
#include "win_packet_impl.h"
#include "win_packet_raw.h"
#include "win_packet.h"
#include "win_memory.h"
#include "win_assert.h"

void *
win_data_at_offset(struct vr_packet *pkt, unsigned short offset)
{
    // THIS FUNCTION IS NOT SECURE
    // DP-CORE assumes all headers will be contigous, ie. pointers
    // of type (struct vr_headertype*), when pointing to the beginning
    // of the header, will be valid for it's entiriety

    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(pkt);
    PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(winPacket);
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(rawPacket);
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    PMDL current_mdl = NET_BUFFER_CURRENT_MDL(nb);
    unsigned length = MmGetMdlByteCount(current_mdl) - NET_BUFFER_CURRENT_MDL_OFFSET(nb);
    while (length < offset) {
        /* Get the pointer to the beginning of data represented in current MDL. */
        offset -= length;

        current_mdl = current_mdl->Next;
        if (current_mdl == NULL)
            return NULL;

        length = MmGetMdlByteCount(current_mdl);
    }

    void* ret = MmGetSystemAddressForMdlSafe(current_mdl,
        LowPagePriority | MdlMappingNoExecute);
    if (ret == NULL)
        return NULL;

    return (uint8_t*) ret + offset;
}
