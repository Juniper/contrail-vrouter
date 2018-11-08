#include "include/allocation.h"

#include <setjmp.h>
#include <cmocka.h>
#include <fake_win_packet.h>
#include <win_packet_impl.h>

PVOID
Fake_WinRawAllocate(size_t size)
{
    return test_calloc(1, size);
}

extern PVOID (*WinRawAllocate_Callback)(size_t size) = Fake_WinRawAllocate;

// TODO: Reuse; copy-pasted from test_win_pclone.c
struct vr_packet *
AllocateVrPacketNonOwned(VOID)
{
    PVR_PACKET_WRAPPER pkt = test_calloc(1, sizeof(*pkt));
    pkt->WinPacket = Fake_WinPacketAllocateNonOwned();

    return &pkt->VrPacket;
}

// TODO: Reuse; copy-pasted from test_win_pclone.c
VOID
FreeVrPacket(struct vr_packet * vrPkt)
{
    win_pfree(vrPkt, 0);
}

struct vr_interface *
AllocateFakeInterface()
{
    struct vr_interface *vif = test_calloc(1, sizeof(*vif));
    vif->vif_mtu = 1514;

    return vif;
}

VOID
FreeFakeInterface(struct vr_interface *vif)
{
    test_free(vif);
}

void
FreePacket(struct vr_packet *vrPacket)
{
    test_free(vrPacket->vp_head);
    FreeFakeInterface(vrPacket->vp_if);
    FreeVrPacket(vrPacket);
}

void
FreeWinMultiPacket(PWIN_MULTI_PACKET packet)
{
    PWIN_PACKET_RAW rawPacket = WinMultiPacketToRawPacket(packet);
    PWIN_PACKET_RAW parent = WinPacketRawGetParentOf(rawPacket);

    Fake_WinMultiPacketFree(packet);
    WinPacketRawDecrementChildCountOf(parent);
}
