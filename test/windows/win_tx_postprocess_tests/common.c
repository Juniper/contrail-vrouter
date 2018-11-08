#include "include/common.h"

#include <setjmp.h>
#include <cmocka.h>
#include <allocation.h>
#include <win_packet_impl.h>
#include <fake_win_packet.h>
#include <win_tx_postprocess.h>

struct vr_packet *
CreateVrPacket(size_t headersSize, size_t dataSize, PHEADERFILLERFUNCTION HeaderFiller, PGENERATEPAYLOADFUNCTION PayloadGenerator,
    PVRPACKETFILLERFUNCTION VrPacketFiller, OffloadFlag offload)
{
    uint8_t *buffer = test_calloc(headersSize + dataSize, 1);
    struct PacketHeaders *headers = (struct PacketHeaders*) buffer;
    uint8_t *data = buffer + headersSize;

    HeaderFiller(headers, dataSize);
    PayloadGenerator(data, dataSize);

    struct vr_interface *vif = AllocateFakeInterface();
    struct vr_packet *vrPacket = AllocateVrPacketNonOwned();
    vrPacket->vp_head = buffer;
    vrPacket->vp_if = vif;
    VrPacketFiller(vrPacket, headers);

    PVR_PACKET_WRAPPER wrapper = GetWrapperFromVrPacket(vrPacket);
    PWIN_PACKET winPkt = wrapper->WinPacket;
    PWIN_PACKET_RAW rawPkt = WinPacketToRawPacket(winPkt);
    PWIN_SUB_PACKET subPkt = WinPacketRawGetFirstSubPacket(rawPkt);

    Fake_WinSubPacketSetData(subPkt, buffer, headersSize + dataSize);

    Fake_WinPacketRawSetOffloadInfo(rawPkt,
        offload & IPCHKSUM_OFFLOADED,
        offload & UDPCHKSUM_OFFLOADED,
        offload & SEG_OFFLOADED);

    return vrPacket;
}

void
Test(PHEADERFILLERFUNCTION inputPacketHeaderFiller,
    size_t dataSize,
    size_t headersSize,
    PGENERATEPAYLOADFUNCTION payloadGenerator,
    PVRPACKETFILLERFUNCTION vrPacketFiller,
    OffloadFlag inputPacketOffloadFlags,
    PHEADERFILLERFUNCTION* outputPacketHeaderFillers,
    size_t outputPacketsNumber,
    PASSERTFUNCTION Assert)
{
    // Create input
    struct vr_packet *vrPacket = CreateVrPacket(headersSize, dataSize, inputPacketHeaderFiller, payloadGenerator, vrPacketFiller, inputPacketOffloadFlags);

    // Process data
    PWIN_MULTI_PACKET result = WinTxPostprocess(vrPacket);

    // Assert output
    assert_ptr_not_equal(result, NULL);
    AssertSubpacketsNumber(result, outputPacketsNumber);
    struct vr_packet *originalVrPacket = CreateVrPacket(headersSize, dataSize, inputPacketHeaderFiller, payloadGenerator, vrPacketFiller, inputPacketOffloadFlags);
    Assert(originalVrPacket, vrPacket, result);
    AssertHeadersAreValid(result, outputPacketHeaderFillers, dataSize);
    AssertPayloadMatch(originalVrPacket, result, headersSize);

    // Clean up
    if(((void*)result) != ((void*)GetWinPacketFromVrPacket(vrPacket)))
        FreeWinMultiPacket(result);
    FreePacket(vrPacket);
    FreePacket(originalVrPacket);
}
