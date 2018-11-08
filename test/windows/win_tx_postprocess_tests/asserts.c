#include "include/asserts.h"

#include <setjmp.h>
#include <cmocka.h>
#include <fake_win_packet.h>
#include <win_packet_impl.h>

void
AssertPayloadMatch(struct vr_packet *originalPacket,
    PWIN_MULTI_PACKET resultPacket, size_t headersSize)
{
    PWIN_PACKET originalWinPacket = GetWinPacketFromVrPacket(originalPacket);
    PWIN_PACKET_RAW originalRawPacket = WinPacketToRawPacket(originalWinPacket);
    PWIN_SUB_PACKET originalSubPacket = WinPacketRawGetFirstSubPacket(originalRawPacket);

    size_t originalPayloadSize = Fake_WinSubPacketGetDataSize(originalSubPacket) - headersSize;
    uint8_t *originalPacketData = Fake_WinSubPacketGetData(originalSubPacket);
    uint8_t *originalPayload = originalPacketData + headersSize;

    PWIN_PACKET_RAW rawResultPacket = WinMultiPacketToRawPacket(resultPacket);
    PWIN_SUB_PACKET subPacket = WinPacketRawGetFirstSubPacket(rawResultPacket);
    size_t resultPayloadSize = 0;

    while(subPacket != NULL)
    {
        size_t subPacketPayloadSize = Fake_WinSubPacketGetDataSize(subPacket) - headersSize;
        uint8_t *subPacketData = Fake_WinSubPacketGetData(subPacket);
        uint8_t *subPacketPayload = subPacketData + headersSize;
        assert_true(memcmp(originalPayload + resultPayloadSize, subPacketPayload, subPacketPayloadSize) == 0);
        resultPayloadSize += subPacketPayloadSize;
        subPacket = WinSubPacketRawGetNext(subPacket);
    }

    assert_int_equal(originalPayloadSize, resultPayloadSize);
}

void
AssertMultiPktOffloadStatus(PWIN_MULTI_PACKET packet, OffloadFlag offload)
{
    PWIN_PACKET_RAW rawPkt = WinMultiPacketToRawPacket(packet);

    if (offload & IPCHKSUM_OFFLOADED) {
        assert_true(WinPacketRawShouldIpChecksumBeOffloaded(rawPkt));
    } else {
        assert_false(WinPacketRawShouldIpChecksumBeOffloaded(rawPkt));
    }

    if (offload & UDPCHKSUM_OFFLOADED) {
        assert_true(WinPacketRawShouldUdpChecksumBeOffloaded(rawPkt));
    } else {
        assert_false(WinPacketRawShouldUdpChecksumBeOffloaded(rawPkt));
    }

    if (offload & TCPPCHKSUM_OFFLOADED) {
        assert_true(WinPacketRawShouldTcpChecksumBeOffloaded(rawPkt));
    } else {
        assert_false(WinPacketRawShouldTcpChecksumBeOffloaded(rawPkt));
    }

    if (offload & SEG_OFFLOADED) {
        assert_true(WinPacketRawShouldSegmentationBeOffloaded(rawPkt));
    } else {
        assert_false(WinPacketRawShouldSegmentationBeOffloaded(rawPkt));
    }
}

void
AssertVrPktOffloadStatus(struct vr_packet *vrPacket, OffloadFlag offload)
{
    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(vrPacket);
    PWIN_PACKET_RAW winPacketRaw = WinPacketToRawPacket(winPacket);
    PWIN_MULTI_PACKET multiPacket = (PWIN_MULTI_PACKET)winPacketRaw;

    AssertMultiPktOffloadStatus(multiPacket, offload);
}

void
AssertSubpacketsNumber(PWIN_MULTI_PACKET segments, size_t expectedPacketsNumber)
{
    PWIN_PACKET_RAW rawResultPacket = WinMultiPacketToRawPacket(segments);
    PWIN_SUB_PACKET subPacket = WinPacketRawGetFirstSubPacket(rawResultPacket);
    size_t counter = 0;
    while(subPacket != NULL)
    {
        counter++;
        subPacket = WinSubPacketRawGetNext(subPacket);
    }
    assert_int_equal(counter, expectedPacketsNumber);
}
