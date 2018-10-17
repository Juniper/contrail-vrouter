/*
 * test_win_tx_postprocess.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <fake_win_packet.h>
#include <vr_packet.h>
#include <win_packet.h>
#include <win_packet_impl.h>
#include <win_packet_raw.h>
#include <win_tx_postprocess.h>

static PVOID
Fake_WinRawAllocate(size_t size)
{
    return test_calloc(1, size);
}

extern PVOID (*WinRawAllocate_Callback)(size_t size) = Fake_WinRawAllocate;

// TODO: Reuse; copy-pasted from test_win_pclone.c
static struct vr_packet *
AllocateVrPacketNonOwned(VOID)
{
    PVR_PACKET_WRAPPER pkt = test_calloc(1, sizeof(*pkt));
    pkt->WinPacket = Fake_WinPacketAllocateNonOwned();
    return &pkt->VrPacket;
}

// TODO: Reuse; copy-pasted from test_win_pclone.c
static VOID
FreeVrPacket(struct vr_packet * vrPkt)
{
    win_pfree(vrPkt, 0);
}

static struct vr_interface *
AllocateFakeInterface()
{
    struct vr_interface *vif = test_calloc(1, sizeof(*vif));
    vif->vif_mtu = 1514;
    return vif;
}

static VOID
FreeFakeInterface(struct vr_interface *Vif)
{
    test_free(Vif);
}

static struct vr_packet *
MPLSoGREPacket()
{
    uint8_t *buffer = test_calloc(4096, 1);

    // NOTE: Ethernet header does not affect packet postprocessing. Initialization not needed.
    struct vr_eth *outerEthHeader = (struct vr_eth *)(buffer);

    // NOTE: Since checksum calculation is offloaded in this test, outer IP header does not
    // affect packet postprocessing in this test.
    struct vr_ip *outerIpHeader = (struct vr_ip *)(outerEthHeader + 1);

    // NOTE: GRE header does not affect packet postprocessing. Initialization not needed.
    struct vr_gre *greHeader = (struct vr_gre *)(outerIpHeader + 1);

    // NOTE: MPLS header does not affect packet postprocessing. Initialization not needed.
    uint32_t *mplsHeader = (uint32_t *)(greHeader + 1);

    struct vr_eth *innerEthHeader = (struct vr_eth *)(mplsHeader + 1);
    {
        uint8_t smac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x03};
        uint8_t dmac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x04};

        VR_MAC_COPY(innerEthHeader->eth_dmac, dmac);
        VR_MAC_COPY(innerEthHeader->eth_smac, smac);
        innerEthHeader->eth_proto = htons(VR_ETH_PROTO_IP);
    }

    struct vr_ip *innerIpHeader = (struct vr_ip *)(innerEthHeader + 1);
    {
        innerIpHeader->ip_hl = 5;
        innerIpHeader->ip_version = 4;
        innerIpHeader->ip_tos = 0;
        innerIpHeader->ip_len = htons(32);
        innerIpHeader->ip_id = htons(0x5351);
        innerIpHeader->ip_frag_off = 0;
        innerIpHeader->ip_ttl = 128;
        innerIpHeader->ip_proto = VR_IP_PROTO_UDP;
        innerIpHeader->ip_csum = 0;
        innerIpHeader->ip_saddr = htonl(0x0a000003);
        innerIpHeader->ip_daddr = htonl(0x0a000004);
    }

    uint8_t payload[] = {0x31, 0x32, 0x33, 0x34};
    struct vr_udp *innerUdpHeader = (struct vr_udp *)(innerIpHeader + 1);
    {
        innerUdpHeader->udp_sport = htons(11111);
        innerUdpHeader->udp_dport = htons(22222);
        innerUdpHeader->udp_length = htons(sizeof(*innerUdpHeader) + ARRAYSIZE(payload));
        innerUdpHeader->udp_csum = htons(0x1424);
    }

    uint8_t *innerPayload = (uint8_t *)(innerUdpHeader + 1);
    memcpy(innerPayload, payload, ARRAYSIZE(payload));

    struct vr_interface *vif = AllocateFakeInterface();

    struct vr_packet *vrPacket = AllocateVrPacketNonOwned();
    {
        vrPacket->vp_head = buffer;
        vrPacket->vp_if = vif;
        vrPacket->vp_nh = NULL;
        vrPacket->vp_data = 0; // TODO: Fill? Field is not used in this test case.
        vrPacket->vp_tail = 0; // TODO: Fill? Field is not used in this test case.
        vrPacket->vp_len = 0; // TODO: Fill? Field is not used in this test case.
        vrPacket->vp_end = 0; // TODO: Fill? Field is not used in this test case.
        vrPacket->vp_network_h = 0; // TODO: Fill? Field is not used in this test case.
        vrPacket->vp_flags = VP_FLAG_FLOW_SET;
        vrPacket->vp_inner_network_h = (intptr_t)innerIpHeader - (intptr_t)buffer;
        vrPacket->vp_cpu = 0;
        vrPacket->vp_type = VP_TYPE_IPOIP;
        vrPacket->vp_ttl = 64;
        vrPacket->vp_queue = 0;
        vrPacket->vp_priority = VP_PRIORITY_INVALID;
        vrPacket->vp_notused = 0;
    }

    PVR_PACKET_WRAPPER wrapper = GetWrapperFromVrPacket(vrPacket);
    PWIN_PACKET winPkt = wrapper->WinPacket;
    PWIN_PACKET_RAW rawPkt = WinPacketToRawPacket(winPkt);
    PWIN_SUB_PACKET subPkt = WinPacketRawGetFirstSubPacket(rawPkt);
    Fake_WinSubPacketSetData(subPkt, buffer, 84 + ARRAYSIZE(payload));

    return vrPacket;
}

static struct vr_packet *
UdpPacketOverMplsOverUdp()
{
    uint8_t *buffer = test_calloc(4096, 1);

    // NOTE: Ethernet header does not affect packet postprocessing. Initialization not needed.
    struct vr_eth *outerEthHeader = (struct vr_eth *)(buffer);

    struct vr_ip *outerIpHeader = (struct vr_ip *)(outerEthHeader + 1);
    {
        outerIpHeader->ip_hl = 5;
        outerIpHeader->ip_version = 4;
        outerIpHeader->ip_tos = 0;
        outerIpHeader->ip_len = htons(1546);
        outerIpHeader->ip_id = htons(44);
        outerIpHeader->ip_frag_off = 0;
        outerIpHeader->ip_ttl = 64;
        outerIpHeader->ip_proto = VR_IP_PROTO_UDP;
        outerIpHeader->ip_csum = htons(0x1C94);
        outerIpHeader->ip_saddr = htonl(0xAC100001);
        outerIpHeader->ip_daddr = htonl(0xAC100002);
    }

    struct vr_udp *outerUdpHeader = (struct vr_udp *)(outerIpHeader + 1);
    {
        outerUdpHeader->udp_sport = htons(49152);
        outerUdpHeader->udp_dport = htons(6635);
        outerUdpHeader->udp_length = htons(1526);
        outerUdpHeader->udp_csum = 0;
    }

    // NOTE: MPLS header does not affect packet postprocessing. Initialization not needed.
    uint32_t *mplsHeader = (uint32_t *)(outerUdpHeader + 1);

    struct vr_eth *innerEthHeader = (struct vr_eth *)(mplsHeader + 1);
    {
        uint8_t smac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x03};
        uint8_t dmac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x04};

        VR_MAC_COPY(innerEthHeader->eth_dmac, dmac);
        VR_MAC_COPY(innerEthHeader->eth_smac, smac);
        innerEthHeader->eth_proto = htons(VR_ETH_PROTO_IP);
    }

    struct vr_ip *innerIpHeader = (struct vr_ip *)(innerEthHeader + 1);
    {
        innerIpHeader->ip_hl = 5;
        innerIpHeader->ip_version = 4;
        innerIpHeader->ip_tos = 0;
        innerIpHeader->ip_len = htons(1500);
        innerIpHeader->ip_id = htons(3100);
        innerIpHeader->ip_frag_off = htons(VR_IP_MF);
        innerIpHeader->ip_ttl = 128;
        innerIpHeader->ip_proto = VR_IP_PROTO_UDP;
        innerIpHeader->ip_csum = 0;
        innerIpHeader->ip_saddr = htonl(0x0a000004);
        innerIpHeader->ip_daddr = htonl(0x0a000003);
    }

    struct vr_udp *innerUdpHeader = (struct vr_udp *)(innerIpHeader + 1);
    {
        innerUdpHeader->udp_sport = htons(11111);
        innerUdpHeader->udp_dport = htons(22222);
        innerUdpHeader->udp_length = htons(2608); // NOTE: ('a...z' * 100) + UDP HEADER
        innerUdpHeader->udp_csum = htons(0xa08c);
    }

    uint8_t payload[4096] = { 0 };
    for (unsigned int i = 0; i < 100; ++i) {
        for (char x = 'a'; x <= 'z'; ++x) {
            payload[i * 26 + (unsigned int)x] = x;
        }
    }
    size_t firstFragmentSize = 1472;

    uint8_t *innerPayload = (uint8_t *)(innerUdpHeader + 1);
    memcpy(innerPayload, payload, firstFragmentSize);

    struct vr_interface *vif = AllocateFakeInterface();
    struct vr_packet *vrPacket = AllocateVrPacketNonOwned();
    {
        vrPacket->vp_head = buffer;
        vrPacket->vp_if = vif;
        vrPacket->vp_nh = NULL;
        vrPacket->vp_data = 0; // TODO: Fill? Field is not used in this test case.
        vrPacket->vp_tail = 0; // TODO: No magic. Originally 0x618.
        vrPacket->vp_len = 0; // TODO: No magic. Originally 0x618.
        vrPacket->vp_end = 0; // TODO: No magic. Originally 0x618.
        vrPacket->vp_network_h = 0xe; // TODO: No magic.
        vrPacket->vp_flags = VP_FLAG_FLOW_SET;
        vrPacket->vp_inner_network_h = 0x3c; // TODO: No magic.
        vrPacket->vp_cpu = 0;
        vrPacket->vp_type = VP_TYPE_IPOIP;
        vrPacket->vp_ttl = 64;
        vrPacket->vp_queue = 0;
        vrPacket->vp_priority = VP_PRIORITY_INVALID;
        vrPacket->vp_notused = 0;
    }

    PVR_PACKET_WRAPPER wrapper = GetWrapperFromVrPacket(vrPacket);
    PWIN_PACKET winPkt = wrapper->WinPacket;
    PWIN_PACKET_RAW rawPkt = WinPacketToRawPacket(winPkt);
    PWIN_SUB_PACKET subPkt = WinPacketRawGetFirstSubPacket(rawPkt);
    Fake_WinSubPacketSetData(subPkt, buffer, 1560); // TODO: Calculate length.

    return vrPacket;
}

static void
FreePacket(struct vr_packet *VrPacket)
{
    test_free(VrPacket->vp_head);
    FreeFakeInterface(VrPacket->vp_if);
    FreeVrPacket(VrPacket);
}

typedef enum
{
    NO_OFFLOADS   = 0,
    IP_OFFLOADED  = 1 << 0,
    UDP_OFFLOADED = 1 << 1,
    TCP_OFFLOADED = 1 << 2,
} ChecksumOffloadFlag;

static void
AssertMultiPktChecksumsOffloadStatus(PWIN_MULTI_PACKET Packet, ChecksumOffloadFlag Offload)
{
    PWIN_PACKET_RAW rawPkt = WinMultiPacketToRawPacket(Packet);

    if (Offload & IP_OFFLOADED) {
        assert_true(WinPacketRawShouldIpChecksumBeOffloaded(rawPkt));
    } else {
        assert_false(WinPacketRawShouldIpChecksumBeOffloaded(rawPkt));
    }

    if (Offload & UDP_OFFLOADED) {
        assert_true(WinPacketRawShouldUdpChecksumBeOffloaded(rawPkt));
    } else {
        assert_false(WinPacketRawShouldUdpChecksumBeOffloaded(rawPkt));
    }

    if (Offload & TCP_OFFLOADED) {
        assert_true(WinPacketRawShouldTcpChecksumBeOffloaded(rawPkt));
    } else {
        assert_false(WinPacketRawShouldTcpChecksumBeOffloaded(rawPkt));
    }
}

static void
AssertVrPktChecksumsOffloadStatus(struct vr_packet *VrPacket, ChecksumOffloadFlag Offload)
{
    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(VrPacket);
    PWIN_PACKET_RAW winPacketRaw = WinPacketToRawPacket(winPacket);
    PWIN_MULTI_PACKET multiPacket = (PWIN_MULTI_PACKET)winPacketRaw;

    AssertMultiPktChecksumsOffloadStatus(multiPacket, Offload);
}

static void *
GetBufferFromMultiPacket(PWIN_MULTI_PACKET Packet)
{
    PWIN_PACKET_RAW rawPkt = WinMultiPacketToRawPacket(Packet);
    PWIN_SUB_PACKET subPkt = WinPacketRawGetFirstSubPacket(rawPkt);
    return Fake_WinSubPacketGetData(subPkt);
}

static void
AssertOuterIpCsumValue(PWIN_MULTI_PACKET Packet, uint16_t Checksum)
{
    void *buffer = GetBufferFromMultiPacket(Packet);

    struct vr_eth *outerEthHeader = (struct vr_eth *)(buffer);
    struct vr_ip *outerIpHeader = (struct vr_ip *)(outerEthHeader + 1);

    assert_int_equal(outerIpHeader->ip_csum, htons(Checksum));
}

static struct vr_ip *
GetInnerIpHeaderFromBuffer(void *buffer)
{
    struct vr_eth *outerEthHeader = (struct vr_eth *)(buffer);
    struct vr_ip *outerIpHeader = (struct vr_ip *)(outerEthHeader + 1);
    struct vr_gre *greHeader = (struct vr_gre *)(outerIpHeader + 1);
    uint32_t *mplsHeader = (uint32_t *)(greHeader + 1);
    struct vr_eth *innerEthHeader = (struct vr_eth *)(mplsHeader + 1);
    struct vr_ip *innerIpHeader = (struct vr_ip *)(innerEthHeader + 1);

    return innerIpHeader;
}

static void
AssertInnerIpCsumValue(PWIN_MULTI_PACKET Packet, uint16_t Checksum)
{
    void *buffer = GetBufferFromMultiPacket(Packet);
    struct vr_ip *innerIpHeader = GetInnerIpHeaderFromBuffer(buffer);

    assert_int_equal(innerIpHeader->ip_csum, htons(Checksum));
}

static void
AssertInnerUdpCsumValue(PWIN_MULTI_PACKET Packet, uint16_t Checksum)
{
    void *buffer = GetBufferFromMultiPacket(Packet);
    struct vr_ip *innerIpHeader = GetInnerIpHeaderFromBuffer(buffer);
    struct vr_udp *innerUdpHeader = (struct vr_udp *)(innerIpHeader + 1);

    assert_int_equal(innerUdpHeader->udp_csum, htons(Checksum));
}

static void
FreeWinMultiPacket(PWIN_MULTI_PACKET Packet)
{
    PWIN_PACKET_RAW rawPacket = WinMultiPacketToRawPacket(Packet);
    PWIN_PACKET_RAW parent = WinPacketRawGetParentOf(rawPacket);

    Fake_WinMultiPacketFree(Packet);
    WinPacketRawDecrementChildCountOf(parent);
}

static void
AssertFirstFragmentIsValid(PWIN_SUB_PACKET SubPacket)
{
    void *buffer = Fake_WinSubPacketGetData(SubPacket);

    struct vr_eth *outerEthHeader = (struct vr_eth *)(buffer);
    struct vr_ip *outerIpHeader = (struct vr_ip *)(outerEthHeader + 1);

    assert_int_equal(outerIpHeader->ip_len, htons(1498));
    assert_int_equal(outerIpHeader->ip_csum, htons(0x1CC4));
    assert_int_equal(outerIpHeader->ip_saddr, htonl(0xAC100001));
    assert_int_equal(outerIpHeader->ip_daddr, htonl(0xAC100002));

    struct vr_udp *outerUdpHeader = (struct vr_udp *)(outerIpHeader + 1);

    // TODO: csum

    uint32_t *mplsHeader = (uint32_t *)(outerUdpHeader + 1);
    struct vr_eth *innerEthHeader = (struct vr_eth *)(mplsHeader + 1);
    struct vr_ip *innerIpHeader = (struct vr_ip *)(innerEthHeader + 1);

    assert_int_equal(innerIpHeader->ip_len, htons(1452));
    assert_int_equal(innerIpHeader->ip_csum, htons(0xF51C));
    assert_int_equal(innerIpHeader->ip_saddr, htonl(0x0a000004));
    assert_int_equal(innerIpHeader->ip_daddr, htonl(0x0a000003));

    assert_int_equal(innerIpHeader->ip_frag_off, htons(VR_IP_MF | 0));
}

static void
AssertSecondFragmentIsValid(PWIN_SUB_PACKET SubPacket)
{
    void *buffer = Fake_WinSubPacketGetData(SubPacket);

    struct vr_eth *outerEthHeader = (struct vr_eth *)(buffer);
    struct vr_ip *outerIpHeader = (struct vr_ip *)(outerEthHeader + 1);

    assert_int_equal(outerIpHeader->ip_len, htons(114));
    assert_int_equal(outerIpHeader->ip_csum, htons(0x222C));
    assert_int_equal(outerIpHeader->ip_saddr, htonl(0xAC100001));
    assert_int_equal(outerIpHeader->ip_daddr, htonl(0xAC100002));

    struct vr_udp *outerUdpHeader = (struct vr_udp *)(outerIpHeader + 1);

    // TODO: csum

    uint32_t *mplsHeader = (uint32_t *)(outerUdpHeader + 1);
    struct vr_eth *innerEthHeader = (struct vr_eth *)(mplsHeader + 1);
    struct vr_ip *innerIpHeader = (struct vr_ip *)(innerEthHeader + 1);

    assert_int_equal(innerIpHeader->ip_len, htons(68));
    assert_int_equal(innerIpHeader->ip_csum, htons(0xF9D1));
    assert_int_equal(innerIpHeader->ip_saddr, htonl(0x0a000004));
    assert_int_equal(innerIpHeader->ip_daddr, htonl(0x0a000003));

    assert_int_equal(innerIpHeader->ip_frag_off, htons(VR_IP_MF | 179));
}

static void
AssertPayloadMatch(struct vr_packet *OriginalPacket,
    PWIN_SUB_PACKET FirstSubPacket, PWIN_SUB_PACKET SecondSubPacket)
{
    PWIN_PACKET originalWinPacket = GetWinPacketFromVrPacket(OriginalPacket);
    PWIN_PACKET_RAW originalRawPacket = WinPacketToRawPacket(originalWinPacket);
    PWIN_SUB_PACKET originalSubPacket = WinPacketRawGetFirstSubPacket(originalRawPacket);

    size_t headersSize = sizeof(struct vr_eth) + sizeof(struct vr_ip) +
        sizeof(struct vr_udp) + sizeof(uint32_t) +
        sizeof(struct vr_eth) + sizeof(struct vr_ip);

    size_t originalPayloadSize = Fake_WinSubPacketGetDataSize(originalSubPacket) - headersSize;
    uint8_t *originalPacketData = Fake_WinSubPacketGetData(originalSubPacket);
    uint8_t *originalPayload = originalPacketData + headersSize;

    size_t firstPayloadSize = Fake_WinSubPacketGetDataSize(FirstSubPacket) - headersSize;
    uint8_t *firstPacketData = Fake_WinSubPacketGetData(FirstSubPacket);
    uint8_t *firstPayload = firstPacketData + headersSize;

    size_t secondPayloadSize = Fake_WinSubPacketGetDataSize(SecondSubPacket) - headersSize;
    uint8_t *secondPacketData = Fake_WinSubPacketGetData(SecondSubPacket);
    uint8_t *secondPayload = secondPacketData + headersSize;

    assert_int_equal(originalPayloadSize, firstPayloadSize + secondPayloadSize);
    assert_true(memcmp(originalPayload, firstPayload, firstPayloadSize) == 0);
    assert_true(memcmp(originalPayload + firstPayloadSize, secondPayload, secondPayloadSize) == 0);
}

static void
Test_win_tx_pp_ArpPacket(void **state)
{
    PVR_PACKET_WRAPPER wrapper = test_calloc(1, sizeof(*wrapper));
    struct vr_packet *packet = &wrapper->VrPacket;
    packet->vp_type = VP_TYPE_ARP;
    packet->vp_if = AllocateFakeInterface();

    PWIN_MULTI_PACKET result = WinTxPostprocess(packet);

    PWIN_MULTI_PACKET expected = NULL;
    assert_ptr_equal(result, expected);

    test_free(packet->vp_if);
    test_free(wrapper);
}

static void
Test_win_tx_pp_SmallIpUdpOverTunnelPacket(void **state)
{
    struct vr_packet *vrPacket = MPLSoGREPacket();
    AssertVrPktChecksumsOffloadStatus(vrPacket, IP_OFFLOADED | UDP_OFFLOADED);

    PWIN_MULTI_PACKET result = WinTxPostprocess(vrPacket);

    assert_ptr_not_equal(result, NULL);
    AssertOuterIpCsumValue(result, 0);
    AssertInnerIpCsumValue(result, 0xD375);
    AssertInnerUdpCsumValue(result, 0x0534);
    AssertMultiPktChecksumsOffloadStatus(result, IP_OFFLOADED);

    FreePacket(vrPacket);
}

static void
Test_win_tx_pp_FragmentedUdpOverMplsOverUdp(void **state)
{
    struct vr_packet *vrPacket = UdpPacketOverMplsOverUdp();
    AssertVrPktChecksumsOffloadStatus(vrPacket, IP_OFFLOADED | UDP_OFFLOADED);

    PWIN_MULTI_PACKET result = WinTxPostprocess(vrPacket);

    assert_ptr_not_equal(result, NULL);
    AssertMultiPktChecksumsOffloadStatus(result, NO_OFFLOADS);

    PWIN_PACKET_RAW resultPacket = WinMultiPacketToRawPacket(result);
    PWIN_SUB_PACKET firstFragment = WinPacketRawGetFirstSubPacket(resultPacket);
    assert_non_null(firstFragment);

    PWIN_SUB_PACKET secondFragment = WinSubPacketRawGetNext(firstFragment);
    assert_non_null(secondFragment);

    PWIN_SUB_PACKET notAFragment = WinSubPacketRawGetNext(secondFragment);
    assert_null(notAFragment);

    AssertFirstFragmentIsValid(firstFragment);
    AssertSecondFragmentIsValid(secondFragment);
    AssertPayloadMatch(vrPacket, firstFragment, secondFragment);

    FreeWinMultiPacket(result);
    FreePacket(vrPacket);
}

#define win_tx_pp_test(f) cmocka_unit_test(Test_win_tx_pp_##f)

int main(void) {
    const struct CMUnitTest tests[] = {
        win_tx_pp_test(ArpPacket),
        win_tx_pp_test(SmallIpUdpOverTunnelPacket),
        win_tx_pp_test(FragmentedUdpOverMplsOverUdp),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
