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
    vif->vif_mtu = 1500;
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
        innerIpHeader->ip_hl = sizeof(*innerIpHeader) / 4;
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

        // The fields below are not used in this test case.
        vrPacket->vp_data = 0;
        vrPacket->vp_tail = 0;
        vrPacket->vp_len = 0;
        vrPacket->vp_end = 0;
        vrPacket->vp_network_h = 0;

        vrPacket->vp_flags = VP_FLAG_FLOW_SET;
        vrPacket->vp_inner_network_h = (intptr_t)innerIpHeader - (intptr_t)buffer;
        vrPacket->vp_cpu = 0;
        vrPacket->vp_type = VP_TYPE_IPOIP;
        vrPacket->vp_ttl = 64;
        vrPacket->vp_queue = 0;
        vrPacket->vp_priority = VP_PRIORITY_INVALID;
        vrPacket->vp_notused = 0;
    }

    size_t headersSize = (uint8_t *)innerPayload - buffer;

    PVR_PACKET_WRAPPER wrapper = GetWrapperFromVrPacket(vrPacket);
    PWIN_PACKET winPkt = wrapper->WinPacket;
    PWIN_PACKET_RAW rawPkt = WinPacketToRawPacket(winPkt);
    PWIN_SUB_PACKET subPkt = WinPacketRawGetFirstSubPacket(rawPkt);
    Fake_WinSubPacketSetData(subPkt, buffer, headersSize + ARRAYSIZE(payload));

    return vrPacket;
}

static struct vr_packet *
ARPPacket()
{
    size_t packetLength = 60; // Minimum Ethernet frame length
    uint8_t *buffer = test_calloc(packetLength, 1);

    // NOTE: Packet headers do not affect packet postprocessing. Initialization not needed.
    struct vr_eth *ethHeader = (struct vr_eth *)(buffer);
    struct vr_arp *arpHeader = (struct vr_arp *)(ethHeader + 1);

    struct vr_interface *vif = AllocateFakeInterface();

    struct vr_packet *vrPacket = AllocateVrPacketNonOwned();
    {
        vrPacket->vp_head = buffer;
        vrPacket->vp_if = vif;
        vrPacket->vp_nh = NULL;

        // The fields below are not used in this test case.
        vrPacket->vp_data = 0;
        vrPacket->vp_tail = 0;
        vrPacket->vp_len = 0;
        vrPacket->vp_end = 0;
        vrPacket->vp_network_h = 0;

        vrPacket->vp_flags = VP_FLAG_FLOW_SET;
        vrPacket->vp_inner_network_h = 0;
        vrPacket->vp_cpu = 0;
        vrPacket->vp_type = VP_TYPE_ARP;
        vrPacket->vp_ttl = 64;
        vrPacket->vp_queue = 0;
        vrPacket->vp_priority = VP_PRIORITY_INVALID;
        vrPacket->vp_notused = 0;
    }

    PVR_PACKET_WRAPPER wrapper = GetWrapperFromVrPacket(vrPacket);
    PWIN_PACKET winPkt = wrapper->WinPacket;
    PWIN_PACKET_RAW rawPkt = WinPacketToRawPacket(winPkt);
    PWIN_SUB_PACKET subPkt = WinPacketRawGetFirstSubPacket(rawPkt);
    Fake_WinSubPacketSetData(subPkt, buffer, packetLength);

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
    IP_OFFLOADED = 1 << 0,
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
Test_win_tx_pp_ArpPacket(void **state)
{
    struct vr_packet *packet = ARPPacket();

    PWIN_MULTI_PACKET result = WinTxPostprocess(packet);

    PWIN_PACKET originalPacket = GetWinPacketFromVrPacket(packet);
    assert_ptr_equal(result, originalPacket);

    FreePacket(packet);
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

#define win_tx_pp_test(f) cmocka_unit_test(Test_win_tx_pp_##f)

int main(void) {
    const struct CMUnitTest tests[] = {
        win_tx_pp_test(ArpPacket),
        win_tx_pp_test(SmallIpUdpOverTunnelPacket),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
