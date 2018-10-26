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
    Fake_WinPacketRawSetOffloadInfo(rawPkt, true, true, false);

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

static unsigned short
CalculateIpHeaderOffset(struct vr_eth *EthHeader, struct vr_ip *IpHeader)
{
    uintptr_t ethHeaderAddr = (uintptr_t)EthHeader;
    uintptr_t ipHeaderAddr = (uintptr_t)IpHeader;
    assert_true(ipHeaderAddr > ethHeaderAddr);
    return (unsigned short)(ipHeaderAddr - ethHeaderAddr);
}

static void
GeneratePayloadAndFillAfterUdp(struct vr_udp* UdpHeader, size_t FragmentSize)
{
    enum { MaxPayloadLength = 2600 };

    assert_true(FragmentSize < MaxPayloadLength);

    uint8_t payload[MaxPayloadLength] = { 0 };
    for (unsigned int i = 0; i < 100; ++i) {
        for (char x = 'a'; x <= 'z'; ++x) {
            payload[i * 26 + ((unsigned int)x - 'a')] = x;
        }
    }

    uint8_t *innerPayload = (uint8_t *)(UdpHeader + 1);
    memcpy(innerPayload, payload, FragmentSize);
}

static struct vr_packet *
UdpPacketOverMplsOverUdp()
{
    uint8_t *buffer = test_calloc(4096, 1);

    // NOTE: Ethernet header does not affect packet postprocessing. Initialization not needed.
    struct vr_eth *outerEthHeader = (struct vr_eth *)(buffer);

    struct vr_ip *outerIpHeader = (struct vr_ip *)(outerEthHeader + 1);
    {
        outerIpHeader->ip_hl = sizeof(*outerIpHeader) / 4;
        outerIpHeader->ip_version = 4;
        outerIpHeader->ip_tos = 0;
        outerIpHeader->ip_len = htons(
            sizeof(struct vr_ip) + sizeof(struct vr_udp) + sizeof(uint32_t) +
            sizeof(struct vr_eth) + 1500
        );
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
        innerIpHeader->ip_hl = sizeof(*innerIpHeader) / 4;
        innerIpHeader->ip_version = 4;
        innerIpHeader->ip_tos = 0;
        innerIpHeader->ip_len = htons(1500);
        innerIpHeader->ip_id = htons(3100);
        innerIpHeader->ip_frag_off = htons(VR_IP_MF);
        innerIpHeader->ip_ttl = 128;
        innerIpHeader->ip_proto = VR_IP_PROTO_UDP;
        innerIpHeader->ip_csum = 0;
        innerIpHeader->ip_saddr = htonl(0x0a010004);
        innerIpHeader->ip_daddr = htonl(0x0a010003);
    }

    struct vr_udp *innerUdpHeader = (struct vr_udp *)(innerIpHeader + 1);
    {
        innerUdpHeader->udp_sport = htons(11111);
        innerUdpHeader->udp_dport = htons(22222);
        innerUdpHeader->udp_length = htons(2608); // NOTE: Payload was ('a...z' * 100) + UDP HEADER
        innerUdpHeader->udp_csum = htons(0xa08c);
    }

    size_t fragmentedUdpPayloadSize = 1472;
    GeneratePayloadAndFillAfterUdp(innerUdpHeader, fragmentedUdpPayloadSize);

    struct vr_interface *vif = AllocateFakeInterface();
    struct vr_packet *vrPacket = AllocateVrPacketNonOwned();
    {
        vrPacket->vp_head = buffer;
        vrPacket->vp_if = vif;
        vrPacket->vp_nh = NULL;
        vrPacket->vp_data = 0;
        vrPacket->vp_tail = 0; // NOTE: Not used.
        vrPacket->vp_len = 0; // NOTE: Not used.
        vrPacket->vp_end = 0; // NOTE: Not used.
        vrPacket->vp_network_h = CalculateIpHeaderOffset(outerEthHeader, outerIpHeader);
        vrPacket->vp_flags = VP_FLAG_FLOW_SET;
        vrPacket->vp_inner_network_h = CalculateIpHeaderOffset(outerEthHeader, innerIpHeader);
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

    size_t subPacketLength = sizeof(*outerEthHeader)
                           + sizeof(*outerIpHeader)
                           + sizeof(*outerUdpHeader)
                           + sizeof(*mplsHeader)
                           + sizeof(*innerEthHeader)
                           + sizeof(*innerIpHeader)
                           + sizeof(*innerUdpHeader)
                           + fragmentedUdpPayloadSize;
    Fake_WinSubPacketSetData(subPkt, buffer, subPacketLength);
    Fake_WinPacketRawSetOffloadInfo(rawPkt, true, true, false);

    return vrPacket;
}

static struct vr_packet *
TcpPacketOverMplsOverUdp()
{
    size_t headerSize = sizeof(struct vr_eth) + sizeof(struct vr_ip) + sizeof(struct vr_udp) + sizeof(uint32_t)
        + sizeof(struct vr_eth) + sizeof(struct vr_ip) + sizeof(struct vr_tcp);

    size_t dataSize = 5000;

    uint8_t *buffer = test_calloc(headerSize + dataSize, 1);

    // NOTE: Ethernet header does not affect packet postprocessing. Initialization not needed.
    struct vr_eth *outerEthHeader = (struct vr_eth *)(buffer);
    {
        uint8_t smac[6] = {0x00, 0x50, 0x56, 0x8C, 0x94, 0xEA};
        uint8_t dmac[6] = {0x00, 0x50, 0x56, 0x8C, 0x4A, 0x77};

        VR_MAC_COPY(outerEthHeader->eth_dmac, dmac);
        VR_MAC_COPY(outerEthHeader->eth_smac, smac);
        outerEthHeader->eth_proto = htons(VR_ETH_PROTO_IP);
    }

    struct vr_ip *outerIpHeader = (struct vr_ip *)(outerEthHeader + 1);
    {
        outerIpHeader->ip_hl = sizeof(*outerIpHeader) / 4;
        outerIpHeader->ip_version = 4;
        outerIpHeader->ip_tos = 0;
        outerIpHeader->ip_len = htons(
            headerSize - sizeof(struct vr_eth) + dataSize
        );
        outerIpHeader->ip_id = htons(392);
        outerIpHeader->ip_frag_off = 0;
        outerIpHeader->ip_ttl = 64;
        outerIpHeader->ip_proto = VR_IP_PROTO_UDP;
        outerIpHeader->ip_csum = htons(0x0D50);
        outerIpHeader->ip_saddr = htonl(0xAC10000B);
        outerIpHeader->ip_daddr = htonl(0xAC10000C);
    }

    struct vr_udp *outerUdpHeader = (struct vr_udp *)(outerIpHeader + 1);
    {
        outerUdpHeader->udp_sport = htons(49152);
        outerUdpHeader->udp_dport = htons(6635);
        outerUdpHeader->udp_length = htons(headerSize - sizeof(struct vr_eth) - sizeof(struct vr_ip) + dataSize);
        outerUdpHeader->udp_csum = 0;
    }

    // NOTE: MPLS header does not affect packet postprocessing. Initialization not needed.
    uint32_t *mplsHeader = (uint32_t *)(outerUdpHeader + 1);

    struct vr_eth *innerEthHeader = (struct vr_eth *)(mplsHeader + 1);

    struct vr_ip *innerIpHeader = (struct vr_ip *)(innerEthHeader + 1);
    {
        innerIpHeader->ip_hl = sizeof(*innerIpHeader) / 4;
        innerIpHeader->ip_version = 4;
        innerIpHeader->ip_tos = 2 + (0 << 2);
        innerIpHeader->ip_len = htons(0);
        innerIpHeader->ip_id = htons(16658);
        innerIpHeader->ip_frag_off = htons(VR_IP_DF);
        innerIpHeader->ip_ttl = 128;
        innerIpHeader->ip_proto = VR_IP_PROTO_TCP;
        innerIpHeader->ip_csum = 0;
        innerIpHeader->ip_saddr = htonl(0x0a000103);
        innerIpHeader->ip_daddr = htonl(0x0a000104);
    }

    struct vr_tcp *innerTcpHeader = (struct vr_tcp *)(innerIpHeader + 1);
    {
        innerTcpHeader->tcp_sport = htons(11111);
        innerTcpHeader->tcp_dport = htons(22222);
        innerTcpHeader->tcp_seq = htonl(0xac5c9eb7);
        innerTcpHeader->tcp_ack = htonl(0xab2b2229);
        innerTcpHeader->tcp_offset_r_flags = htons(VR_TCP_FLAG_PSH | VR_TCP_FLAG_ACK | ((20/4) << 12));
        innerTcpHeader->tcp_win = htons(8212);
        innerTcpHeader->tcp_csum = htons(0x160D);
        innerTcpHeader->tcp_urg = htons(0);
    }

    memset(buffer + headerSize, '1', dataSize);

    struct vr_interface *vif = AllocateFakeInterface();
    struct vr_packet *vrPacket = AllocateVrPacketNonOwned();
    {
        vrPacket->vp_head = buffer;
        vrPacket->vp_if = vif;
        vrPacket->vp_nh = NULL;
        vrPacket->vp_data = 0;
        vrPacket->vp_tail = 0; // NOTE: Not used.
        vrPacket->vp_len = 0; // NOTE: Not used.
        vrPacket->vp_end = 0; // NOTE: Not used.
        vrPacket->vp_network_h = CalculateIpHeaderOffset(outerEthHeader, outerIpHeader);
        vrPacket->vp_flags = VP_FLAG_FLOW_SET;
        vrPacket->vp_inner_network_h = CalculateIpHeaderOffset(outerEthHeader, innerIpHeader);
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

    Fake_WinSubPacketSetData(subPkt, buffer, headerSize + dataSize);
    Fake_WinPacketRawSetOffloadInfo(rawPkt, false, false, true);

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
    IPCHKSUM_OFFLOADED  = 1 << 0,
    UDPCHKSUM_OFFLOADED = 1 << 1,
    TCPPCHKSUM_OFFLOADED = 1 << 2,
    SEG_OFFLOADED = 1 << 3,
} OffloadFlag;

static void
AssertMultiPktOffloadStatus(PWIN_MULTI_PACKET Packet, OffloadFlag Offload)
{
    PWIN_PACKET_RAW rawPkt = WinMultiPacketToRawPacket(Packet);

    if (Offload & IPCHKSUM_OFFLOADED) {
        assert_true(WinPacketRawShouldIpChecksumBeOffloaded(rawPkt));
    } else {
        assert_false(WinPacketRawShouldIpChecksumBeOffloaded(rawPkt));
    }

    if (Offload & UDPCHKSUM_OFFLOADED) {
        assert_true(WinPacketRawShouldUdpChecksumBeOffloaded(rawPkt));
    } else {
        assert_false(WinPacketRawShouldUdpChecksumBeOffloaded(rawPkt));
    }

    if (Offload & TCPPCHKSUM_OFFLOADED) {
        assert_true(WinPacketRawShouldTcpChecksumBeOffloaded(rawPkt));
    } else {
        assert_false(WinPacketRawShouldTcpChecksumBeOffloaded(rawPkt));
    }

    if (Offload & SEG_OFFLOADED) {
        assert_true(WinPacketRawShouldSegmentationBeOffloaded(rawPkt));
    } else {
        assert_false(WinPacketRawShouldSegmentationBeOffloaded(rawPkt));
    }
}

static void
AssertVrPktOffloadStatus(struct vr_packet *VrPacket, OffloadFlag Offload)
{
    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(VrPacket);
    PWIN_PACKET_RAW winPacketRaw = WinPacketToRawPacket(winPacket);
    PWIN_MULTI_PACKET multiPacket = (PWIN_MULTI_PACKET)winPacketRaw;

    AssertMultiPktOffloadStatus(multiPacket, Offload);
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
    assert_int_equal(outerUdpHeader->udp_csum, htons(0));

    uint32_t *mplsHeader = (uint32_t *)(outerUdpHeader + 1);
    struct vr_eth *innerEthHeader = (struct vr_eth *)(mplsHeader + 1);
    struct vr_ip *innerIpHeader = (struct vr_ip *)(innerEthHeader + 1);

    assert_int_equal(innerIpHeader->ip_len, htons(1452));
    assert_int_equal(innerIpHeader->ip_csum, htons(0xF51C));
    assert_int_equal(innerIpHeader->ip_saddr, htonl(0x0a010004));
    assert_int_equal(innerIpHeader->ip_daddr, htonl(0x0a010003));

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
    assert_int_equal(outerUdpHeader->udp_csum, htons(0));

    uint32_t *mplsHeader = (uint32_t *)(outerUdpHeader + 1);
    struct vr_eth *innerEthHeader = (struct vr_eth *)(mplsHeader + 1);
    struct vr_ip *innerIpHeader = (struct vr_ip *)(innerEthHeader + 1);

    assert_int_equal(innerIpHeader->ip_len, htons(68));
    assert_int_equal(innerIpHeader->ip_csum, htons(0xF9D1));
    assert_int_equal(innerIpHeader->ip_saddr, htonl(0x0a010004));
    assert_int_equal(innerIpHeader->ip_daddr, htonl(0x0a010003));

    assert_int_equal(innerIpHeader->ip_frag_off, htons(VR_IP_MF | (1432 / 8)));
}

static void
AssertFragmentsAreValid(PWIN_MULTI_PACKET Fragments)
{
    PWIN_PACKET_RAW resultPacket = WinMultiPacketToRawPacket(Fragments);
    PWIN_SUB_PACKET firstFragment = WinPacketRawGetFirstSubPacket(resultPacket);
    assert_non_null(firstFragment);

    PWIN_SUB_PACKET secondFragment = WinSubPacketRawGetNext(firstFragment);
    assert_non_null(secondFragment);

    PWIN_SUB_PACKET notAFragment = WinSubPacketRawGetNext(secondFragment);
    assert_null(notAFragment);

    AssertFirstFragmentIsValid(firstFragment);
    AssertSecondFragmentIsValid(secondFragment);
}

static void
AssertPayloadMatch(struct vr_packet *OriginalPacket,
    PWIN_MULTI_PACKET ResultPacket, size_t headersSize)
{
    PWIN_PACKET originalWinPacket = GetWinPacketFromVrPacket(OriginalPacket);
    PWIN_PACKET_RAW originalRawPacket = WinPacketToRawPacket(originalWinPacket);
    PWIN_SUB_PACKET originalSubPacket = WinPacketRawGetFirstSubPacket(originalRawPacket);

    size_t originalPayloadSize = Fake_WinSubPacketGetDataSize(originalSubPacket) - headersSize;
    uint8_t *originalPacketData = Fake_WinSubPacketGetData(originalSubPacket);
    uint8_t *originalPayload = originalPacketData + headersSize;

    PWIN_PACKET_RAW rawResultPacket = WinMultiPacketToRawPacket(ResultPacket);
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

static void
AssertFirstSegmentIsValid(PWIN_SUB_PACKET SubPacket)
{
    void *buffer = Fake_WinSubPacketGetData(SubPacket);

    struct vr_eth *outerEthHeader = (struct vr_eth *)(buffer);
    struct vr_ip *outerIpHeader = (struct vr_ip *)(outerEthHeader + 1);
    struct vr_udp *outerUdpHeader = (struct vr_udp *)(outerIpHeader + 1);
    uint32_t *mplsHeader = (uint32_t *)(outerUdpHeader + 1);
    struct vr_eth *innerEthHeader = (struct vr_eth *)(mplsHeader + 1);
    struct vr_ip *innerIpHeader = (struct vr_ip *)(innerEthHeader + 1);
    struct vr_tcp *innerTcpHeader = (struct vr_tcp *)(innerIpHeader + 1);

    assert_int_equal(outerIpHeader->ip_len, htons(1386));
    assert_int_equal(outerIpHeader->ip_csum, htons(0x1BC4));
    assert_int_equal(outerIpHeader->ip_saddr, htonl(0xAC10000B));
    assert_int_equal(outerIpHeader->ip_daddr, htonl(0xAC10000C));

    assert_int_equal(outerUdpHeader->udp_csum, htons(0));

    assert_int_equal(innerIpHeader->ip_len, htons(1340));
    assert_int_equal(innerIpHeader->ip_csum, htons(0x9EA1));
    assert_int_equal(innerIpHeader->ip_saddr, htonl(0x0A000103));
    assert_int_equal(innerIpHeader->ip_daddr, htonl(0x0A000104));
    assert_int_equal(innerIpHeader->ip_frag_off, htons(VR_IP_DF));

    assert_int_equal(innerTcpHeader->tcp_seq, htonl(0xac5c9eb7));
    assert_int_equal(innerTcpHeader->tcp_ack, htonl(0xab2b2229));
    assert_int_equal(innerTcpHeader->tcp_offset_r_flags, htons(VR_TCP_FLAG_ACK | ((20/4) << 12)));
    assert_int_equal(innerTcpHeader->tcp_win, htons(8212));
    assert_int_equal(innerTcpHeader->tcp_csum, htons(0xF320));
    assert_int_equal(innerTcpHeader->tcp_urg, htons(0));
}

static void
AssertLastSegmentIsValid(PWIN_SUB_PACKET SubPacket)
{
    void *buffer = Fake_WinSubPacketGetData(SubPacket);

    struct vr_eth *outerEthHeader = (struct vr_eth *)(buffer);
    struct vr_ip *outerIpHeader = (struct vr_ip *)(outerEthHeader + 1);
    struct vr_udp *outerUdpHeader = (struct vr_udp *)(outerIpHeader + 1);
    uint32_t *mplsHeader = (uint32_t *)(outerUdpHeader + 1);
    struct vr_eth *innerEthHeader = (struct vr_eth *)(mplsHeader + 1);
    struct vr_ip *innerIpHeader = (struct vr_ip *)(innerEthHeader + 1);
    struct vr_tcp *innerTcpHeader = (struct vr_tcp *)(innerIpHeader + 1);

    assert_int_equal(outerIpHeader->ip_len, htons(1186));
    assert_int_equal(outerIpHeader->ip_csum, htons(0x1C8C));
    assert_int_equal(outerIpHeader->ip_saddr, htonl(0xAC10000B));
    assert_int_equal(outerIpHeader->ip_daddr, htonl(0xAC10000C));

    assert_int_equal(outerUdpHeader->udp_csum, htons(0));

    assert_int_equal(innerIpHeader->ip_len, htons(1140));
    assert_int_equal(innerIpHeader->ip_csum, htons(0x9F69));
    assert_int_equal(innerIpHeader->ip_saddr, htonl(0x0a000103));
    assert_int_equal(innerIpHeader->ip_daddr, htonl(0x0a000104));
    assert_int_equal(innerIpHeader->ip_frag_off, htons(VR_IP_DF));

    assert_int_equal(innerTcpHeader->tcp_seq, htonl(0xac5cadf3));
    assert_int_equal(innerTcpHeader->tcp_ack, htonl(0xab2b2229));
    assert_int_equal(innerTcpHeader->tcp_offset_r_flags, htons(VR_TCP_FLAG_PSH | VR_TCP_FLAG_ACK | ((20/4) << 12)));
    assert_int_equal(innerTcpHeader->tcp_win, htons(8212));
    assert_int_equal(innerTcpHeader->tcp_csum, htons(0x1BDC));
    assert_int_equal(innerTcpHeader->tcp_urg, htons(0));
}

static void
AssertSegmentsAreValid(PWIN_MULTI_PACKET Segments)
{
    PWIN_PACKET_RAW resultPacket = WinMultiPacketToRawPacket(Segments);

    PWIN_SUB_PACKET firstSegment = WinPacketRawGetFirstSubPacket(resultPacket);
    assert_non_null(firstSegment);

    PWIN_SUB_PACKET secondSegment = WinSubPacketRawGetNext(firstSegment);
    assert_non_null(secondSegment);

    PWIN_SUB_PACKET thirdSegment = WinSubPacketRawGetNext(secondSegment);
    assert_non_null(thirdSegment);

    PWIN_SUB_PACKET fourthSegment = WinSubPacketRawGetNext(thirdSegment);
    assert_non_null(fourthSegment);

    PWIN_SUB_PACKET notASegment = WinSubPacketRawGetNext(fourthSegment);
    assert_null(notASegment);

    AssertFirstSegmentIsValid(firstSegment);
    AssertLastSegmentIsValid(fourthSegment);
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
    AssertVrPktOffloadStatus(vrPacket, IPCHKSUM_OFFLOADED | UDPCHKSUM_OFFLOADED);

    PWIN_MULTI_PACKET result = WinTxPostprocess(vrPacket);

    assert_ptr_not_equal(result, NULL);
    AssertOuterIpCsumValue(result, 0);
    AssertInnerIpCsumValue(result, 0xD375);
    AssertInnerUdpCsumValue(result, 0x0534);
    AssertMultiPktOffloadStatus(result, IPCHKSUM_OFFLOADED);

    FreePacket(vrPacket);
}

static void
Test_win_tx_pp_FragmentedUdpOverMplsOverUdp(void **state)
{
    struct vr_packet *vrPacket = UdpPacketOverMplsOverUdp();
    AssertVrPktOffloadStatus(vrPacket, IPCHKSUM_OFFLOADED | UDPCHKSUM_OFFLOADED);

    PWIN_MULTI_PACKET result = WinTxPostprocess(vrPacket);

    assert_ptr_not_equal(result, NULL);
    AssertMultiPktOffloadStatus(result, NO_OFFLOADS);
    AssertFragmentsAreValid(result);
    size_t headersSize = sizeof(struct vr_eth) + sizeof(struct vr_ip) +
        sizeof(struct vr_udp) + sizeof(uint32_t) +
        sizeof(struct vr_eth) + sizeof(struct vr_ip);
    AssertPayloadMatch(vrPacket, result, headersSize);

    FreeWinMultiPacket(result);
    FreePacket(vrPacket);
}

static void
Test_win_tx_pp_SegmentedTcpOverMplsOverUdp(void **state)
{
    struct vr_packet *vrPacket = TcpPacketOverMplsOverUdp();
    AssertVrPktOffloadStatus(vrPacket, SEG_OFFLOADED);

    PWIN_MULTI_PACKET result = WinTxPostprocess(vrPacket);

    assert_ptr_not_equal(result, NULL);
    AssertMultiPktOffloadStatus(result, NO_OFFLOADS);
    AssertSegmentsAreValid(result);
    size_t headersSize = sizeof(struct vr_eth) + sizeof(struct vr_ip) +
        sizeof(struct vr_udp) + sizeof(uint32_t) +
        sizeof(struct vr_eth) + sizeof(struct vr_ip) + sizeof(struct vr_tcp);
    AssertPayloadMatch(vrPacket, result, headersSize);

    FreeWinMultiPacket(result);
    FreePacket(vrPacket);
}

#define win_tx_pp_test(f) cmocka_unit_test(Test_win_tx_pp_##f)

int main(void) {
    const struct CMUnitTest tests[] = {
        win_tx_pp_test(ArpPacket),
        win_tx_pp_test(SmallIpUdpOverTunnelPacket),
        win_tx_pp_test(FragmentedUdpOverMplsOverUdp),
        win_tx_pp_test(SegmentedTcpOverMplsOverUdp),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
