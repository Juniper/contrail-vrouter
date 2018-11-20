#include <setjmp.h>
#include <cmocka.h>
#include <allocation.h>
#include <common.h>
#include <asserts.h>
#include <win_packet.h>
#include <win_packet_impl.h>
#include <fake_win_packet.h>
#include <win_tx_postprocess.h>
#include <asserts_packets_headers.h>

#define HEADERS \
    HEADER(vr_eth, outerEthHeader) \
    HEADER(vr_ip, outerIpHeader) \
    HEADER(vr_gre, greHeader) \
    HEADER(vr_mpls, mplsHeader) \
    HEADER(vr_eth, innerEthHeader) \
    HEADER(vr_ip, innerIpHeader) \
    HEADER(vr_udp, innerUdpHeader)

#include "include\generate_headers_structure.h"

static void
FillHeaders_Test1(struct PacketHeaders *headers, size_t dataSize)
{
    memset(headers, 0, headersSize);

    uint8_t smac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x03};
    uint8_t dmac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x04};
    VR_MAC_COPY(headers->innerEthHeader.eth_dmac, dmac);
    VR_MAC_COPY(headers->innerEthHeader.eth_smac, smac);
    headers->innerEthHeader.eth_proto = htons(VR_ETH_PROTO_IP);

    headers->innerIpHeader.ip_hl = sizeof(headers->innerIpHeader) / 4;
    headers->innerIpHeader.ip_version = 4;
    headers->innerIpHeader.ip_tos = 0;
    headers->innerIpHeader.ip_len = htons(32);
    headers->innerIpHeader.ip_id = htons(0x5351);
    headers->innerIpHeader.ip_frag_off = 0;
    headers->innerIpHeader.ip_ttl = 128;
    headers->innerIpHeader.ip_proto = VR_IP_PROTO_UDP;
    headers->innerIpHeader.ip_csum = 0;
    headers->innerIpHeader.ip_saddr = htonl(0x0a000003);
    headers->innerIpHeader.ip_daddr = htonl(0x0a000004);

    headers->innerUdpHeader.udp_sport = htons(11111);
    headers->innerUdpHeader.udp_dport = htons(22222);
    headers->innerUdpHeader.udp_length = htons(sizeof(headers->innerUdpHeader) + dataSize);
    headers->innerUdpHeader.udp_csum = htons(0x1424);
}

static void
FillOutputHeaders_Test1(struct PacketHeaders *headers, size_t dataSize)
{
    FillHeaders_Test1(headers, dataSize);

    headers->innerUdpHeader.udp_csum = htons(0x0534);
    headers->innerIpHeader.ip_csum = htons(0xD375);
    headers->outerIpHeader.ip_csum = htons(0);
}

static void
GeneratePayload_Test1(uint8_t* data, size_t payloadSize)
{
    uint8_t payload[] = {0x31, 0x32, 0x33, 0x34};
    memcpy(data, payload, payloadSize);
}

static void
FillVrPacket_Test1(struct vr_packet* packet, struct PacketHeaders* headers)
{
    packet->vp_flags = VP_FLAG_FLOW_SET;
    packet->vp_inner_network_h = CountHeaderOffset(headers, innerIpHeader);
    packet->vp_type = VP_TYPE_IPOIP;
    packet->vp_ttl = 64;
    packet->vp_priority = VP_PRIORITY_INVALID;
}

static void Assert(struct vr_packet *originalVrPacket, struct vr_packet *processedVrPacket, PWIN_MULTI_PACKET result)
{
    assert_ptr_equal(result, GetWinPacketFromVrPacket(processedVrPacket));
    AssertMultiPktOffloadStatus(result, IPCHKSUM_OFFLOADED);
}

static PHEADERFILLERFUNCTION outputPacketHeaderFillers_Test1[] = { FillOutputHeaders_Test1 };

#define TEST_CASES \
    TEST_CASE(Case1, \
        FillHeaders_Test1, \
        4, \
        headersSize, \
        GeneratePayload_Test1, \
        FillVrPacket_Test1, \
        IPCHKSUM_OFFLOADED | UDPCHKSUM_OFFLOADED, \
        outputPacketHeaderFillers_Test1, \
        1, \
        Assert)

#define TEST_NAME SmallIpUdpOverTunnelPacket

#include "include\generate_test_functions.h"
