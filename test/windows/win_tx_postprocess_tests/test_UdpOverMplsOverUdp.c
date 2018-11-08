#include <setjmp.h>
#include <cmocka.h>
#include <allocation.h>
#include <common.h>
#include <asserts.h>
#include <payload_generators.h>
#include <win_packet.h>
#include <win_packet_impl.h>
#include <fake_win_packet.h>
#include <win_tx_postprocess.h>
#include <asserts_packets_headers.h>

#define HEADERS \
    HEADER(vr_eth, outerEthHeader) \
    HEADER(vr_ip, outerIpHeader) \
    HEADER(vr_udp, outerUdpHeader) \
    HEADER(vr_mpls, mplsHeader) \
    HEADER(vr_eth, innerEthHeader) \
    HEADER(vr_ip, innerIpHeader)

#include "include\generate_headers_structure.h"

static void
FillHeaders_Test1(struct PacketHeaders *headers, size_t dataSize)
{
    memset(headers, 0, headersSize);

    headers->outerIpHeader.ip_hl = sizeof(headers->outerIpHeader) / 4;
    headers->outerIpHeader.ip_version = 4;
    headers->outerIpHeader.ip_tos = 0;
    headers->outerIpHeader.ip_len = htons(CountPacketLengthFromHeader(headers, outerIpHeader, dataSize));
    headers->outerIpHeader.ip_id = htons(44);
    headers->outerIpHeader.ip_frag_off = 0;
    headers->outerIpHeader.ip_ttl = 64;
    headers->outerIpHeader.ip_proto = VR_IP_PROTO_UDP;
    headers->outerIpHeader.ip_csum = htons(0x1C94);
    headers->outerIpHeader.ip_saddr = htonl(0xAC100001);
    headers->outerIpHeader.ip_daddr = htonl(0xAC100002);

    headers->outerUdpHeader.udp_sport = htons(49152);
    headers->outerUdpHeader.udp_dport = htons(6635);
    headers->outerUdpHeader.udp_length = htons(1526);
    headers->outerUdpHeader.udp_csum = 0;

    uint8_t smac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x03};
    uint8_t dmac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x04};
    VR_MAC_COPY(headers->innerEthHeader.eth_dmac, dmac);
    VR_MAC_COPY(headers->innerEthHeader.eth_smac, smac);
    headers->innerEthHeader.eth_proto = htons(VR_ETH_PROTO_IP);

    headers->innerIpHeader.ip_hl = sizeof(headers->innerIpHeader) / 4;
    headers->innerIpHeader.ip_version = 4;
    headers->innerIpHeader.ip_tos = 0;
    headers->innerIpHeader.ip_len = htons(1500);
    headers->innerIpHeader.ip_id = htons(3100);
    headers->innerIpHeader.ip_frag_off = htons(VR_IP_MF);
    headers->innerIpHeader.ip_ttl = 128;
    headers->innerIpHeader.ip_proto = VR_IP_PROTO_UDP;
    headers->innerIpHeader.ip_csum = 0;
    headers->innerIpHeader.ip_saddr = htonl(0x0a010004);
    headers->innerIpHeader.ip_daddr = htonl(0x0a010003);
}

static void
FillFragmentHeaders_Test1_Fragment1(struct PacketHeaders *headers, size_t dataSize)
{
    FillHeaders_Test1(headers, dataSize);

    headers->outerIpHeader.ip_len = htons(1498);
    headers->outerIpHeader.ip_csum = htons(0x1CC4);

    headers->outerUdpHeader.udp_length = htons(1478);

    headers->innerIpHeader.ip_len = htons(1452);
    headers->innerIpHeader.ip_csum = htons(0xF51C);
}

static void
FillFragmentHeaders_Test1_Fragment2(struct PacketHeaders *headers, size_t dataSize)
{
    FillHeaders_Test1(headers, dataSize);

    headers->outerIpHeader.ip_len = htons(114);
    headers->outerIpHeader.ip_csum = htons(0x222C);

    headers->outerUdpHeader.udp_length = htons(94);

    headers->innerIpHeader.ip_len = htons(68);
    headers->innerIpHeader.ip_csum = htons(0xF9D1);
    headers->innerIpHeader.ip_frag_off = htons(VR_IP_MF | (1432 / 8));
}

static void
FillVrPacket_Test1(struct vr_packet* packet, struct PacketHeaders* headers)
{
    packet->vp_network_h = CountHeaderOffset(headers, outerIpHeader);
    packet->vp_flags = VP_FLAG_FLOW_SET;
    packet->vp_inner_network_h = CountHeaderOffset(headers, innerIpHeader);
    packet->vp_type = VP_TYPE_IPOIP;
    packet->vp_ttl = 64;
    packet->vp_priority = VP_PRIORITY_INVALID;
}

static void
GeneratePayload_Test1(uint8_t* data, size_t payloadSize)
{
    struct vr_udp *udpHeaders = (struct vr_udp*)data;

    udpHeaders->udp_sport = htons(11111);
    udpHeaders->udp_dport = htons(22222);
    udpHeaders->udp_length = htons(2608); // NOTE: Payload was ('a...z' * 100) + UDP HEADER
    udpHeaders->udp_csum = htons(0xa08c);

    GenerateAZPayload(data + sizeof(struct vr_udp), payloadSize - sizeof(struct vr_udp));
}

static void
AssertInsideUdpHeaders(struct vr_packet *OriginalPacket, PWIN_MULTI_PACKET ResultPacket)
{
    PWIN_PACKET_RAW rawResultPacket = WinMultiPacketToRawPacket(ResultPacket);
    PWIN_SUB_PACKET subPacket = WinPacketRawGetFirstSubPacket(rawResultPacket);
    size_t subPacketPayloadSize = Fake_WinSubPacketGetDataSize(subPacket) - headersSize;
    uint8_t *subPacketData = Fake_WinSubPacketGetData(subPacket);
    uint8_t *subPacketPayload = subPacketData + headersSize;

    PWIN_PACKET originalWinPacket = GetWinPacketFromVrPacket(OriginalPacket);
    PWIN_PACKET_RAW originalRawPacket = WinPacketToRawPacket(originalWinPacket);
    PWIN_SUB_PACKET originalSubPacket = WinPacketRawGetFirstSubPacket(originalRawPacket);
    size_t originalPayloadSize = Fake_WinSubPacketGetDataSize(originalSubPacket) - headersSize;
    uint8_t *originalPacketData = Fake_WinSubPacketGetData(originalSubPacket);
    uint8_t *originalPayload = originalPacketData + headersSize;

    if(!CheckIf_vr_udp_HeaderEquals((struct vr_udp*)subPacketPayload, (struct vr_udp*)originalPayload))
    {
        print_error("Header name: inner UDP\n");
        fail();
    }
}

static void Assert(struct vr_packet *originalVrPacket, struct vr_packet *processedVrPacket, PWIN_MULTI_PACKET result)
{
    AssertMultiPktOffloadStatus(result, NO_OFFLOADS);
    AssertInsideUdpHeaders(originalVrPacket, result);
}

static PHEADERFILLERFUNCTION outputPacketHeaderFillers_Test1[] = { FillFragmentHeaders_Test1_Fragment1, FillFragmentHeaders_Test1_Fragment2 };

#define TEST_NAME UdpOverMplsOverUdp

// TODO UDP_CHECKSUM_OFFLOAD IS DISABLED!!!
#define TEST_CASES \
    TEST_CASE(AZ_1472_FRAGMENT, \
        FillHeaders_Test1, \
        1480, \
        headersSize, \
        GeneratePayload_Test1, \
        FillVrPacket_Test1, \
        IPCHKSUM_OFFLOADED, \
        outputPacketHeaderFillers_Test1, \
        2, \
        Assert)

#include "include\generate_test_functions.h"
