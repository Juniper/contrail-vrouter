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
    HEADER(vr_ip, innerIpHeader) \
    HEADER(vr_tcp, innerTcpHeader)

#include "include\generate_headers_structure.h"

static void
FillHeaders_Test1(struct PacketHeaders *headers, size_t dataSize)
{
    memset(headers, 0, headersSize);

    headers->outerIpHeader.ip_hl = sizeof(struct vr_ip) / 4;
    headers->outerIpHeader.ip_version = 4;
    headers->outerIpHeader.ip_tos = 0;
    headers->outerIpHeader.ip_len = htons(CountPacketLengthFromHeader(headers, outerIpHeader, dataSize));
    headers->outerIpHeader.ip_id = htons(392);
    headers->outerIpHeader.ip_frag_off = 0;
    headers->outerIpHeader.ip_ttl = 64;
    headers->outerIpHeader.ip_proto = VR_IP_PROTO_UDP;
    headers->outerIpHeader.ip_csum = htons(0x0D50);
    headers->outerIpHeader.ip_saddr = htonl(0xAC10000B);
    headers->outerIpHeader.ip_daddr = htonl(0xAC10000C);

    headers->outerUdpHeader.udp_sport = htons(49152);
    headers->outerUdpHeader.udp_dport = htons(6635);
    headers->outerUdpHeader.udp_length = htons(CountPacketLengthFromHeader(headers, outerUdpHeader, dataSize));
    headers->outerUdpHeader.udp_csum = 0;

    headers->innerIpHeader.ip_hl = sizeof(struct vr_ip) / 4;
    headers->innerIpHeader.ip_version = 4;
    headers->innerIpHeader.ip_tos = 2 + (0 << 2);
    headers->innerIpHeader.ip_len = htons(0);
    headers->innerIpHeader.ip_id = htons(16658);
    headers->innerIpHeader.ip_frag_off = htons(VR_IP_DF);
    headers->innerIpHeader.ip_ttl = 128;
    headers->innerIpHeader.ip_proto = VR_IP_PROTO_TCP;
    headers->innerIpHeader.ip_csum = 0;
    headers->innerIpHeader.ip_saddr = htonl(0x0A000103);
    headers->innerIpHeader.ip_daddr = htonl(0x0A000104);

    headers->innerTcpHeader.tcp_sport = htons(11111);
    headers->innerTcpHeader.tcp_dport = htons(22222);
    headers->innerTcpHeader.tcp_seq = htonl(0xAC5C9EB7);
    headers->innerTcpHeader.tcp_ack = htonl(0xAB2B2229);
    headers->innerTcpHeader.tcp_offset_r_flags = htons(VR_TCP_FLAG_PSH | VR_TCP_FLAG_ACK | ((20/4) << 12));
    headers->innerTcpHeader.tcp_win = htons(8212);
    headers->innerTcpHeader.tcp_csum = htons(0x160D);
    headers->innerTcpHeader.tcp_urg = htons(0);
}

static void
FillSegmentHeaders_Test1_Segment1(struct PacketHeaders *headers, size_t dataSize)
{
    FillHeaders_Test1(headers, dataSize);

    headers->outerIpHeader.ip_len = htons(1386);
    headers->outerIpHeader.ip_csum = htons(0x1BC4);

    headers->outerUdpHeader.udp_length = htons(1366);

    headers->innerIpHeader.ip_len = htons(1340);
    headers->innerIpHeader.ip_csum = htons(0x9EA1);

    headers->innerTcpHeader.tcp_offset_r_flags = htons(VR_TCP_FLAG_ACK | ((20/4) << 12));
    headers->innerTcpHeader.tcp_csum = htons(0xFFA5);
}

static void
FillSegmentHeaders_Test1_Segment4(struct PacketHeaders *headers, size_t dataSize)
{
    FillHeaders_Test1(headers, dataSize);

    headers->outerIpHeader.ip_len = htons(1186);
    headers->outerIpHeader.ip_csum = htons(0x1C8C);

    headers->outerUdpHeader.udp_length = htons(1166);

    headers->innerIpHeader.ip_len = htons(1140);
    headers->innerIpHeader.ip_csum = htons(0x9F69);

    headers->innerTcpHeader.tcp_offset_r_flags = htons(VR_TCP_FLAG_PSH | VR_TCP_FLAG_ACK | ((20/4) << 12));
    headers->innerTcpHeader.tcp_csum = htons(0xD470);

    headers->innerTcpHeader.tcp_seq = htonl(0xAC5CADF3);
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

static void Assert(struct vr_packet *originalVrPacket, struct vr_packet *processedVrPacket, PWIN_MULTI_PACKET result)
{
    AssertMultiPktOffloadStatus(result, NO_OFFLOADS);
}

static PHEADERFILLERFUNCTION outputPacketHeaderFillers_Test1[] = { FillSegmentHeaders_Test1_Segment1, NULL, NULL, FillSegmentHeaders_Test1_Segment4 };

#define TEST_CASES \
    TEST_CASE(AZ_5000_OFFLOAD, \
        FillHeaders_Test1, \
        5000, \
        headersSize, \
        GenerateAZPayload, \
        FillVrPacket_Test1, \
        SEG_OFFLOADED, \
        outputPacketHeaderFillers_Test1, \
        4, \
        Assert)

#define TEST_NAME TcpOverMplsOverUdp

#include "include\generate_test_functions.h"
