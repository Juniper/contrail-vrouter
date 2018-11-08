#include <setjmp.h>
#include <cmocka.h>
#include <allocation.h>
#include <common.h>
#include <payload_generators.h>
#include <win_packet.h>
#include <win_packet_impl.h>
#include <fake_win_packet.h>
#include <win_tx_postprocess.h>

#include <asserts_packets_headers.h>

#define HEADERS \
    HEADER(vr_eth, outerEthHeader) \
    HEADER(vr_arp, outerIpHeader)

#include "include\generate_headers_structure.h"

static void
FillHeaders_Test1(struct PacketHeaders *headers, size_t dataSize)
{
    memset(headers, 0, headersSize);
}

static void
FillVrPacket_Test1(struct vr_packet* packet, struct PacketHeaders* headers)
{
    packet->vp_flags = VP_FLAG_FLOW_SET;
    packet->vp_type = VP_TYPE_ARP;
    packet->vp_ttl = 64;
    packet->vp_priority = VP_PRIORITY_INVALID;
}

static void Assert(struct vr_packet *originalVrPacket, struct vr_packet *processedVrPacket, PWIN_MULTI_PACKET result)
{
    assert_ptr_equal(result, GetWinPacketFromVrPacket(processedVrPacket));
}

static PHEADERFILLERFUNCTION outputPacketHeaderFillers_Test1[] = { FillHeaders_Test1 };

#define TEST_CASES \
    TEST_CASE(Case1, \
        FillHeaders_Test1, \
        20, \
        headersSize, \
        GenerateEmptyPayload, \
        FillVrPacket_Test1, \
        NO_OFFLOADS, \
        outputPacketHeaderFillers_Test1, \
        1, \
        Assert)

#define TEST_NAME ArpPacket

#include "include\generate_test_functions.h"
