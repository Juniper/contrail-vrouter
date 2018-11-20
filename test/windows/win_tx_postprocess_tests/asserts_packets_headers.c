#include "include/asserts_packets_headers.h"

#include <setjmp.h>
#include <cmocka.h>
#include <win_packet_impl.h>
#include <fake_win_packet.h>

#define HEADER_TYPE vr_ip
#define HEADER_FIELDS \
    FIELD(ip_version) \
    FIELD(ip_hl) \
    FIELD(ip_tos) \
    FIELD(ip_len) \
    FIELD(ip_id) \
    FIELD(ip_frag_off) \
    FIELD(ip_ttl) \
    FIELD(ip_proto) \
    FIELD(ip_csum) \
    FIELD(ip_saddr) \
    FIELD(ip_daddr)
CheckIfHeaderEqualsFunctionDefinition
#undef HEADER_TYPE
#undef HEADER_FIELDS

#define HEADER_TYPE vr_eth
#define HEADER_FIELDS \
    FIELD(eth_proto)
CheckIfHeaderEqualsFunctionDefinition
#undef HEADER_TYPE
#undef HEADER_FIELDS

#define HEADER_TYPE vr_udp
#define HEADER_FIELDS \
    FIELD(udp_sport) \
    FIELD(udp_dport) \
    FIELD(udp_length) \
    FIELD(udp_csum)
CheckIfHeaderEqualsFunctionDefinition
#undef HEADER_TYPE
#undef HEADER_FIELDS

#define HEADER_TYPE vr_tcp
#define HEADER_FIELDS \
    FIELD(tcp_sport) \
    FIELD(tcp_dport) \
    FIELD(tcp_seq) \
    FIELD(tcp_ack) \
    FIELD(tcp_offset_r_flags) \
    FIELD(tcp_win) \
    FIELD(tcp_csum) \
    FIELD(tcp_urg)
CheckIfHeaderEqualsFunctionDefinition
#undef HEADER_TYPE
#undef HEADER_FIELDS

#define HEADER_TYPE vr_mpls
#define HEADER_FIELDS \
    FIELD(data)
CheckIfHeaderEqualsFunctionDefinition
#undef HEADER_TYPE
#undef HEADER_FIELDS

#define HEADER_TYPE vr_arp
#define HEADER_FIELDS \
    FIELD(arp_hw) \
    FIELD(arp_proto) \
    FIELD(arp_hwlen) \
    FIELD(arp_protolen) \
    FIELD(arp_op) \
    FIELD(arp_spa) \
    FIELD(arp_dpa)
CheckIfHeaderEqualsFunctionDefinition
#undef HEADER_TYPE
#undef HEADER_FIELDS

#define HEADER_TYPE vr_gre
#define HEADER_FIELDS \
    FIELD(gre_flags) \
    FIELD(gre_proto)
CheckIfHeaderEqualsFunctionDefinition
#undef HEADER_TYPE
#undef HEADER_FIELDS

extern PCHECKHEADERSAREVALIDFUNCTION CheckHeadersAreValid = NULL;

void
AssertHeadersAreValid(PWIN_MULTI_PACKET segments, PHEADERFILLERFUNCTION fillers[], size_t dataSize)
{
    PWIN_PACKET_RAW rawResultPacket = WinMultiPacketToRawPacket(segments);
    PWIN_SUB_PACKET subPacket = WinPacketRawGetFirstSubPacket(rawResultPacket);
    size_t counter = 0;
    while(subPacket != NULL)
    {
        counter++;
        if(fillers[counter-1] != NULL)
        {
            if(!CheckHeadersAreValid(subPacket, fillers[counter-1], dataSize))
            {
                print_error("Packet number: %d\n", counter);
                fail();
            }
        }
        subPacket = WinSubPacketRawGetNext(subPacket);
    }
}
