/*
 * vr_packet.h -- packet handling functionality of vrouter
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_PACKET_H__
#define __VR_PACKET_H__

#include "vr_defs.h"
#include "vr_qos.h"
#include "vr_flow.h"
#include "vrouter.h"
#include "vr_btable.h"
#include "vr_bridge.h"
#include "vr_mirror.h"
#include "vr_os.h"

/* ethernet header */
#define VR_ETHER_DMAC_OFF       0
#define VR_ETHER_SMAC_OFF       6
#define VR_ETHER_PROTO_OFF      12
#define VR_ETHER_VLAN_PROTO_OFF 16

#define VR_ETHER_PROTO_MAC_OFF  1
#define VR_ETHER_PROTO_MAC_LEN  2

#define VR_IP_PROTO_ICMP        1
#define VR_IP_PROTO_IGMP        2
#define VR_IP_PROTO_TCP         6
#define VR_IP_PROTO_UDP         17
#define VR_IP_PROTO_GRE         47
#define VR_IP_PROTO_ICMP6       58
#define VR_IP_PROTO_SCTP        132

#define VR_GRE_FLAG_CSUM        (ntohs(0x8000))
#define VR_GRE_FLAG_KEY         (ntohs(0x2000))

#define VR_DHCP_SRC_PORT        68
#define VR_DHCP6_SRC_PORT       546

/* Size of basic GRE header */
#define VR_GRE_BASIC_HDR_LEN    4

/* Size of GRE header with checksum */
#define VR_GRE_CKSUM_HDR_LEN    8

/* Size of GRE header with key */
#define VR_GRE_KEY_HDR_LEN      8

#define VR_DYNAMIC_PORT_START   0
#define VR_DYNAMIC_PORT_END     65535

/*
 * Overlay length used for TCP MSS adjust. For UDP outer header, overlay
 * len is 20 (IP header) + 8 (UDP) + 4 (MPLS). For GRE, it is 20 (IP header)
 * + 8 (GRE header + key) + 4 (MPLS). Instead of allowing for only one
 * label, we will allow a maximum of 3 labels, so we end up with 40 bytes
 * of overleay headers.
 */
#define VROUTER_OVERLAY_LEN 40

/*
 * Over lay length is going to be ethernet header bytes more incase of L2 packet
 */
#define VROUTER_L2_OVERLAY_LEN  62


/* packets originated by DP. For eg: mirrored packets */
#define VP_FLAG_FROM_DP         (1 << 0)
#define VP_FLAG_TO_ME           (1 << 1)
/* request policy lookup - for components other than interfaces */
#define VP_FLAG_FLOW_GET        (1 << 2)
/* packet already went through one round of policy lookup */
#define VP_FLAG_FLOW_SET        (1 << 3)
#define VP_FLAG_MULTICAST       (1 << 4)
/* Partially checksummed by VM */
#define VP_FLAG_CSUM_PARTIAL    (1 << 5)
/* Attempt to do receive offload on inner packet */
#define VP_FLAG_GRO             (1 << 6)
/* Attempt to do segmentation on inner packet */
#define VP_FLAG_GSO             (1 << 7)
/* Diagnostic packet */
#define VP_FLAG_DIAG            (1 << 8)
#define VP_FLAG_GROED           (1 << 9)

/*
 * possible 256 values of what a packet can be. currently, this value is
 * used only as an aid in fragmentation.
 */
#define VP_TYPE_NULL            0

#define VP_TYPE_ARP             1
#define VP_TYPE_IP              2
#define VP_TYPE_IP6             3

#define VP_TYPE_IPOIP           4
#define VP_TYPE_IP6OIP          5

#define VP_TYPE_AGENT           6
#define VP_TYPE_PBB             7
#define VP_TYPE_UNKNOWN         8
#define VP_TYPE_MAX             VP_TYPE_UNKNOWN


/*
 * Values to define how to proceed with handling a packet.
 */
#define PKT_RET_FAST_PATH           1
#define PKT_RET_SLOW_PATH           2
#define PKT_RET_ERROR               3
#define PKT_RET_UNHANDLED           4

/*
 * Values to define the MPLS tunnel type
 */
#define PKT_MPLS_TUNNEL_INVALID               0x00
#define PKT_MPLS_TUNNEL_L3                    0x01
#define PKT_MPLS_TUNNEL_L2_UCAST              0x02
#define PKT_MPLS_TUNNEL_L2_MCAST              0x03
#define PKT_MPLS_TUNNEL_L2_CONTROL_DATA       0x04


/*
 * Values to defaine the srouce of Multicast packet
 */
#define PKT_SRC_TOR_REPL_TREE      0x1
#define PKT_SRC_INGRESS_REPL_TREE  0x2
#define PKT_SRC_EDGE_REPL_TREE     0x4
#define PKT_SRC_ANY_REPL_TREE      (PKT_SRC_TOR_REPL_TREE | \
                PKT_SRC_SRC_REPL_TREE | PKT_SRC_EDGE_REPL_TREE)


/*
 * Values to define the encap type of outgoing packet
 */
#define PKT_ENCAP_MPLS          0x01
#define PKT_ENCAP_VXLAN         0x02


/* packet drop reasons */
#define VP_DROP_DISCARD                     0
#define VP_DROP_PULL                        1
#define VP_DROP_INVALID_IF                  2
#define VP_DROP_INVALID_ARP                 3
#define VP_DROP_TRAP_NO_IF                  4
#define VP_DROP_NOWHERE_TO_GO               5
#define VP_DROP_FLOW_QUEUE_LIMIT_EXCEEDED   6
#define VP_DROP_FLOW_NO_MEMORY              7
#define VP_DROP_FLOW_INVALID_PROTOCOL       8
#define VP_DROP_FLOW_NAT_NO_RFLOW           9
#define VP_DROP_FLOW_ACTION_DROP            10
#define VP_DROP_FLOW_ACTION_INVALID         11
#define VP_DROP_FLOW_UNUSABLE               12
#define VP_DROP_FLOW_TABLE_FULL             13
#define VP_DROP_INTERFACE_TX_DISCARD        14
#define VP_DROP_INTERFACE_DROP              15
#define VP_DROP_DUPLICATED                  16
#define VP_DROP_PUSH                        17
#define VP_DROP_TTL_EXCEEDED                18
#define VP_DROP_INVALID_NH                  19
#define VP_DROP_INVALID_LABEL               20
#define VP_DROP_INVALID_PROTOCOL            21
#define VP_DROP_INTERFACE_RX_DISCARD        22
#define VP_DROP_INVALID_MCAST_SOURCE        23
#define VP_DROP_HEAD_ALLOC_FAIL             24
#define VP_DROP_PCOW_FAIL                   25
#define VP_DROP_MCAST_DF_BIT                26
#define VP_DROP_MCAST_CLONE_FAIL            27
#define VP_DROP_NO_MEMORY                   28
#define VP_DROP_REWRITE_FAIL                29
#define VP_DROP_MISC                        30
#define VP_DROP_INVALID_PACKET              31
#define VP_DROP_CKSUM_ERR                   32
#define VP_DROP_NO_FMD                      33
#define VP_DROP_CLONED_ORIGINAL             34
#define VP_DROP_INVALID_VNID                35
#define VP_DROP_FRAGMENTS                   36
#define VP_DROP_INVALID_SOURCE              37
#define VP_DROP_L2_NO_ROUTE                 38
#define VP_DROP_FRAGMENT_QUEUE_FAIL         39
#define VP_DROP_VLAN_FWD_TX                 40
#define VP_DROP_VLAN_FWD_ENQ                41
#define VP_DROP_NEW_FLOWS                   42
#define VP_DROP_FLOW_EVICT                  43
#define VP_DROP_TRAP_ORIGINAL               44
#define VP_DROP_LEAF_TO_LEAF                45
#define VP_DROP_BMAC_ISID_MISMATCH          46
#define VP_DROP_PKT_LOOP                    47
#define VP_DROP_NO_CRYPT_PATH               48
#define VP_DROP_MAX                         49


/*
 * NOTE: Please do not add any more fields without ensuring
 * that the size is <= 48 bytes in 64 bit systems.
 */
struct vr_packet {
    unsigned char *vp_head;
    struct vr_interface *vp_if;
    struct vr_nexthop *vp_nh;
    unsigned short vp_data;
    unsigned short vp_tail;
    unsigned short vp_len;
    unsigned short vp_end;
    unsigned short vp_network_h;
    unsigned short vp_flags;
    unsigned short vp_inner_network_h;
    unsigned char vp_cpu;
    unsigned char vp_type;
    unsigned char vp_ttl;
    unsigned char vp_queue;
    unsigned char vp_priority:4,
                  vp_notused:4;
#ifdef _WIN32
    void* vp_net_buffer_list;
#endif
};


#define VP_QUEUE_INVALID    0xFF
#define VP_PRIORITY_INVALID 0xF

extern void pkt_reset(struct vr_packet *);
extern struct vr_packet *pkt_copy(struct vr_packet *, unsigned short,
        unsigned short);
extern struct vr_packet *pkt_cow(struct vr_packet *, unsigned short);
extern int vr_myip(struct vr_interface *, unsigned int);

typedef enum {
    L4_TYPE_UNKNOWN,
    L4_TYPE_DHCP_REQUEST,
    L4_TYPE_ROUTER_SOLICITATION,
    L4_TYPE_NEIGHBOUR_SOLICITATION,
    L4_TYPE_NEIGHBOUR_ADVERTISEMENT,
    L4_TYPE_IGMP,
} l4_pkt_type_t;

__attribute__packed__open__
struct vr_eth {
    unsigned char eth_dmac[VR_ETHER_ALEN];
    unsigned char eth_smac[VR_ETHER_ALEN];
    unsigned short eth_proto;
} __attribute__packed__close__;

#define VLAN_ID_INVALID         0xFFFF
#define VLAN_ID_MAX             0xFFFF
#define VR_VLAN_PRIORITY_SHIFT  13

__attribute__packed__open__
struct vr_vlan_hdr {
    unsigned short vlan_tag;
    unsigned short vlan_proto;
} __attribute__packed__close__;

__attribute__packed__open__
struct vr_pbb_itag {
    uint8_t    pbbi_pcp:3,
               pbbi_dei:1,
               pbbi_uca:1,
               pbbi_res:3;
    uint32_t   pbbi_isid:24;
} __attribute__packed__close__;


#define VR_ARP_HW_LEN           6
#define VR_ARP_OP_REQUEST       1
#define VR_ARP_OP_REPLY         2

#define VR_ETH_PROTO_ARP        0x806
#define VR_ETH_PROTO_IP         0x800
#define VR_ETH_PROTO_IP6        0x86DD
#define VR_ETH_PROTO_VLAN       0x8100
#define VR_ETH_PROTO_PBB        0x88E7

#define VR_DIAG_CSUM         0xffff
#define VR_UDP_PORT_RANGE_START 49152
#define VR_UDP_PORT_RANGE_END   65535

static inline int8_t
vr_vlan_get_tos(uint8_t *eth_data)
{
    struct vr_eth *eth = (struct vr_eth *)eth_data;
    struct vr_vlan_hdr *vlan;

    if (ntohs(eth->eth_proto) != VR_ETH_PROTO_VLAN)
        return -1;

    vlan = (struct vr_vlan_hdr *)(eth + 1);
    return (ntohs(vlan->vlan_tag) >> VR_VLAN_PRIORITY_SHIFT);
}

#ifdef arp_op
#undef arp_op
#endif

#define VR_ARP_HW_TYPE_ETHER    1

__attribute__packed__open__
struct vr_arp {
    unsigned short arp_hw;
    unsigned short arp_proto;
    unsigned char arp_hwlen;
    unsigned char arp_protolen;
    unsigned short arp_op;
    unsigned char arp_sha[VR_ARP_HW_LEN];
    unsigned int arp_spa;
    unsigned char arp_dha[VR_ARP_HW_LEN];
    unsigned int arp_dpa;
} __attribute__packed__close__;

static inline bool
vr_grat_arp(struct vr_arp *sarp)
{
    /*
     * Treat below two as Gratuitous ARP
     * Null source IP - ARP Probe
     * Source IP same as dest IP - ARP Announcement
     */
    if ((!sarp->arp_spa) || (sarp->arp_spa == sarp->arp_dpa))
        return true;
    return false;
}

#define VR_IP_DF                (0x1 << 14)
#define VR_IP_MF                (0x1 << 13)
#define VR_IP_FRAG_OFFSET_MASK  (VR_IP_MF - 1)
#define VR_IP_DSCP(val)         ((val) << 2)

#define VR_IP_ADDRESS_LEN       4

#define VR_IP6_MF               0x1
#define VR_IP6_FRAG_OFFSET_BITS 3

__attribute__packed__open__
struct vr_ip {
#if defined(__KERNEL__) && defined(__linux__)
#if defined(__LITTLE_ENDIAN_BITFIELD)
   unsigned char ip_hl:4,
                 ip_version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
   unsigned char ip_version:4,
                 ip_hl:4;
#endif
#elif defined(__KERNEL__) && defined(__FreeBSD__)
#if BYTE_ORDER == LITTLE_ENDIAN
   unsigned char ip_hl:4,
                 ip_version:4;
#elif BYTE_ORDER == BIG_ENDIAN
   unsigned char ip_version:4,
                 ip_hl:4;
#endif
#else
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
   unsigned char ip_hl:4,
                 ip_version:4;
#elif (__BYTE_ORDER == __BIG_ENDIAN)
   unsigned char ip_version:4,
                 ip_hl:4;
#endif
#endif
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_frag_off;
    unsigned char ip_ttl;
    unsigned char ip_proto;
    unsigned short ip_csum;
    unsigned int ip_saddr;
    unsigned int ip_daddr;
} __attribute__packed__close__;

static inline void
vr_incremental_diff(unsigned int oldval, unsigned int newval,
        unsigned int *diff)
{
    unsigned int tmp;

    tmp = ~oldval + newval;
    if (tmp < newval)
        tmp += 1;

    *diff += tmp;
    if (*diff < tmp)
        *diff += 1;

    return;
}

static inline void
vr_ip_incremental_csum(struct vr_ip *ip, unsigned int diff)
{
    unsigned int csum;

    diff = (diff >> 16) + (diff & 0xffff);
    if (diff >> 16) {
        diff &= 0xffff;
        diff += 1;
    }

    csum = ~(ip->ip_csum) & 0xffff;
    csum += diff;
    csum = (csum >> 16) + (csum & 0xffff);
    if (csum >> 16)
        csum = (csum & 0xffff) + 1;

    ip->ip_csum = (~csum & 0xffff);
    return;
}

static inline uint8_t
vr_inet_get_tos(struct vr_ip *iph)
{
    return (iph->ip_tos & 0xFC) >> 2;
}

static inline void
vr_inet_set_tos(struct vr_ip *iph, uint8_t tos)
{
    unsigned int diff = 0;

    if (iph->ip_tos == tos)
        return;

    vr_incremental_diff(iph->ip_tos << 8, tos << 8, &diff);
    iph->ip_tos = tos;
    vr_ip_incremental_csum(iph, diff);

    return;
}


#define SOURCE_LINK_LAYER_ADDRESS_OPTION    1
#define TARGET_LINK_LAYER_ADDRESS_OPTION    2

__attribute__packed__open__
struct vr_neighbor_option {
    uint8_t vno_type;
    uint8_t vno_length;
    uint8_t vno_value[0];
} __attribute__packed__close__;

__attribute__packed__open__
struct vr_ip6_frag {
    uint8_t ip6_frag_nxt;
    uint8_t ip6_frag_res;
    uint16_t ip6_frag_offset;
    uint32_t ip6_frag_id;
} __attribute__packed__close__;

__attribute__packed__open__
struct vr_ip6_pseudo {
    unsigned char ip6_src[VR_IP6_ADDRESS_LEN];
    unsigned char ip6_dst[VR_IP6_ADDRESS_LEN];
    unsigned short ip6_l4_length;
    unsigned short ip6_zero;
    unsigned int ip6_zero_nh;
} __attribute__packed__close__;


__attribute__packed__open__
struct vr_ip6 {
#ifdef __KERNEL__
#if defined(__LITTLE_ENDIAN_BITFIELD)
    uint8_t         ip6_priority_h:4,
                    ip6_version:4;
    uint8_t         ip6_flow_h:4,
                    ip6_priority_l:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    uint8_t         ip6_version:4,
                    ip6_priority_h:4;
    uint8_t         ip6_priority_l:4,
                    ip6_flow_h:4;
#endif
#else
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
    uint8_t         ip6_priority_h:4,
                    ip6_version:4;
    uint8_t         ip6_flow_h:4,
                    ip6_priority_l:4;
#elif (__BYTE_ORDER == __BIG_ENDIAN)
    uint8_t         ip6_version:4,
                    ip6_priority_h:4;
    uint8_t         ip6_priority_l:4,
                    ip6_flow_h:4;
#endif
#endif
    uint16_t        ip6_flow_l;
    uint16_t        ip6_plen;
    uint8_t         ip6_nxt;
    uint8_t         ip6_hlim;
    uint8_t         ip6_src[VR_IP6_ADDRESS_LEN];
    uint8_t         ip6_dst[VR_IP6_ADDRESS_LEN];
} __attribute__packed__close__;

#define VR_IP4_MAPPED_IP6_ZERO_BYTES    10
#define VR_IP4_MAPPED_IP6_ONE_BYTES     2

static inline uint8_t
vr_inet6_get_tos(struct vr_ip6 *ip6h)
{
    return ((((ip6h->ip6_priority_h << 4) | (ip6h->ip6_priority_l)) >> 2) & 0x3F);
}

static inline void
vr_inet6_set_tos(struct vr_ip6 *ip6h, uint8_t tos)
{
    ip6h->ip6_priority_h = ((tos << 2) >> 4);
    ip6h->ip6_priority_l = ((tos << 2) & 0xF);

    return;
}

static inline void
vr_inet6_generate_ip6(uint8_t *ip6, uint32_t ip)
{
    memset(ip6, 0, VR_IP4_MAPPED_IP6_ZERO_BYTES);
    memset(ip6 + VR_IP4_MAPPED_IP6_ZERO_BYTES, 1,
            VR_IP4_MAPPED_IP6_ONE_BYTES);
    memcpy(ip6 + VR_IP4_MAPPED_IP6_ZERO_BYTES + VR_IP4_MAPPED_IP6_ONE_BYTES,
            &ip, sizeof(ip));

    return;
}

struct tcphdr;

bool vr_ip_proto_pull(struct vr_ip *);
bool vr_ip6_proto_pull(struct vr_ip6 *);

int vr_ip_transport_parse(struct vr_ip *iph, struct vr_ip6 *ip6h,
            void **thp, unsigned int frag_size,
            void (do_tcp_mss_adj)(struct tcphdr *, unsigned short, unsigned char),
            unsigned int *hlenp, unsigned short *th_csump, unsigned int *tcph_pull_lenp,
            unsigned int *pull_lenp);
int vr_inner_pkt_parse(unsigned char *va,
            int (*tunnel_type_cb)(unsigned int, unsigned int, unsigned short *),
            int *encap_type, int *pkt_typep, unsigned int *pull_lenp,
            unsigned int frag_size, struct vr_ip **iphp, struct vr_ip6 **ip6hp,
            unsigned short gre_udp_encap, unsigned char ip_proto);

#define MCAST_IP                        (0xE0000000)
#define MCAST_IP_MASK                   (0xF0000000)
#define IS_BMCAST_IP(ip) \
            (((ntohl(ip) & MCAST_IP_MASK) == MCAST_IP) || (ip == 0xFFFFFFFF))

static inline void
vr_mcast_mac_from_isid(uint32_t isid, uint8_t *mac)
{
    if (!mac)
        return;

    mac[0] = 1;
    mac[1] = 0x1E;
    mac[2] = 0x83;
    mac[3] = 0xFF & (isid >> 16);
    mac[4] = 0xFF & (isid >> 8);
    mac[5] = 0xFF & isid;

    return;
}

#define VR_IP_ADDR_SIZE(type) \
        ((type == VP_TYPE_IP6) ? VR_IP6_ADDRESS_LEN \
                               : VR_IP_ADDRESS_LEN)

static inline unsigned char
vr_eth_proto_to_pkt_type(unsigned short eth_proto)
{
    if (eth_proto == VR_ETH_PROTO_IP)
        return VP_TYPE_IP;
    else if (eth_proto == VR_ETH_PROTO_IP6)
        return VP_TYPE_IP6;
    else if (eth_proto == VR_ETH_PROTO_ARP)
        return VP_TYPE_ARP;
    else if (eth_proto == VR_ETH_PROTO_PBB)
        return VP_TYPE_PBB;

    return VP_TYPE_UNKNOWN;
}

static inline bool
vr_ip_is_ip4(struct vr_ip *iph)
{
    if ((iph->ip_version & 0xf) == 0x4)
        return true;
    return false;
}

static inline bool
vr_ip_is_ip6(struct vr_ip *iph)
{
    if ((iph->ip_version & 0xf) == 0x6)
        return true;
    return false;
}
static inline unsigned char *pkt_network_header(struct vr_packet *);

static inline bool
vr_ip_dont_fragment_set(struct vr_packet *pkt)
{
    struct vr_ip *ip;

    ip = (struct vr_ip *)pkt_network_header(pkt);
    if (vr_ip_is_ip6(ip))
        return true;

    if (ntohs(ip->ip_frag_off) & VR_IP_DF)
        return true;

    return false;
}

static inline bool
vr_ip_fragment_tail(struct vr_ip *iph)
{
    unsigned short frag = ntohs(iph->ip_frag_off);
    bool more = (frag & VR_IP_MF) ? true : false;
    unsigned short offset = frag & VR_IP_FRAG_OFFSET_MASK;

    if (!vr_ip_is_ip4(iph))
        return false;

    if (!more && offset)
        return true;

    return false;
}

static inline bool
vr_pkt_is_ip(struct vr_packet *pkt)
{
    if (pkt->vp_type == VP_TYPE_IPOIP || pkt->vp_type == VP_TYPE_IP ||
              pkt->vp_type == VP_TYPE_IP6OIP)
        return true;

    return false;
}

static inline bool
vr_pkt_type_is_overlay(unsigned short type)
{
    if (type == VP_TYPE_IPOIP || type == VP_TYPE_IP6OIP)
        return true;

    return false;
}

static inline bool
vr_pkt_needs_csum_gso_update(struct vr_packet *pkt)
{
    if (pkt->vp_flags & VP_FLAG_FROM_DP) {
        if (pkt->vp_flags & (VP_FLAG_CSUM_PARTIAL | VP_FLAG_GSO))
            return true;
    }

    return false;
}

static inline bool
vr_pkt_is_diag(struct vr_packet *pkt)
{
    if (pkt->vp_flags & VP_FLAG_DIAG)
        return true;
    return false;
}

static inline void
vr_pkt_set_diag(struct vr_packet *pkt)
{
    pkt->vp_flags |= VP_FLAG_DIAG;
    return;
}

static inline bool
vr_pkt_is_gro(struct vr_packet *pkt)
{
    if (pkt->vp_flags & VP_FLAG_GRO)
        return true;
    return false;
}

static inline void
vr_pkt_set_gro(struct vr_packet *pkt)
{
    pkt->vp_flags |= VP_FLAG_GRO;
    return;
}

static inline void
vr_pkt_unset_gro(struct vr_packet *pkt)
{
    pkt->vp_flags &= ~VP_FLAG_GRO;
    return;
}

static inline bool
vr_ip_fragment_head(struct vr_ip *iph)
{
    unsigned short frag = ntohs(iph->ip_frag_off);
    bool more = (frag & VR_IP_MF) ? true : false;
    unsigned short offset = frag & VR_IP_FRAG_OFFSET_MASK;

    if (!vr_ip_is_ip4(iph))
        return false;

    if (more && !offset)
        return true;

    return false;
}

static inline bool
vr_ip_fragment(struct vr_ip *iph)
{
    unsigned short frag = ntohs(iph->ip_frag_off);
    bool more = (frag & VR_IP_MF) ? true : false;
    unsigned short offset = frag & VR_IP_FRAG_OFFSET_MASK;

    if (!vr_ip_is_ip4(iph))
        return false;

    if (offset || more)
        return true;

    return false;
}

static inline bool
vr_ip_transport_header_valid(struct vr_ip *iph)
{
    unsigned short frag = ntohs(iph->ip_frag_off);
    unsigned short offset = frag & VR_IP_FRAG_OFFSET_MASK;

    if (!vr_ip_is_ip4(iph))
        return true;

    if (offset)
        return false;

    return true;
}


#define VR_TCP_FLAG_FIN         0x0001
#define VR_TCP_FLAG_SYN         0x0002
#define VR_TCP_FLAG_RST         0x0004
#define VR_TCP_FLAG_PSH         0x0008
#define VR_TCP_FLAG_ACK         0x0010
#define VR_TCP_FLAG_URG         0x0020
#define VR_TCP_FLAG_ECN         0x0040
#define VR_TCP_FLAG_CWR         0x0080

#define VR_TCP_OFFSET(field)    ((ntohs(field) & 0xF000) >> 12)
#define VR_TCP_FLAGS(field)     (ntohs(field) & 0x01FF)

__attribute__packed__open__
struct vr_tcp {
    unsigned short tcp_sport;
    unsigned short tcp_dport;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    uint16_t tcp_offset_r_flags;
    unsigned short tcp_win;
    unsigned short tcp_csum;
    unsigned short tcp_urg;
} __attribute__packed__close__;

__attribute__packed__open__
struct vr_udp {
    unsigned short udp_sport;
    unsigned short udp_dport;
    unsigned short udp_length;
    unsigned short udp_csum;
} __attribute__packed__close__;

__attribute__packed__open__
struct vr_sctp {
    unsigned short sctp_sport;
    unsigned short sctp_dport;
    unsigned int sctp_vtag;
    unsigned int sctp_csum;
} __attribute__packed__close__;

#define VR_ICMP_TYPE_ECHO_REPLY     0
#define VR_ICMP_TYPE_DEST_UNREACH   3
#define VR_ICMP_TYPE_ECHO           8
#define VR_ICMP_TYPE_TIME_EXCEEDED 11

#define VR_ICMP6_TYPE_PKT_TOO_BIG  2
#define VR_ICMP6_TYPE_ECHO_REQ     128
#define VR_ICMP6_TYPE_ECHO_REPLY   129
#define VR_ICMP6_TYPE_ROUTER_SOL   133
#define VR_ICMP6_TYPE_NEIGH_SOL    135
#define VR_ICMP6_TYPE_NEIGH_AD     136

#define VR_ICMP6_NEIGH_AD_FLAG_ROUTER   0x8000
#define VR_ICMP6_NEIGH_AD_FLAG_SOLCITED 0x4000
#define VR_ICMP6_NEIGH_AD_FLAG_OVERRIDE 0x2000

#define VR_ICMP6_NEIGH_AD_FLAG_ROUTER   0x8000
#define VR_ICMP6_NEIGH_AD_FLAG_SOLCITED 0x4000
#define VR_ICMP6_NEIGH_AD_FLAG_OVERRIDE 0x2000

#define VR_IP6_PROTO_FRAG          44

__attribute__packed__open__
struct vr_icmp {
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_csum;
    /* now only for icmp echo */
    uint16_t icmp_eid;
    uint16_t icmp_eseq;
    uint8_t  icmp_data[0]; /* compatibility with ICMPv6 */
} __attribute__packed__close__;

static inline bool
vr_icmp_echo(struct vr_icmp *icmph)
{
    uint8_t type = icmph->icmp_type;

    if ((type == VR_ICMP_TYPE_ECHO) ||
            (type == VR_ICMP_TYPE_ECHO_REPLY))
        return true;

    return false;
}

static inline bool
vr_v6_prefix_is_ll(uint8_t *prefix)
{
    if (prefix && (prefix[0] == 0xFE) && (prefix[1] == 0x80))
        return true;

    return false;
}

static inline bool
vr_v6_prefix_null(uint8_t *prefix)
{
    uint64_t *p = (uint64_t *)(prefix);
    if (p && (!p[0]) && (!p[1]))
        return true;

    return false;
}

static inline bool
vr_icmp_error(struct vr_icmp *icmph)
{
    uint8_t type = icmph->icmp_type;

    if ((type == VR_ICMP_TYPE_DEST_UNREACH) ||
            (type == VR_ICMP_TYPE_TIME_EXCEEDED))
        return true;

    return false;
}

static inline bool
vr_ip6_transport_header_valid(struct vr_ip6 *ip6)
{
    struct vr_ip6_frag *frag;
    unsigned short offset;

    if (ip6->ip6_nxt != VR_IP6_PROTO_FRAG)
        return true;

    frag = (struct vr_ip6_frag *)(ip6 + 1);
    offset = (ntohs(frag->ip6_frag_offset)) >> VR_IP6_FRAG_OFFSET_BITS;
    if (offset)
        return false;

    return true;
}

static inline bool
vr_ip6_fragment(struct vr_ip6 *ip6)
{
    if (ip6->ip6_nxt == VR_IP6_PROTO_FRAG)
        return true;

    return false;
}

static inline bool
vr_ip6_fragment_head(struct vr_ip6 *ip6)
{
    struct vr_ip6_frag *frag;
    unsigned short offset;
    bool more;

    if (ip6->ip6_nxt != VR_IP6_PROTO_FRAG)
        return false;

    frag = (struct vr_ip6_frag *)(ip6 + 1);
    offset = ntohs(frag->ip6_frag_offset);
    more = (offset & VR_IP6_MF) ? true : false;
    offset = offset >> VR_IP6_FRAG_OFFSET_BITS;

    if (more && !offset)
        return true;

    return false;
}


static inline bool
vr_icmp6_error(struct vr_icmp *icmp6)
{
    uint8_t type = icmp6->icmp_type;

    if (type < 128)
        return true;

    return false;
}

__attribute__packed__open__
struct vr_gre {
    unsigned short gre_flags;
    unsigned short gre_proto;
} __attribute__packed__close__;

__attribute__packed__open__
struct vr_gre_key {
    struct vr_gre gre_comm_hdr;
    unsigned int gre_key;
} __attribute__packed__close__;

struct vr_pcap {
    /* timestamp seconds */
    unsigned int pcap_ts_sec;
    /* timestamp microseconds */
    unsigned int pcap_ts_usec;
    /* number of octets of packet saved in file */
    unsigned int pcap_incl_len;
    /* actual length of packet */
    unsigned int pcap_orig_len;
};

__attribute__packed__open__
struct vr_vxlan {
    unsigned int vxlan_flags;
    unsigned int vxlan_vnid;
} __attribute__packed__close__;

#define VR_VXLAN_IBIT               0x08000000
#define VR_VXLAN_RABIT              0x01000000

/*
 * Mcast packet adds the following before replicating
 * Original Transport + IP Header
 * New Mpls header (4 bytes)
 * New Udp header (It could be GRE Mpls or Udp Mpls tunnel. Wee need to
 * take the maximum of two )
 * New IP header
 * New L2 header (eth + vlan)
 */
#define VR_L3_MCAST_PKT_HEAD_SPACE      (sizeof(struct vr_eth) + \
                                        sizeof(struct vr_vlan_hdr) + \
                                        sizeof(struct vr_ip) + \
                                        sizeof(struct vr_udp) + 4)

/*
 * The complete VXlan header contains IP and UDP header
 */
#define VR_VXLAN_HDR_LEN        (sizeof(struct vr_vxlan) + \
                                    sizeof(struct vr_ip) + sizeof(struct vr_udp))

#define VR_L2_CTRL_DATA           (0x0000)
#define VR_L2_CTRL_DATA_LEN       4

/*
 * The L2 mcast head space contains Vxlan header and 4 bytes of control
 * word inaddtion to L3 mcast head space
 */
#define VR_L2_MCAST_PKT_HEAD_SPACE  (VR_L3_MCAST_PKT_HEAD_SPACE + \
                                      VR_VXLAN_HDR_LEN + \
                                        VR_L2_CTRL_DATA_LEN)


extern unsigned short vr_ip_csum(struct vr_ip *);
extern unsigned short vr_generate_unique_ip_id(void);
extern void vr_proto_fragment(struct vr_interface *, struct vr_packet *);
extern unsigned short vr_ip_partial_csum(struct vr_ip *);
extern unsigned short vr_ip6_partial_csum(struct vr_ip6 *);

enum {
    UNKNOWN_SOURCE,
    TOR_SOURCE,
    TOR_EVPN_SOURCE,
};

enum {
    VR_LABEL_TYPE_UNKNOWN,
    VR_LABEL_TYPE_MPLS,
    VR_LABEL_TYPE_VXLAN_ID
};

/*
 * forwarding metadata is something that is carried through out the
 * forwarding path. we are constrained by what can be held in the
 * packet, and hence this structure should be of great use. mostly
 * a local variable (in stack), this should not cause performance
 * degradation, if so used. please also watch what you are doing with
 * this variable
 */
#define FMD_FLAG_LABEL_IS_VXLAN_ID      0x01
#define FMD_FLAG_MAC_IS_MY_MAC          0x02
#define FMD_FLAG_ETREE_ENABLE           0x04
#define FMD_FLAG_ETREE_ROOT             0x08
#define FMD_FLAG_L2_CONTROL_DATA        0x10

/*
 * 16 bits of fmd_mirror_data constitutes the below
 * MSB - 0 - last 12 bits indicate Vlan id
 * MSB - 1 - Last 13 bits are interface id
 *       2 bits after MSB - Mirror type
 */

#define FMD_MIRROR_INVALID_DATA 0xFFFF

struct vr_forwarding_md {
    int32_t fmd_flow_index;
    int32_t fmd_label;
    int8_t fmd_ecmp_nh_index;
    int8_t fmd_ecmp_src_nh_index;
    int16_t fmd_dvrf;
    uint32_t fmd_outer_src_ip;
    uint16_t fmd_vlan;
    uint16_t fmd_mirror_data;
    uint16_t fmd_udp_src_port;
    uint8_t fmd_to_me;
    uint8_t fmd_src;
    uint8_t fmd_flags;
    int8_t fmd_dscp;
    int8_t fmd_dotonep;
    int8_t fmd_dmac[VR_ETHER_ALEN];
    int8_t fmd_smac[VR_ETHER_ALEN];
};

static inline void
vr_init_forwarding_md(struct vr_forwarding_md *fmd)
{
    fmd->fmd_flow_index = -1;
    fmd->fmd_ecmp_nh_index = -1;
    fmd->fmd_ecmp_src_nh_index = -1;
    fmd->fmd_label = -1;
    fmd->fmd_dvrf = -1;
    fmd->fmd_outer_src_ip = 0;
    fmd->fmd_vlan = VLAN_ID_INVALID;
    fmd->fmd_mirror_data = FMD_MIRROR_INVALID_DATA;
    fmd->fmd_udp_src_port = 0;
    fmd->fmd_to_me = 0;
    fmd->fmd_src = 0;
    fmd->fmd_flags = 0;
    fmd->fmd_dscp = -1;
    fmd->fmd_dotonep = -1;
    VR_MAC_RESET(fmd->fmd_dmac);
    VR_MAC_RESET(fmd->fmd_smac);

    return;
}

static inline bool
vr_fmd_label_is_vxlan_id(struct vr_forwarding_md *fmd)
{
    if (fmd->fmd_flags & FMD_FLAG_LABEL_IS_VXLAN_ID)
        return true;
    return false;
}

static inline void
vr_fmd_update_etree(struct vr_forwarding_md *fmd, bool valid)
{
    if (valid)
        fmd->fmd_flags |= FMD_FLAG_ETREE_ENABLE;
    else
        fmd->fmd_flags &= ~FMD_FLAG_ETREE_ENABLE;

    return;
}

static inline void
vr_fmd_update_etree_root(struct vr_forwarding_md *fmd, bool root)
{
    if (root)
        fmd->fmd_flags |= FMD_FLAG_ETREE_ROOT;
    else
        fmd->fmd_flags &= ~FMD_FLAG_ETREE_ROOT;

    return;
}

static inline bool
vr_fmd_etree_is_enabled(struct vr_forwarding_md *fmd)
{
    if (fmd->fmd_flags & FMD_FLAG_ETREE_ENABLE)
        return true;

    return false;
}

static inline bool
vr_fmd_etree_is_root(struct vr_forwarding_md *fmd)
{
    if (fmd->fmd_flags & FMD_FLAG_ETREE_ROOT)
        return true;

    return false;
}

static inline void
vr_fmd_update_label_type(struct vr_forwarding_md *fmd,
        unsigned int type)
{
    if (type == VR_LABEL_TYPE_VXLAN_ID) {
        fmd->fmd_flags |= FMD_FLAG_LABEL_IS_VXLAN_ID;
    } else {
        fmd->fmd_flags &= ~FMD_FLAG_LABEL_IS_VXLAN_ID;
    }

    return;
}

static inline void
vr_fmd_set_label(struct vr_forwarding_md *fmd, unsigned int label,
        unsigned int type)
{
    fmd->fmd_label = label;
    vr_fmd_update_label_type(fmd, type);

    return;
}

static inline void
vr_fmd_update_l2_control_data(struct vr_forwarding_md *fmd, bool enable)
{
    if (enable)
        fmd->fmd_flags |= FMD_FLAG_L2_CONTROL_DATA;
    else
        fmd->fmd_flags &= ~FMD_FLAG_L2_CONTROL_DATA;

    return;
}

static inline bool
vr_fmd_l2_control_data_is_enabled(struct vr_forwarding_md *fmd)
{
    if (fmd->fmd_flags & FMD_FLAG_L2_CONTROL_DATA)
        return true;

    return false;
}

static inline uint16_t
vr_fmd_get_mirror_vlan(struct vr_forwarding_md *fmd)
{
    if (fmd->fmd_mirror_data != FMD_MIRROR_INVALID_DATA) {
        if (!(fmd->fmd_mirror_data & 0x8000))
            return (fmd->fmd_mirror_data & 0x0FFF);
    }

    return FMD_MIRROR_INVALID_DATA;
}

static inline mirror_type_t
vr_fmd_get_mirror_type(struct vr_forwarding_md *fmd)
{
    if (fmd->fmd_mirror_data != FMD_MIRROR_INVALID_DATA) {
        if (fmd->fmd_mirror_data & 0x8000)
            return (((fmd->fmd_mirror_data & 0x6000) >> 13) & 0x0003);
    }

    return MIRROR_TYPE_UNKNOWN;
}

static inline uint16_t
vr_fmd_get_mirror_if_id(struct vr_forwarding_md *fmd)
{
    uint16_t intf_id = FMD_MIRROR_INVALID_DATA;

    if (fmd->fmd_mirror_data != FMD_MIRROR_INVALID_DATA) {
        if (fmd->fmd_mirror_data & 0x8000) {
            intf_id = fmd->fmd_mirror_data & 0x1FFF;
            if (intf_id == 0x1FFF)
                intf_id = FMD_MIRROR_INVALID_DATA;
        }
    }

    return intf_id;
}

static inline void
vr_fmd_put_mirror_vlan(struct vr_forwarding_md *fmd, uint16_t vlan)
{
    fmd->fmd_mirror_data = vlan & 0x0FFF;

    return;
}


static inline void
vr_fmd_put_mirror_type(struct vr_forwarding_md *fmd, mirror_type_t type)
{
    uint16_t intf_id = vr_fmd_get_mirror_if_id(fmd);
    fmd->fmd_mirror_data = 0x8000 | ((type & 0x3) << 13) | (intf_id & 0x1FFF);

    return;
}

static inline void
vr_fmd_put_mirror_if_id(struct vr_forwarding_md *fmd, uint16_t if_id)
{
    mirror_type_t type = vr_fmd_get_mirror_type(fmd);
    fmd->fmd_mirror_data = 0x8000 | ((type & 0x3) << 13) | (if_id & 0x1FFF);

    return;
}


/*
 * Size is : 2 Transport ports,
 *            IPV6 header which carried the above transport,
 *            ICMPV6 + IPV6 header generated by source of ICMP error,
 *            Fabric Tunnel headers, 2 ethernet headers and agent hdr
 */
#define VR_AGENT_MIN_PACKET_LEN     ((2 * sizeof(unsigned short)) + \
                                    sizeof(struct vr_ip6) + \
                                    sizeof(struct vr_icmp) + \
                                    sizeof(struct vr_ip6) + VR_VXLAN_HDR_LEN + \
                                    VR_L2_CTRL_DATA_LEN + \
                                    (2 * VR_ETHER_HLEN) + sizeof(struct agent_hdr))

static inline bool
pkt_is_gso(struct vr_packet *pkt)
{
    if (vr_pgso_size && vr_pgso_size(pkt))
        return true;
    return false;
}

static inline unsigned char *
pkt_data_at_offset(struct vr_packet *pkt, unsigned short off)
{
    if (off < pkt->vp_end)
        return pkt->vp_head + off;

    return vr_data_at_offset(pkt, off);
}

static inline unsigned char *
pkt_data(struct vr_packet *pkt)
{
    return pkt->vp_head + pkt->vp_data;
}

static inline void
pkt_set_data(struct vr_packet *pkt, unsigned short off)
{
    if (pkt->vp_data == off)
        return;

    pkt->vp_data = off;
    pkt->vp_len = pkt->vp_tail - pkt->vp_data;

    return;
}

static inline void
pkt_set_inner_network_header(struct vr_packet *pkt, unsigned short off)
{
    pkt->vp_inner_network_h = off;
    return;
}

static inline unsigned short
pkt_get_inner_network_header_off(struct vr_packet *pkt)
{
    return pkt->vp_inner_network_h;

}

static inline unsigned char *
pkt_inner_network_header(struct vr_packet *pkt)
{
    if (pkt->vp_inner_network_h < pkt->vp_end)
        return pkt->vp_head + pkt->vp_inner_network_h;

    return NULL;
}

static inline void
pkt_set_network_header(struct vr_packet *pkt, unsigned short off)
{
    pkt->vp_network_h = off;
    return;
}

static inline unsigned short
pkt_get_network_header_off(struct vr_packet *pkt)
{
    return pkt->vp_network_h;
}

static inline unsigned char *
pkt_network_header(struct vr_packet *pkt)
{
    if (pkt->vp_network_h < pkt->vp_end)
        return pkt->vp_head + pkt->vp_network_h;

    return vr_network_header(pkt);
}

static inline unsigned char *
pkt_pull(struct vr_packet *pkt, unsigned int len)
{
    if (pkt->vp_data + len > pkt->vp_tail)
        return NULL;

    pkt->vp_data += len;
    pkt->vp_len -= len;

    return pkt_data(pkt);
}

static inline unsigned char *
pkt_pull_tail(struct vr_packet *pkt, unsigned int len)
{
    if (pkt->vp_tail + len > pkt->vp_end)
        return NULL;

    pkt->vp_tail += len;
    pkt->vp_len += len;

    return pkt->vp_head + pkt->vp_tail;
}

static inline unsigned char *
pkt_push(struct vr_packet *pkt, unsigned int len)
{
    if (len > pkt->vp_data)
        return NULL;

    pkt->vp_data -= len;
    pkt->vp_len += len;

    return pkt_data(pkt);
}

static inline unsigned short
pkt_head_len(struct vr_packet *pkt)
{
    return pkt->vp_len;
}

static inline unsigned int
pkt_len(struct vr_packet *pkt)
{
    return pkt_head_len(pkt) + vr_pfrag_len(pkt);
}

static inline unsigned char *
pkt_reserve_head_space(struct vr_packet *pkt, unsigned short len)
{
    if (pkt->vp_data + len > pkt->vp_end)
        return NULL;

    if (pkt->vp_data == pkt->vp_tail)
        pkt->vp_tail += len;

    if (pkt->vp_data + len > pkt->vp_tail)
        return NULL;

    pkt->vp_data += len;

    return pkt_data(pkt);
}

static inline unsigned short
pkt_head_space(struct vr_packet *pkt)
{
    return pkt->vp_data;
}

static inline void
pkt_init_fragment(struct vr_packet *dst, struct vr_packet *src)
{
    dst->vp_if = src->vp_if;
    dst->vp_nh = src->vp_nh;
    dst->vp_cpu = src->vp_cpu;
    dst->vp_flags = src->vp_flags;

    return;
}

static inline void
pkt_drop_stats(struct vr_interface *vif, unsigned short reason, int cpu)
{
    uint8_t *data;
    unsigned int count = 1;
    struct vrouter *router = vrouter_get(0);

    /*
     * Lets log the errors as of now, till we are sure that nothing is
     * un accounted
     */
    if (reason >= VP_DROP_MAX) {
        vr_printf("Vrouter: vr_pdrop_stats invalid reason %d\n", reason);
        return;
    }

    if (cpu < 0) {
        vr_printf("Vrouter: vr_pdrop_stats invalid CPU %d"
                   " reason %d\n", cpu, reason);
        return;
    }

    /* Lets increment the per cpu global stats */
    if (router)
        ((uint64_t *)(router->vr_pdrop_stats[cpu]))[reason]++;

    /* If vif is NULL, no accounting can be done against the vif. So return */
    if (!vif)
        return;

    /* Increment per cpu stats */
    if (vif->vif_pcpu_drop_stats) {
        data = vr_btable_get(vif->vif_pcpu_drop_stats,
                            ((cpu * VP_DROP_MAX) + reason));
        if (data) {
            count = ++(*data);
            if (count < 255)
                return;
            *data = 0;
        }
    }

    /*
     * Fall through, either for failure of per cpu stat or for carry
     * over
     */
    if (vif->vif_drop_stats) {
        (void)vr_sync_add_and_fetch_64u(vif->vif_drop_stats + reason, count);
    }

    return;
}

#endif /* __VR_PACKET_H__ */
