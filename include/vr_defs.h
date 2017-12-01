/*
 * vr_defs.h - definitions
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_DEFS_H__
#define __VR_DEFS_H__

#include "vr_os.h"

#define MAC_FORMAT     "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_VALUE(x)   (x)[0],(x)[1],(x)[2],(x)[3],(x)[4],(x)[5]

#ifndef _WIN32
#define ARRAYSIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define VR_ETHER_HLEN           14
#define VR_ETHER_ALEN            6
#define VR_VLAN_HLEN             4

#define VR_GRE_PROTO_MPLS       0x8847
#define VR_GRE_PROTO_MPLS_NO    htons(0x8847)

#define AGENT_CMD_SWITCH            0
#define AGENT_CMD_ROUTE             1
#define AGENT_TRAP_ARP              2
#define AGENT_TRAP_L2_PROTOCOLS     3
#define AGENT_TRAP_NEXTHOP          4
#define AGENT_TRAP_RESOLVE          5
#define AGENT_TRAP_FLOW_MISS        6
#define AGENT_TRAP_L3_PROTOCOLS     7
#define AGENT_TRAP_DIAG             8
#define AGENT_TRAP_ECMP_RESOLVE     9
#define AGENT_TRAP_SOURCE_MISMATCH  10
#define AGENT_TRAP_HANDLE_DF        11
#define AGENT_TRAP_ZERO_TTL         12
#define AGENT_TRAP_ICMP_ERROR       13
#define AGENT_TRAP_TOR_CONTROL_PKT  14
#define AGENT_TRAP_FLOW_ACTION_HOLD 15
#define AGENT_TRAP_ROUTER_ALERT     16
#define AGENT_TRAP_MAC_LEARN        17
#define AGENT_TRAP_MAC_MOVE         18
#define MAX_AGENT_HDR_COMMANDS      19

enum rt_type{
    RT_UCAST = 0,
    RT_MCAST,
    RT_MAX,
};

/* for inet(6) routes */
#define VR_RT_LABEL_VALID_FLAG      0x1
#define VR_RT_ARP_PROXY_FLAG        0x2
#define VR_RT_ARP_TRAP_FLAG         0x4
#define VR_RT_ARP_FLOOD_FLAG        0x8

/* for bridge routes */
#define VR_BE_VALID_FLAG                    0x01
#define VR_BE_LABEL_VALID_FLAG              0x02
#define VR_BE_FLOOD_DHCP_FLAG               0x04
#define VR_BE_MAC_MOVED_FLAG                0x08
#define VR_BE_L2_CONTROL_DATA_FLAG          0x10
#define VR_BE_MAC_NEW_FLAG                  0x20
#define VR_BE_EVPN_CONTROL_PROCESSING_FLAG  0x40

#define VR_BRIDGE_FLAG_MASK(flags)  \
    ((flags) & ~(VR_BE_VALID_FLAG | VR_BE_MAC_NEW_FLAG))

#define AGENT_PKT_HEAD_SPACE (sizeof(struct vr_eth) + \
        sizeof(struct agent_hdr))

__attribute__packed__open__
struct agent_hdr {
    unsigned short hdr_ifindex;
    unsigned short hdr_vrf;
    unsigned short hdr_cmd;
    unsigned int hdr_cmd_param;
    unsigned int hdr_cmd_param_1;
    unsigned int hdr_cmd_param_2;
    unsigned int hdr_cmd_param_3;
    unsigned int hdr_cmd_param_4;
    uint8_t hdr_cmd_param_5;
    uint8_t hdr_cmd_param_5_pack[3];
} __attribute__packed__close__;

#define CMD_PARAM_PACKET_CTRL       0x1
#define CMD_PARAM_1_DIAG            0x1
#define MAX_CMD_PARAMS                3

struct vr_list_node {
        struct vr_list_node *node_n;
};

struct vr_list_head {
        struct vr_list_node *node_p;
};


#define VR_HPAGE_CFG_RESP_HPAGE_SUCCESS              0
#define VR_HPAGE_CFG_RESP_MEM_FAILURE               -1
#define VR_HPAGE_CFG_RESP_INVALID_ARG_MEM_INITED    -2
#define VR_HPAGE_CFG_RESP_HPAGE_FAILURE_MEM_INITED  -3
#define VR_HPAGE_CFG_RESP_MEM_ALREADY_INITED        -4
#define VR_HPAGE_CFG_RESP_HPAGE_PARTIAL_SUCCESS     -5

#endif /* __VR_DEFS_H__ */
