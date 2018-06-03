/*
 * vr_dpdk_offloads.c -- dpdk callbacks for datapath flow offloads management
 *
 * Copyright 2018 Mellanox Technologies, Ltd
 */
#include "vr_dpdk_offloads.h"
#include "vr_vxlan.h"
#include <rte_flow.h>

int
dpdk_offload_flow_destroy(struct vr_offload_flow *oflow)
{
    struct vr_dpdk_ethdev *ethdev = (struct vr_dpdk_ethdev *)oflow->pvif->vif_os;
    struct rte_flow_error error;
    int ret = 0;

    RTE_LOG(DEBUG, VROUTER, "Destroy dpdk offload flow:\n"
            "\t\tflow index = %u\n"
            "\t\tflow interface ID = %u\n"
            "\t\tflow host ip = 0x%X\n"
            "\t\tflow tunnel type = %u\n"
            "\t\tflow tunnel tag = %u\n"
            "\t\tflow nexthop ID = %u\n", oflow->fe_index, oflow->pvif->vif_idx,
            oflow->ip, oflow->tunnel_type, oflow->tunnel_tag, oflow->nh->nh_id);

    if (likely(oflow->flow_handle != NULL)) {
        ret = rte_flow_destroy(ethdev->ethdev_port_id, oflow->flow_handle, &error);
        if (unlikely(ret != 0))
            RTE_LOG(ERR, VROUTER, "Failed to destroy flow - %s\n", error.message ?
                    error.message : "no error message");
    } else
        RTE_LOG(WARNING, VROUTER, "try to destroy an empty offload flow\n");

    return ret;
}

int
dpdk_offload_flow_create(struct vr_offload_flow *oflow)
{
#if (RTE_VERSION >= RTE_VERSION_NUM(18, 5, 0, 0))
    static struct rte_flow_attr attr = {
        .ingress = 1,
    };
    static struct rte_flow_item_eth eth_spec = {
        .type = RTE_BE16(VR_ETH_PROTO_IP),
    };
    static struct rte_flow_item_eth eth_mask = {
        .type = -1,
    };
    static struct rte_flow_item_ipv4 ipv4_spec;
    static struct rte_flow_item_ipv4 ipv4_mask = {
        .hdr = {
            .dst_addr = -1,
            .next_proto_id = -1,
        },
    };
    static struct rte_flow_item_gre gre_spec = {
        .protocol = RTE_BE16(VR_GRE_PROTO_MPLS),
    };
    static struct rte_flow_item_gre gre_mask = {
        .protocol = -1,
    };
    static struct rte_flow_item_udp udp_spec;
    static struct rte_flow_item_udp udp_mask = {
        .hdr = {
            .dst_port = -1,
        },
    };
    static struct rte_flow_item_mpls mpls_spec;
    static struct rte_flow_item_mpls mpls_mask = {
        .label_tc_s = "\xff\xff\xf0",
    };
    static struct rte_flow_item_vxlan vxlan_spec;
    static struct rte_flow_item_vxlan vxlan_mask = {
        .vni = "\xff\xff\xff",
    };

    static struct rte_flow_item_eth ieth_spec;
    static struct rte_flow_item_eth ieth_mask = {
        .type = -1,
    };
    static struct rte_flow_item_ipv4 iipv4_spec;
    static struct rte_flow_item_ipv4 iipv4_mask = {
        .hdr = {
            .src_addr = -1,
            .dst_addr = -1,
            .next_proto_id = -1,
        },
    };
    static struct rte_flow_item_ipv6 iipv6_spec;
    static struct rte_flow_item_ipv6 iipv6_mask = {
        .hdr = {
            .src_addr = {
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            },
            .dst_addr = {
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            },
            .proto = -1,
        },

    };
    static struct rte_flow_item_tcp itcpudp_spec;
    static struct rte_flow_item_tcp itcpudp_mask;
    enum {ETH, IPV4, GRE, UDP, MPLS, VXLAN, IETH, IIPV4, IIPV6, ITCPUDP, IEND};
    static struct rte_flow_item pattern[] = {
        [ETH] = {
            .type = RTE_FLOW_ITEM_TYPE_ETH,
            .spec = &eth_spec,
            .mask = &eth_mask,
            .last = NULL,
        },
        [IPV4] = {
            .type = RTE_FLOW_ITEM_TYPE_IPV4,
            .spec = &ipv4_spec,
            .mask = &ipv4_mask,
            .last = NULL,
        },
        [GRE] = {
            .type = RTE_FLOW_ITEM_TYPE_GRE,
            .spec = &gre_spec,
            .mask = &gre_mask,
            .last = NULL,
        },
        [UDP] = {
            .type = RTE_FLOW_ITEM_TYPE_UDP,
            .spec = &udp_spec,
            .mask = &udp_mask,
            .last = NULL,
        },
        [MPLS] = {
            .type = RTE_FLOW_ITEM_TYPE_MPLS,
            .spec = &mpls_spec,
            .mask = &mpls_mask,
            .last = NULL,
        },
        [VXLAN] = {
            .type = RTE_FLOW_ITEM_TYPE_VXLAN,
            .spec = &vxlan_spec,
            .mask = &vxlan_mask,
            .last = NULL,
        },
        [IETH] = {
            .type = RTE_FLOW_ITEM_TYPE_ETH,
            .spec = &ieth_spec,
            .mask = &ieth_mask,
            .last = NULL,
        },
        [IIPV4] = {
            .type = RTE_FLOW_ITEM_TYPE_IPV4,
            .spec = &iipv4_spec,
            .mask = &iipv4_mask,
            .last = NULL,
        },
        [IIPV6] = {
            .type = RTE_FLOW_ITEM_TYPE_IPV6,
            .spec = &iipv6_spec,
            .mask = &iipv6_mask,
            .last = NULL,
        },
        [ITCPUDP] = {
            .type = RTE_FLOW_ITEM_TYPE_TCP,
            .spec = &itcpudp_spec,
            .mask = &itcpudp_mask,
            .last = NULL,
        },
        [IEND] = {
            .type = RTE_FLOW_ITEM_TYPE_END,
            .spec = NULL,
            .mask = NULL,
            .last = NULL,
        },
    };
    static uint16_t rss_queues[VR_DPDK_MAX_NB_RX_QUEUES];
    static struct rte_flow_action_rss rss_action = {
        .queue = &rss_queues[0],
    };
    static struct rte_flow_action_mark mark;
    enum {RSS, MARK, ACTION_END};
    static struct rte_flow_action actions[] = {
        [RSS] = {
            .type = RTE_FLOW_ACTION_TYPE_RSS,
            .conf = &rss_action,
        },
        [MARK] = {
            .type = RTE_FLOW_ACTION_TYPE_MARK,
            .conf = &mark,
        },
        [ACTION_END] = {
            .type = RTE_FLOW_ACTION_TYPE_END,
        },
    };
    struct vr_dpdk_ethdev *ethdev = (struct vr_dpdk_ethdev *)oflow->pvif->vif_os;
    struct rte_flow_error error;
    uint32_t header;
    int i;

    RTE_LOG(DEBUG, VROUTER, "Create dpdk offload flow:\n"
            "\t\tflow index = %u\n"
            "\t\tflow interface ID = %u\n"
            "\t\tflow host ip = 0x%X\n"
            "\t\tflow tunnel type = %u\n"
            "\t\tflow tunnel tag = %u\n"
            "\t\tflow nexthop ID = %u\n", oflow->fe_index, oflow->pvif->vif_idx,
            oflow->ip, oflow->tunnel_type, oflow->tunnel_tag, oflow->nh->nh_id);

    if (unlikely(oflow->flow_handle != NULL)) {
        RTE_LOG(ERR, VROUTER, "Failed to create flow - oflow %u already exists\n",
                oflow->fe_index);
        return -EEXIST;
    }

    /* Fill actions */
    rss_action.queue_num = 0;
    for (i = 0; i < VR_DPDK_MAX_NB_RX_QUEUES; ++i)
        if (ethdev->ethdev_queue_states[i] == VR_DPDK_QUEUE_RSS_STATE)
            rss_queues[rss_action.queue_num++] = i;
    rss_action.types = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP;
    mark.id = oflow->fe_index;

    /* Fill inner L3 item */
    switch (oflow->fe->fe_type) {
    case VP_TYPE_IP:
        pattern[IIPV4].type = RTE_FLOW_ITEM_TYPE_IPV4;
        pattern[IIPV6].type = RTE_FLOW_ITEM_TYPE_VOID;
        ieth_spec.type = RTE_BE16(VR_ETH_PROTO_IP);
        iipv4_spec.hdr.src_addr = oflow->fe->fe_key.flow4_sip;
        iipv4_spec.hdr.dst_addr = oflow->fe->fe_key.flow4_dip;
        iipv4_spec.hdr.next_proto_id = oflow->fe->fe_key.flow4_proto;
        rss_action.types &= ~(ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6 |
                              ETH_RSS_NONFRAG_IPV6_OTHER | ETH_RSS_IPV6_EX);
        RTE_LOG(DEBUG, VROUTER, "\t\tflow L3 tuples: ipv4 src = %u dst = %u\n",
                ntohl(oflow->fe->fe_key.flow4_sip),
                ntohl(oflow->fe->fe_key.flow4_dip));
        break;
    case VP_TYPE_IP6:
        pattern[IIPV4].type = RTE_FLOW_ITEM_TYPE_VOID;
        pattern[IIPV6].type = RTE_FLOW_ITEM_TYPE_IPV6;
        ieth_spec.type = RTE_BE16(VR_ETH_PROTO_IP6);
        memcpy(&iipv6_spec.hdr.src_addr, oflow->fe->fe_key.flow6_sip,
               VR_IP6_ADDRESS_LEN);
        memcpy(&iipv6_spec.hdr.dst_addr, oflow->fe->fe_key.flow6_dip,
               VR_IP6_ADDRESS_LEN);
        iipv6_spec.hdr.proto = oflow->fe->fe_key.flow6_proto;
        rss_action.types &= ~(ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 |
                              ETH_RSS_NONFRAG_IPV4_OTHER);
        RTE_LOG(DEBUG, VROUTER, "\t\tflow L3 tuples: ipv6 src ="
                " %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
                " dst = %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                iipv6_spec.hdr.src_addr[0], iipv6_spec.hdr.src_addr[1],
                iipv6_spec.hdr.src_addr[2], iipv6_spec.hdr.src_addr[3],
                iipv6_spec.hdr.src_addr[4], iipv6_spec.hdr.src_addr[5],
                iipv6_spec.hdr.src_addr[6], iipv6_spec.hdr.src_addr[7],
                iipv6_spec.hdr.src_addr[8], iipv6_spec.hdr.src_addr[9],
                iipv6_spec.hdr.src_addr[10], iipv6_spec.hdr.src_addr[11],
                iipv6_spec.hdr.src_addr[12], iipv6_spec.hdr.src_addr[13],
                iipv6_spec.hdr.src_addr[14], iipv6_spec.hdr.src_addr[15],
                iipv6_spec.hdr.dst_addr[0], iipv6_spec.hdr.dst_addr[1],
                iipv6_spec.hdr.dst_addr[2], iipv6_spec.hdr.dst_addr[3],
                iipv6_spec.hdr.dst_addr[4], iipv6_spec.hdr.dst_addr[5],
                iipv6_spec.hdr.dst_addr[6], iipv6_spec.hdr.dst_addr[7],
                iipv6_spec.hdr.dst_addr[8], iipv6_spec.hdr.dst_addr[9],
                iipv6_spec.hdr.dst_addr[10], iipv6_spec.hdr.dst_addr[11],
                iipv6_spec.hdr.dst_addr[12], iipv6_spec.hdr.dst_addr[13],
                iipv6_spec.hdr.dst_addr[14], iipv6_spec.hdr.dst_addr[15]);
        break;
    default:
        RTE_LOG(ERR, VROUTER, "Failed to create flow - flow %u has unsupported L3"
                " protocol %u\n", oflow->fe_index, oflow->fe->fe_type);
        return -ENOTSUP;
    }

    /* Fill inner L4 item */
    switch (oflow->fe->fe_key.flow_proto) {
    case VR_IP_PROTO_TCP:
        pattern[ITCPUDP].type = RTE_FLOW_ITEM_TYPE_TCP;
        rss_action.types &= ~ETH_RSS_UDP;
        break;
    case VR_IP_PROTO_UDP:
        pattern[ITCPUDP].type = RTE_FLOW_ITEM_TYPE_UDP;
        rss_action.types &= ~ETH_RSS_TCP;
        break;
    default:
        RTE_LOG(ERR, VROUTER, "Failed to create flow - flow %u has unsupported L4"
                " protocol %u\n", oflow->fe_index, oflow->fe->fe_key.flow_proto);
        return -ENOTSUP;
    }
    if (oflow->fe->fe_key.flow_dport) {
            itcpudp_mask.hdr.dst_port = -1;
            itcpudp_spec.hdr.dst_port = oflow->fe->fe_key.flow_dport;
    } else
        /* Handle fat flow */
        itcpudp_mask.hdr.dst_port = 0;

    if (oflow->fe->fe_key.flow_sport) {
        itcpudp_mask.hdr.src_port = -1;
        itcpudp_spec.hdr.src_port = oflow->fe->fe_key.flow_sport;
     } else
         /* Handle fat flow */
         itcpudp_mask.hdr.src_port = 0;

    RTE_LOG(DEBUG, VROUTER, "flow L4 tuples: %s src = %u dst = %u\n",
            oflow->fe->fe_key.flow_proto == VR_IP_PROTO_TCP ? "tcp" : "udp",
            ntohs(oflow->fe->fe_key.flow_sport),
            ntohs(oflow->fe->fe_key.flow_dport));

    /* Fill outer items */
    ipv4_spec.hdr.dst_addr = oflow->ip;
    switch (oflow->tunnel_type) {
    case NH_FLAG_TUNNEL_GRE:
    case NH_FLAG_TUNNEL_UDP_MPLS:
        pattern[MPLS].type = RTE_FLOW_ITEM_TYPE_MPLS;
        header = htonl(oflow->tunnel_tag << VR_MPLS_LABEL_SHIFT);
        mpls_spec.label_tc_s[0] = header & 0xff;
        mpls_spec.label_tc_s[1] = (header >> 8) & 0xff;
        mpls_spec.label_tc_s[2] = (header >> 16) & 0xff;
        pattern[VXLAN].type = RTE_FLOW_ITEM_TYPE_VOID;
        if (oflow->is_mpls_l2)
            pattern[IETH].type =  RTE_FLOW_ITEM_TYPE_ETH;
        else
            pattern[IETH].type = RTE_FLOW_ITEM_TYPE_VOID;
        if (oflow->tunnel_type == NH_FLAG_TUNNEL_GRE) {
            ipv4_spec.hdr.next_proto_id = VR_IP_PROTO_GRE;
            pattern[GRE].type = RTE_FLOW_ITEM_TYPE_GRE;
            pattern[UDP].type = RTE_FLOW_ITEM_TYPE_VOID;
            rss_action.level = 2; /* RSS on inner */
        } else {
            ipv4_spec.hdr.next_proto_id = VR_IP_PROTO_UDP;
            pattern[GRE].type = RTE_FLOW_ITEM_TYPE_VOID;
            pattern[UDP].type = RTE_FLOW_ITEM_TYPE_UDP;
            udp_spec.hdr.dst_port = RTE_BE16(VR_MPLS_OVER_UDP_NEW_DST_PORT);
            rss_action.level = 1; /* RSS on outer */
            rss_action.types = ETH_RSS_IPV4 |
                               ETH_RSS_FRAG_IPV4 |
                               ETH_RSS_NONFRAG_IPV4_OTHER |
                               ETH_RSS_NONFRAG_IPV4_UDP;
        }
        break;
    case NH_FLAG_TUNNEL_VXLAN:
        ipv4_spec.hdr.next_proto_id = VR_IP_PROTO_UDP;
        pattern[GRE].type = RTE_FLOW_ITEM_TYPE_VOID;
        pattern[UDP].type = RTE_FLOW_ITEM_TYPE_UDP;
        udp_spec.hdr.dst_port = RTE_BE16(VR_VXLAN_UDP_DST_PORT);
        pattern[MPLS].type = RTE_FLOW_ITEM_TYPE_VOID;
        pattern[VXLAN].type = RTE_FLOW_ITEM_TYPE_VXLAN;
        header = htonl(oflow->tunnel_tag << VR_VXLAN_VNID_SHIFT);
        vxlan_spec.vni[0] = header & 0xff;
        vxlan_spec.vni[1] = (header >> 8) & 0xff;
        vxlan_spec.vni[2] = (header >> 16) & 0xff;
        pattern[IETH].type = RTE_FLOW_ITEM_TYPE_ETH;
        rss_action.level = 1; /* RSS on outer */
        rss_action.types = ETH_RSS_IPV4 |
                           ETH_RSS_FRAG_IPV4 |
                           ETH_RSS_NONFRAG_IPV4_OTHER |
                           ETH_RSS_NONFRAG_IPV4_UDP;
        break;
    default:
        RTE_LOG(ERR, VROUTER, "Failed to create flow - flow %u has unsupported tunnel"
                " protocol %u\n", oflow->fe_index, oflow->tunnel_type);
        return -ENOTSUP;
    }

    /* Create dpdk flow */
    oflow->flow_handle = rte_flow_create(ethdev->ethdev_port_id, &attr, pattern,
                                         actions, &error);
    if (unlikely(oflow->flow_handle == NULL)) {
        RTE_LOG(ERR, VROUTER, "Failed to create flow - %s (%d)\n", error.message ?
                error.message : "no error message", error.type);
        return -rte_errno;
    }
    return 0;
#else
    RTE_SET_USED(oflow);
    RTE_LOG(DEBUG, VROUTER, "Cannot create a dpdk offload flow, the version must be"
            " at least 18.05\n");
    return -ENOTSUP;
#endif
}

void
dpdk_offload_prepare(struct vr_packet *pkt, struct vr_forwarding_md *fmd)
{
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);
    struct vr_offload_flow *oflow;

    if (m->ol_flags & PKT_RX_FDIR_ID) {
        oflow = vr_offloads_flow_get(m->hash.fdir.hi);
        if (oflow) {
            pkt->vp_nh = oflow->nh;
            pkt->vp_flags |= VP_FLAG_TO_ME;
            fmd->fmd_fe = oflow->fe;
            fmd->fmd_flow_index = oflow->fe_index;
            fmd->fmd_label = oflow->tunnel_tag;
        }
    }
}
