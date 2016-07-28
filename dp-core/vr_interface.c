/*
 * vr_interface.c -- router interface management
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include <vr_interface.h>
#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_mirror.h"
#include "vr_htable.h"
#include "vr_datapath.h"
#include "vr_bridge.h"

volatile bool agent_alive = false;

static struct vr_host_interface_ops *hif_ops;

static int vm_srx(struct vr_interface *, struct vr_packet *, unsigned short);
static int vm_rx(struct vr_interface *, struct vr_packet *, unsigned short);
static int eth_rx(struct vr_interface *, struct vr_packet *, unsigned short);
static mac_response_t vm_mac_request(struct vr_interface *, struct vr_packet *,
                struct vr_forwarding_md *, unsigned char *);
static void vif_fat_flow_free(uint8_t **);
static int vif_fat_flow_add(struct vr_interface *, vr_interface_req *);
static bool vif_fat_flow_port_is_set(struct vr_interface *, uint8_t,
                uint16_t);

void vif_attach(struct vr_interface *);
void vif_detach(struct vr_interface *);
int vr_gro_vif_add(struct vrouter *, unsigned int, char *, unsigned short);
struct vr_interface_stats *vif_get_stats(struct vr_interface *, unsigned short);
struct vr_interface *__vrouter_get_interface_os(struct vrouter *, unsigned int);

extern struct vr_host_interface_ops *vr_host_interface_init(void);
extern void vr_host_interface_exit(void);
extern void vr_host_vif_init(struct vrouter *);
extern struct vr_interface *vif_bridge_get_sub_interface(vr_htable_t,
        unsigned short, unsigned char *);
extern int vif_bridge_get_index(struct vr_interface *, struct vr_interface *);
extern int vif_bridge_init(struct vr_interface *);
extern void vif_bridge_deinit(struct vr_interface *);
extern int vif_bridge_delete(struct vr_interface *, struct vr_interface *);
extern int vif_bridge_add(struct vr_interface *, struct vr_interface *);
extern void vhost_remove_xconnect(void);

#define MINIMUM(a, b) (((a) < (b)) ? (a) : (b))

struct vr_interface_stats *
vif_get_stats(struct vr_interface *vif, unsigned short cpu)
{
    return &vif->vif_stats[cpu & VR_CPU_MASK];
}

static int
vif_discard_tx(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    vr_pfree(pkt, VP_DROP_INTERFACE_TX_DISCARD);
    return 0;
}

static int
vif_discard_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id __attribute__((unused)))
{
    vr_pfree(pkt, VP_DROP_INTERFACE_RX_DISCARD);
    return 0;
}

void
vif_drop_pkt(struct vr_interface *vif, struct vr_packet *pkt, bool input)
{
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    if (input)
        stats->vis_ierrors++;
    else
        stats->vis_oerrors++;
    vr_pfree(pkt, VP_DROP_INTERFACE_DROP);
    return;
}


/*
 * in the rewrite case, we will assume the positive case of caller
 * passing us valid rewrite ptr and len and will not check for those
 */
static unsigned char *
vif_cmn_rewrite(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd, unsigned char *rewrite,
        unsigned short len)
{
    unsigned char *head;

    if (!len)
        return pkt_data(pkt);

    if (pkt_head_space(pkt) < len) {
        pkt = vr_pexpand_head(pkt, len - pkt_head_space(pkt));
        if (!pkt)
            return NULL;
    }

    head = pkt_push(pkt, len);
    if (!head)
        return NULL;

    memcpy(head, rewrite, len);
    return head;
}

static int
vr_interface_service_enable(struct vr_interface *vif)
{
    int i;

    /*
     * handle the case of existing vrf assign table, which
     * was not freed because the table was not empty. also,
     * note that for existing vrf table, we do not reset the
     * entries and the table users count, as per requirements
     * from agent
     */
    if (!vif->vif_vrf_table) {
        vif->vif_vrf_table = vr_malloc(sizeof(struct vr_vrf_assign) *
                VIF_VRF_TABLE_ENTRIES, VR_INTERFACE_VRF_TABLE_OBJECT);
        if (!vif->vif_vrf_table)
            return -ENOMEM;

        for (i = 0; i < VIF_VRF_TABLE_ENTRIES; i++) {
            vif->vif_vrf_table[i].va_vrf = -1;
            vif->vif_vrf_table[i].va_nh_id = 0;
        }

        /* for the new table, there are no users */
        vif->vif_vrf_table_users = 0;
    }

    vif->vif_rx = vm_srx;

    return 0;
}


static void
vr_interface_service_disable(struct vr_interface *vif)
{

    if (vif_is_virtual(vif))
        vif->vif_rx = vm_rx;
    else
        vif->vif_rx = eth_rx;

    /*
     * once everybody sees the change, we are free to do whatever
     * we want with the vrf assign table
     */
    if (!vr_not_ready)
        vr_delay_op();

    /*
     * it is possible that when this function is called from
     * interface delete, the table users are +ve, and hence
     * the memory will not be freed here. our saving grace
     * is vif_free (called from last put operation), which
     * takes care of freeing the memory
     */
    if (vif->vif_vrf_table && !vif->vif_vrf_table_users) {
        vr_free(vif->vif_vrf_table, VR_INTERFACE_VRF_TABLE_OBJECT);
        vif->vif_vrf_table = NULL;
    }

    return;
}

/*
 * xconnect mode
 *
 * xconnect mode, as of now, is relevant only for physical (ethX) and vhost
 * interfaces. the purpose of xconnect mode is to make sure that the host
 * management interface does not lose connectivity to network when agent is
 * either not started or not alive.
 *
 * the xconnect mode works differently in different devices. since for ethernet
 * interfaces, we would still like to process all packets destined to VMs,
 * packets will have to be processed by the vrouter stack. however, for vhost
 * interfaces, we just need the packets to be pushed to ethernet interface,
 * and hence the packets are switched to the corresponding physical interface
 */
void
vif_set_xconnect(struct vr_interface *vif)
{
    if (!vif)
        return;

    vif->vif_flags |= VIF_FLAG_XCONNECT;
    return;
}

void
vif_remove_xconnect(struct vr_interface *vif)
{
    if (!vif)
        return;

    vif->vif_flags &= ~VIF_FLAG_XCONNECT;
    return;
}

int
vif_xconnect(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    struct vr_interface *bridge;

    if (!vif)
        goto free_pkt;

    bridge = vif->vif_bridge;
    if (bridge) {
        vr_preset(pkt);
        return bridge->vif_tx(bridge, pkt, fmd);
    }

free_pkt:
    if (vif)
        vif_drop_pkt(vif, pkt, 1);
    return 0;
}

static unsigned char *
agent_set_rewrite(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd, unsigned char *rewrite,
        unsigned short len)
{
    unsigned char *head;
    unsigned int hdr_len;
    struct agent_hdr *hdr;

    vr_preset(pkt);

    hdr_len = sizeof(struct agent_hdr) + len;
    if (pkt_head_space(pkt) < hdr_len) {
        pkt = vr_pexpand_head(pkt, hdr_len - pkt_head_space(pkt));
        if (!pkt)
            return NULL;
    }

    head = pkt_push(pkt, hdr_len);
    if (!head)
        return NULL;

    /* copy the rewrite first */
    memcpy(head, rewrite, len);

    hdr = (struct agent_hdr *)(head + len);
    hdr->hdr_ifindex = htons(pkt->vp_if->vif_idx);
    hdr->hdr_vrf = htons(fmd->fmd_dvrf);
    /* this needs some thought */
    hdr->hdr_cmd = htons(AGENT_TRAP_NEXTHOP);
    hdr->hdr_cmd_param = 0;

    return head;
}

static int
agent_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id __attribute__((unused)))
{
    unsigned short cmd;

    struct agent_hdr *hdr;
    struct vr_forwarding_md fmd;
    struct vr_interface *agent_vif;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    hdr = (struct agent_hdr *)pkt_pull(pkt, sizeof(struct vr_eth));
    if (!hdr || !pkt_pull(pkt, sizeof(*hdr))) {
        stats->vis_ierrors++;
        vr_pfree(pkt, VP_DROP_PULL);
        return 0;
    }

    /*
     * Update the original (OS visible) packet to point to the
     * l2 header of the injected packet
     */
    vr_pset_data(pkt, pkt->vp_data);

    cmd = ntohs(hdr->hdr_cmd);

    switch (cmd) {
    case AGENT_CMD_ROUTE:
        /*
         * XXX
         * Packet with command "route" from agent may
         * result in flow setup, this breaks the
         * assumption that all packets for a flow will
         * reach same CPU. Need a better way to handle this
         */
        agent_vif = __vrouter_get_interface(vrouter_get(0),
                                            ntohs(hdr->hdr_ifindex));
        if (!agent_vif) {
            agent_vif = vif;
        }
        pkt->vp_if = agent_vif;

        if (ntohl(hdr->hdr_cmd_param) == CMD_PARAM_PACKET_CTRL) {
            if (ntohl(hdr->hdr_cmd_param_1) == CMD_PARAM_1_DIAG) {
                pkt->vp_flags |= VP_FLAG_DIAG;
            }
        }

        vr_virtual_input(ntohs(hdr->hdr_vrf), agent_vif, pkt, VLAN_ID_INVALID);

        break;

    case AGENT_CMD_SWITCH:
        vif = __vrouter_get_interface(vrouter_get(0), ntohs(hdr->hdr_ifindex));
        if (!vif) {
            stats->vis_ierrors++;
            vr_pfree(pkt, VP_DROP_INVALID_IF);
            return 0;
        }

        vr_init_forwarding_md(&fmd);
        fmd.fmd_dvrf = ntohs(hdr->hdr_vrf);

        pkt->vp_type = VP_TYPE_AGENT;
        pkt_set_network_header(pkt, pkt->vp_data + sizeof(struct vr_eth));
        pkt_set_inner_network_header(pkt,
                                     pkt->vp_data + sizeof(struct vr_eth));
        return vif->vif_tx(vif, pkt, &fmd);

        break;

    default:
        vr_pfree(pkt, VP_DROP_INVALID_PACKET);
        break;
    }

    return 0;
}

static int
agent_tx(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    int ret;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    stats->vis_obytes += pkt_len(pkt);
    stats->vis_opackets++;

    ret = hif_ops->hif_tx(vif, pkt);
    if (ret != 0) {
        ret = 0;
        stats->vis_oerrors++;
    }

    return ret;
}

/*
 * Return true if the packet may be truncated.
 */
static int
agent_trap_may_truncate(int trap_reason)
{
    switch (trap_reason) {
    case AGENT_TRAP_NEXTHOP:
    case AGENT_TRAP_RESOLVE:
    case AGENT_TRAP_FLOW_MISS:
    case AGENT_TRAP_FLOW_ACTION_HOLD:
    case AGENT_TRAP_ECMP_RESOLVE:
    case AGENT_TRAP_HANDLE_DF:
    case AGENT_TRAP_ZERO_TTL:
        return 1;

    case AGENT_TRAP_ARP:
    case AGENT_TRAP_L2_PROTOCOLS:
    case AGENT_TRAP_L3_PROTOCOLS:
    case AGENT_TRAP_DIAG:
    default:
        return 0;
    }
}

static int
agent_send(struct vr_interface *vif, struct vr_packet *pkt,
                void *ifspecific)
{
    unsigned short encap = VIF_ENCAP_TYPE_ETHER;
    int len, head_space;
    struct vr_eth *eth;

    struct vr_forwarding_md fmd;
    struct agent_hdr *hdr;
    unsigned char *rewrite;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);
    struct vr_packet *pkt_c;
    struct agent_send_params *params =
        (struct agent_send_params *)ifspecific;
    struct vr_flow_trap_arg *fta;
    struct vr_df_trap_arg *dta;
    bool truncate = false;


    vr_preset(pkt);

    if (pkt_is_gso(pkt)) {
        truncate = true;
    }

    if ((params->trap_reason == AGENT_TRAP_HANDLE_DF) ||
            (params->trap_reason == AGENT_TRAP_ZERO_TTL)) {
        if (pkt_len(pkt) > VR_AGENT_MIN_PACKET_LEN)
            truncate = true;
    }

    if (hif_ops->hif_get_encap)
        encap = hif_ops->hif_get_encap(pkt->vp_if);

    head_space = AGENT_PKT_HEAD_SPACE;
    if (encap == VIF_ENCAP_TYPE_L3)
        head_space += VR_ETHER_HLEN;

    if (truncate || (pkt_head_space(pkt) < head_space)) {
        len = pkt_len(pkt);

        if (agent_trap_may_truncate(params->trap_reason)) {
            len = MINIMUM(len, VR_AGENT_MIN_PACKET_LEN);
        }

        pkt_c = pkt_copy(pkt, 0, len);
        if (pkt_c) {
            vr_pfree(pkt, VP_DROP_DUPLICATED);
            pkt = pkt_c;
        }
    }

    pkt->vp_type = VP_TYPE_AGENT;

    if (encap == VIF_ENCAP_TYPE_L3) {
        eth = (struct vr_eth *)(pkt_push(pkt, VR_ETHER_HLEN));
        if (!eth)
            goto drop;

        memcpy(eth->eth_dmac, vif->vif_mac, VR_ETHER_ALEN);
        memcpy(eth->eth_smac, vif->vif_mac, VR_ETHER_ALEN);
        if (pkt->vp_type == VP_TYPE_IP6)
            eth->eth_proto = htons(VR_ETH_PROTO_IP6);
        else
            eth->eth_proto = htons(VR_ETH_PROTO_IP);
    }

    pkt_set_network_header(pkt, pkt->vp_data + sizeof(struct vr_eth));
    pkt_set_inner_network_header(pkt,
            pkt->vp_data + sizeof(struct vr_eth));

    hdr = (struct agent_hdr *)pkt_push(pkt, sizeof(struct agent_hdr));
    if (!hdr)
        goto drop;

    hdr->hdr_ifindex = htons(pkt->vp_if->vif_idx);
    hdr->hdr_vrf = htons(params->trap_vrf);
    hdr->hdr_cmd = htons(params->trap_reason);

    switch (params->trap_reason) {
    case AGENT_TRAP_FLOW_MISS:
    case AGENT_TRAP_FLOW_ACTION_HOLD:
        if (params->trap_param) {
            fta = (struct vr_flow_trap_arg *)(params->trap_param);
            hdr->hdr_cmd_param = htonl(fta->vfta_index);
            hdr->hdr_cmd_param_1 = htonl(fta->vfta_nh_index);
            hdr->hdr_cmd_param_2 = htonl(fta->vfta_stats.flow_bytes);
            hdr->hdr_cmd_param_3 = htonl(fta->vfta_stats.flow_packets);
            hdr->hdr_cmd_param_4 = htonl((fta->vfta_stats.flow_bytes_oflow |
                        (fta->vfta_stats.flow_packets_oflow << 16)));
            hdr->hdr_cmd_param_5 = fta->vfta_gen_id;
        }
        break;

    case AGENT_TRAP_ECMP_RESOLVE:
    case AGENT_TRAP_SOURCE_MISMATCH:
        if (params->trap_param)
            hdr->hdr_cmd_param = htonl(*(unsigned int *)(params->trap_param));
        break;

    case AGENT_TRAP_DIAG:
        if (params->trap_param)
            hdr->hdr_cmd_param = htonl(*(unsigned int *)(params->trap_param));
        break;

    case AGENT_TRAP_HANDLE_DF:
        dta = (struct vr_df_trap_arg *)(params->trap_param);
        hdr->hdr_cmd_param = htonl(dta->df_mtu);
        hdr->hdr_cmd_param_1 = htonl(dta->df_flow_index);
        break;

    default:
        hdr->hdr_cmd_param = 0;
        hdr->hdr_cmd_param_1 = 0;
        break;
    }

    rewrite = pkt_push(pkt, VR_ETHER_HLEN);
    if (!rewrite)
        goto drop;

    memcpy(rewrite, vif->vif_rewrite, VR_ETHER_HLEN);

    vr_init_forwarding_md(&fmd);
    return vif->vif_tx(vif, pkt, &fmd);

drop:
    stats->vis_oerrors++;
    vr_pfree(pkt, VP_DROP_PUSH);
    return 0;
}

static int
agent_drv_del(struct vr_interface *vif)
{
    hif_ops->hif_del_tap(vif);

    vif->vif_tx = vif_discard_tx;
    vif->vif_rx = vif_discard_rx;

    return hif_ops->hif_del(vif);
}

static int
agent_drv_add(struct vr_interface *vif,
        vr_interface_req *vifr __attribute__((unused)))
{
    int ret;

    if (!vif->vif_mtu)
        vif->vif_mtu = 1514;

    vif->vif_set_rewrite = agent_set_rewrite;

    /**
     * At this moment, vif_tx() and vif_rx() are vif_discard_tx() and
     * vif_discard_rx(). Let them stay this way until we succesfully call
     * platform-dependent implementation of hif_add(). On some platfoms it may
     * set up resoruces needed by hif_tx(), which is called by agent_tx().
     */
    ret = hif_ops->hif_add(vif);
    if (ret) {
        return ret;
    }

    vif->vif_tx = agent_tx;
    vif->vif_rx = agent_rx;
    vif->vif_send = agent_send;

    ret = hif_ops->hif_add_tap(vif);
    if (ret)
        hif_ops->hif_del(vif);

    return ret;
}
/* end agent driver */

/* vhost driver */
static mac_response_t
vhost_mac_request(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd, unsigned char *dmac)
{
    struct vr_arp *sarp;

    if (pkt->vp_type == VP_TYPE_ARP) {
        sarp = (struct vr_arp *)pkt_data(pkt);
        if (IS_LINK_LOCAL_IP(sarp->arp_dpa) ||
                (vif->vif_type == VIF_TYPE_GATEWAY)) {
            VR_MAC_COPY(dmac, vif->vif_mac);
            return MR_PROXY;
        }
    }

    if (vif->vif_type == VIF_TYPE_GATEWAY)
        return MR_DROP;

    return MR_XCONNECT;
}

static int
vhost_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id __attribute__((unused)))
{
    struct vr_forwarding_md fmd;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    /* please see the text on xconnect mode */
    vr_init_forwarding_md(&fmd);
    fmd.fmd_dvrf = vif->vif_vrf;
    if (vif_mode_xconnect(vif))
        return vif_xconnect(vif, pkt, &fmd);

    return vr_fabric_input(vif, pkt, vlan_id);
}

static int
vhost_tx(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    int ret;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);
    unsigned short eth_proto, pull_len = 0;
    unsigned char *new_eth, *eth;
    struct vr_eth *eth_hdr;
    struct vr_vlan_hdr *vlan;
    struct vr_interface *in_vif;

    stats->vis_obytes += pkt_len(pkt);
    stats->vis_opackets++;

    if (vif->vif_type == VIF_TYPE_XEN_LL_HOST)
        memcpy(pkt_data(pkt), vif->vif_mac, sizeof(vif->vif_mac));
    else if (vif->vif_type == VIF_TYPE_HOST) {
        in_vif = pkt->vp_if;
        if (!hif_ops->hif_get_encap ||
                (hif_ops->hif_get_encap(in_vif) == VIF_ENCAP_TYPE_ETHER)) {
            /* Untag any tagged packets */
            eth = pkt_data(pkt);
            eth_proto = ntohs(*(unsigned short *)(eth + VR_ETHER_PROTO_OFF));
            while (eth_proto == VR_ETH_PROTO_VLAN) {
                vlan = (struct vr_vlan_hdr *)(pkt_data(pkt) + pull_len +
                        VR_ETHER_HLEN);
                eth_proto = ntohs(vlan->vlan_proto);
                pull_len += sizeof(*vlan);
            }

            /* If there are any vlan tags */
            if (pull_len) {
                new_eth = pkt_pull(pkt, pull_len);
                if (!new_eth) {
                    vr_pfree(pkt, VP_DROP_PULL);
                    return 0;
                }
                memmove(new_eth, eth, (2 * VR_ETHER_ALEN));
            }
            /*
             * Rewrite dst MAC for the link local (169.254/16) addresses.
             * The replies from VMs are destined to VRRP MAC, hence
             * they are discarded by the IP stack.
             * For the Linux platform we fix it by setting skb->pkt_type
             * to PACKET_HOST in linux_if_rx() function.
             * The following code fixes MACs for all the platforms.
             */
            if (vif_is_virtual(in_vif)) {
                eth_hdr = (struct vr_eth *)pkt_data(pkt);
                memcpy(eth_hdr->eth_dmac, vif->vif_mac, VR_ETHER_ALEN);
            }
        } else {
            eth_hdr = (struct vr_eth *)pkt_push(pkt, VR_ETHER_HLEN);
            memcpy(eth_hdr->eth_dmac, vif->vif_mac, VR_ETHER_ALEN);
            memcpy(eth_hdr->eth_smac, vif->vif_mac, VR_ETHER_ALEN);
            if (pkt->vp_type == VP_TYPE_IP6)
                eth_hdr->eth_proto = htons(VR_ETH_PROTO_IP6);
            else
                eth_hdr->eth_proto = htons(VR_ETH_PROTO_IP);
        }
    }

    ret = hif_ops->hif_rx(vif, pkt);
    if (ret < 0) {
        ret = 0;
        stats->vis_oerrors++;
    }

    return ret;
}

static int
vhost_drv_del(struct vr_interface *vif)
{

    vif->vif_tx = vif_discard_tx;
    vif->vif_rx = vif_discard_rx;

    return hif_ops->hif_del(vif);
}

static int
vhost_drv_add(struct vr_interface *vif,
        vr_interface_req *vifr __attribute__((unused)))
{
    int ret = 0;

    if (!vif->vif_mtu)
        vif->vif_mtu = 1514;

    vif->vif_set_rewrite = vif_cmn_rewrite;
    vif->vif_tx = vhost_tx;
    vif->vif_rx = vhost_rx;
    vif->vif_mac_request = vhost_mac_request;

    ret = hif_ops->hif_add(vif);
    if (ret)
        return ret;
    /*
     * add tap to the corresponding physical interface, now
     * that vhost is functional
     */
    if (vif->vif_bridge) {
        ret = hif_ops->hif_add_tap(vif->vif_bridge);
        if (ret)
            return ret;
    }

    return 0;
}
/* end vhost driver */

/* vlan driver */
static int
vlan_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id __attribute__((unused)))
{
    int8_t tos;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    pkt->vp_if = vif;

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    tos = vr_vlan_get_tos(pkt_data(pkt));
    if (tos >= 0)
        pkt->vp_priority = tos;

    if (vr_untag_pkt(pkt)) {
        stats->vis_ierrors++;
        vr_pfree(pkt, VP_DROP_PULL);
        return 0;
    }

    vr_pset_data(pkt, pkt->vp_data);

    return vr_virtual_input(vif->vif_vrf, vif, pkt, VLAN_ID_INVALID);
}


static int
vlan_tx(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    int ret = 0;

    struct vr_interface *pvif;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    if (!(pkt->vp_flags & VP_FLAG_GRO)) {
        stats->vis_obytes += pkt_len(pkt);
        stats->vis_opackets++;
    }

    fmd->fmd_vlan = vif->vif_vlan_id;
    if (vif_is_vlan(vif)) {
        if (vif->vif_ovlan_id) {
            fmd->fmd_vlan = vif->vif_ovlan_id;
            if (vr_tag_pkt(pkt, vif->vif_ovlan_id)) {
                goto drop;
            }
            vr_pset_data(pkt, pkt->vp_data);
        } else {
            vr_vlan_set_priority(pkt);
        }
    }

    pvif = vif->vif_parent;
    if (!pvif)
        goto drop;

    ret = pvif->vif_tx(pvif, pkt, fmd);
    if (ret < 0) {
        ret = 0;
        goto drop;
    }

    return ret;

drop:
    vr_pfree(pkt, VP_DROP_INVALID_IF);
    stats->vis_oerrors++;

    return ret;
}

static int
vlan_drv_del(struct vr_interface *vif)
{
    int ret = 0;
    struct vr_interface *pvif;

    pvif = vif->vif_parent;
    if (!pvif)
        return 0;

    if (pvif->vif_driver->drv_delete_sub_interface) {
        ret = pvif->vif_driver->drv_delete_sub_interface(pvif, vif);
        if (ret)
            goto exit_del;
    }

exit_del:
    if (vif->vif_src_mac) {
        vr_free(vif->vif_src_mac, VR_INTERFACE_MAC_OBJECT);
        vif->vif_src_mac = NULL;
    }

    return ret;
}

static int
vlan_drv_add(struct vr_interface *vif, vr_interface_req *vifr)
{
    struct vr_interface *pvif = NULL;

    if ((unsigned int)(vifr->vifr_parent_vif_idx) > VR_MAX_INTERFACES)
        return -EINVAL;

    if (((unsigned short)(vifr->vifr_vlan_id) >= VLAN_ID_MAX) ||
            ((unsigned short)(vifr->vifr_ovlan_id) >= VLAN_ID_MAX))
        return -EINVAL;

    if (vifr->vifr_src_mac_size && vifr->vifr_src_mac) {
        if (vifr->vifr_src_mac_size != VR_ETHER_ALEN)
            return -EINVAL;

        vif->vif_src_mac = vr_malloc(VR_ETHER_ALEN, VR_INTERFACE_MAC_OBJECT);
        if (!vif->vif_src_mac)
            return -ENOMEM;

        memcpy(vif->vif_src_mac, vifr->vifr_src_mac, VR_ETHER_ALEN);
    }

    if (!vif->vif_mtu)
        vif->vif_mtu = 1514;

    vif->vif_set_rewrite = vif_cmn_rewrite;
    vif->vif_tx = vlan_tx;
    vif->vif_rx = vlan_rx;
    vif->vif_mac_request = vm_mac_request;
    vif->vif_vlan_id = vifr->vifr_vlan_id;
    vif->vif_ovlan_id = vifr->vifr_ovlan_id;

    pvif = vrouter_get_interface(vifr->vifr_rid, vifr->vifr_parent_vif_idx);
    if (!pvif)
        return -EINVAL;

    vif->vif_parent = pvif;

    if (!pvif->vif_driver->drv_add_sub_interface)
        return -EINVAL;

    return pvif->vif_driver->drv_add_sub_interface(pvif, vif);
}
/* end vlan driver */

/* eth driver */
static int
vm_srx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id)
{
    unsigned short vrf;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    if (vlan_id >= VIF_VRF_TABLE_ENTRIES)
        vrf = vif->vif_vrf;
    else
        vrf = vif->vif_vrf_table[vlan_id].va_vrf;

    return vr_virtual_input(vrf, vif, pkt, vlan_id);
}

static mac_response_t
vm_mac_request(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd, unsigned char *dmac)
{
    if (pkt->vp_type == VP_TYPE_ARP) {
        return vm_arp_request(vif, pkt, fmd, dmac);
    } else if (pkt->vp_type == VP_TYPE_IP6) {
        return vm_neighbor_request(vif, pkt, fmd, dmac);
    }

    return MR_DROP;
}

static int
vm_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id)
{
    struct vr_interface *sub_vif = NULL;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);
    struct vr_eth *eth = (struct vr_eth *)pkt_data(pkt);

    if (vlan_id != VLAN_ID_INVALID && vlan_id < VLAN_ID_MAX) {
        if (vif->vif_btable) {
            sub_vif = vif_bridge_get_sub_interface(vif->vif_btable, vlan_id,
                                                    eth->eth_smac);
        } else {
            if (vif->vif_sub_interfaces)
                sub_vif = vif->vif_sub_interfaces[vlan_id];
        }

        if (sub_vif)
            return sub_vif->vif_rx(sub_vif, pkt, VLAN_ID_INVALID);
    }

    /*
     * there is a requirement that stats be not counted in both the
     * underlying interface and in the sub-interface (double count).
     * this behavior is a specific requirement for VM interfaces since
     * the VM interface and the sub-interface on top are considered
     * two different VMIs and can be in two different VRFs. Counting
     * stats in both interfaces will wrongly put statistics in a VRF
     * where the statistics should not have been counted. hence the
     * stats count block is below and not the first thing that we do
     * in this function.
     */
    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    return vr_virtual_input(vif->vif_vrf, vif, pkt, vlan_id);
}

static int
tun_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id)
{
    unsigned char first_b;
    struct vr_forwarding_md fmd;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    if (vif_mode_xconnect(vif))
        pkt->vp_flags |= VP_FLAG_TO_ME;

    first_b = *pkt_data(pkt);
    first_b &= 0xf0;

    switch (first_b) {
    case 0x40:
        pkt->vp_type = VP_TYPE_IP;
        break;

    case 0x60:
        pkt->vp_type = VP_TYPE_IP6;
        break;

    default:
        vr_pfree(pkt, VP_DROP_INVALID_PACKET);
        return 0;
    }

    pkt_set_network_header(pkt, pkt->vp_data);

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = vlan_id;
    fmd.fmd_dvrf = vif->vif_vrf;

    vr_l3_input(pkt, &fmd);

    return 0;
}

static unsigned char *
eth_set_rewrite(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd, unsigned char *rewrite,
        unsigned short len)
{
    if (!len)
        return pkt_data(pkt);

    if ((pkt->vp_if->vif_type == VIF_TYPE_HOST) &&
            !(pkt->vp_flags & VP_FLAG_FROM_DP)) {
        vr_preset(pkt);
        return pkt_data(pkt);
    }

    return vif_cmn_rewrite(vif, pkt, fmd, rewrite, len);
}

static mac_response_t
eth_mac_request(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd, unsigned char *dmac)
{
    struct vr_arp *sarp;

    if (vif_mode_xconnect(vif))
        return MR_XCONNECT;

    /*
     * If there is a label or if the vrf is different, it is meant for VM's
     */
    if ((fmd->fmd_label >= 0) || (fmd->fmd_dvrf != vif->vif_vrf))
        return vm_mac_request(vif, pkt, fmd, dmac);

    if (pkt->vp_type == VP_TYPE_ARP) {
        sarp = (struct vr_arp *)pkt_data(pkt);
        if (vr_grat_arp(sarp))
            return MR_TRAP_X;
    }

    return MR_XCONNECT;
}



static int
eth_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id)
{
    struct vr_interface *sub_vif = NULL;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);
    struct vr_eth *eth = (struct vr_eth *)pkt_data(pkt);

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    /*
     * please see the text on xconnect mode
     *
     * since we would like the packets to reach the VMs (if they were
     * destined to in the first place), packets have to traverse the
     * stack. so, just mark a flag suggesting that packet is destined
     * for the vrouter and force the vrouter to receive the packet
     */
    if (vif_mode_xconnect(vif))
        pkt->vp_flags |= VP_FLAG_TO_ME;

    if ((vlan_id == VLAN_ID_INVALID) &&
            (vif->vif_flags & VIF_FLAG_NATIVE_VLAN_TAG))
        vlan_id = 0;

    if (vlan_id != VLAN_ID_INVALID && vlan_id < VLAN_ID_MAX) {
        if (vif->vif_btable) {
            sub_vif = vif_bridge_get_sub_interface(vif->vif_btable, vlan_id,
                                                    eth->eth_smac);
        } else {
            if (vif->vif_sub_interfaces)
                sub_vif = vif->vif_sub_interfaces[vlan_id];
        }

        if (sub_vif)
            return sub_vif->vif_rx(sub_vif, pkt, VLAN_ID_INVALID);
    }

    return vr_fabric_input(vif, pkt, vlan_id);
}

static int
eth_tx(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    int ret, handled;
    bool stats_count = true, from_subvif = false;

    struct vr_forwarding_md m_fmd;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    if (vif_is_virtual(vif)) {
        handled = vif_plug_mac_request(vif, pkt, fmd);
        if (handled)
            return 0;

        /*
         * GRO packets come here twice - once with VP_FLAG_GRO set and
         * once without the flag set. Don't count them twice. Also,
         * if the packet came from the sub interface on top, we should
         * not be counting them twice. The way we determine that the
         * packet has come from sub-interface is by looking at nexthop
         * and checking whether nh_dev is not the same as vif, or in
         * the absence of nh and the packet ingressed from agent interface,
         * the vlan id is set.
         */
        if (pkt->vp_flags & VP_FLAG_GRO)
            stats_count = false;

        if ((pkt->vp_nh && (pkt->vp_nh->nh_dev != vif)) ||
            ((pkt->vp_if->vif_type == VIF_TYPE_AGENT) &&
                 (fmd->fmd_vlan != VLAN_ID_INVALID))) {
                from_subvif = true;
                stats_count = false;
        }
    }

    if (stats_count) {
        stats->vis_obytes += pkt_len(pkt);
        stats->vis_opackets++;
    }

    if (vif->vif_flags & VIF_FLAG_MIRROR_TX) {
        vr_init_forwarding_md(&m_fmd);
        m_fmd.fmd_dvrf = vif->vif_vrf;
        vr_mirror(vif->vif_router, vif->vif_mirror_id, pkt, &m_fmd,
                MIRROR_TYPE_PORT_TX);
    }

    ret = hif_ops->hif_tx(vif, pkt);
    if (ret != 0) {
        if (!from_subvif)
            ret = 0;

        if (stats_count)
            stats->vis_oerrors++;
    }

    return ret;
}

static int
eth_drv_del(struct vr_interface *vif)
{
    int ret;

    hif_ops->hif_del_tap(vif);

    vif->vif_tx = vif_discard_tx;
    vif->vif_rx = vif_discard_rx;

    ret = hif_ops->hif_del(vif);
    if (vif->vif_flags & VIF_FLAG_SERVICE_IF)
        vr_interface_service_disable(vif);
    return ret;
}


static int
eth_drv_del_sub_interface(struct vr_interface *pvif, struct vr_interface *vif)
{
    int ret = 0;

    if (vif->vif_src_mac) {
        ret = vif_bridge_delete(pvif, vif);
    } else {
        if (pvif->vif_sub_interfaces &&
                (pvif->vif_sub_interfaces[vif->vif_vlan_id] == vif)) {
            pvif->vif_sub_interfaces[vif->vif_vlan_id] = NULL;
        } else {
            ret = -EINVAL;
        }
    }

    if (!ret) {
        vrouter_put_interface(pvif);
        vif->vif_parent = NULL;
        hif_ops->hif_del(vif);
    }

    return ret;
}

static int
eth_drv_add_sub_interface(struct vr_interface *pvif, struct vr_interface *vif)
{
    int ret = 0;

    ret = hif_ops->hif_add(vif);
    if (ret)
        return ret;

    if (vif->vif_src_mac) {
        if (!pvif->vif_btable) {
            ret = vif_bridge_init(pvif);
            if (ret)
                return ret;
        }

        ret = vif_bridge_add(pvif, vif);
    } else {
        if(!pvif->vif_sub_interfaces) {
            pvif->vif_sub_interfaces = vr_zalloc(VLAN_ID_MAX *
                sizeof(struct vr_interface *), VR_INTERFACE_OBJECT);
            if (!pvif->vif_sub_interfaces)
                return -ENOMEM;
            /*
             * we are not going to free this memory, since it is not guaranteed
             * that we will get contiguous memory. so hold on to it for the life
             * time of the interface
             */
        }

        if (pvif->vif_sub_interfaces[vif->vif_vlan_id])
            return -EEXIST;

        pvif->vif_sub_interfaces[vif->vif_vlan_id] = vif;
    }

    return ret;
}

static int
eth_drv_add(struct vr_interface *vif,
        vr_interface_req *vifr __attribute__((unused)))
{
    int ret = 0;

    if (!vif->vif_mtu) {
        vif->vif_mtu = 9160;
        if (vif->vif_type == VIF_TYPE_PHYSICAL)
            vif->vif_mtu = 1514;
    }


    if (vif->vif_type != VIF_TYPE_STATS) {
        vif->vif_tx = eth_tx;

        if (vif_is_virtual(vif)) {
            vif->vif_rx = vm_rx;
            vif->vif_set_rewrite = vif_cmn_rewrite;
            vif->vif_mac_request = vm_mac_request;
        } else {
            vif->vif_rx = eth_rx;
            vif->vif_set_rewrite = eth_set_rewrite;
            vif->vif_mac_request = eth_mac_request;
        }
    }

    if (vif->vif_flags & VIF_FLAG_SERVICE_IF) {
        ret = vr_interface_service_enable(vif);
        if (ret)
            goto exit_add;
    }

    ret = hif_ops->hif_add(vif);
    if (ret)
        goto exit_add;

    if ((vif->vif_type == VIF_TYPE_PHYSICAL) &&
            (hif_ops->hif_get_encap(vif) == VIF_ENCAP_TYPE_L3)) {
            vif->vif_rx = tun_rx;
    }

    /*
     * as soon as we add the tap, packets will start traversing vrouter.
     * now, without a vhost interface getting added, such packets are
     * useless. Also, once reset happens, the physical interface sends
     * packets directly to vhost interface, bypassing vrouter. If we tap
     * here, such packets will be blackholed. hence, do not tap the interface
     * if the interface is set to be associated with a vhost interface.
     */
    if ((!(vif->vif_flags & VIF_FLAG_VHOST_PHYS)) ||
            (vif->vif_bridge)) {
        ret = hif_ops->hif_add_tap(vif);
        if (ret)
            hif_ops->hif_del(vif);
    }

exit_add:
    if (ret)
        if (vif->vif_flags & VIF_FLAG_SERVICE_IF)
            vr_interface_service_disable(vif);

    return ret;
}
/* end eth driver */

static struct vr_interface_driver vif_drivers[VIF_TYPE_MAX] = {
    [VIF_TYPE_HOST] = {
        .drv_add                    =   vhost_drv_add,
        .drv_delete                 =   vhost_drv_del,
    },
    [VIF_TYPE_XEN_LL_HOST] = {
        .drv_add                    =   vhost_drv_add,
        .drv_delete                 =   vhost_drv_del,
    },
    [VIF_TYPE_GATEWAY] = {
        .drv_add                    =   vhost_drv_add,
        .drv_delete                 =   vhost_drv_del,
    },
    [VIF_TYPE_AGENT] = {
        .drv_add                    =   agent_drv_add,
        .drv_delete                 =   agent_drv_del,
    },
    [VIF_TYPE_PHYSICAL] = {
        .drv_add                    =   eth_drv_add,
        .drv_delete                 =   eth_drv_del,
        .drv_add_sub_interface      =   eth_drv_add_sub_interface,
        .drv_delete_sub_interface   =   eth_drv_del_sub_interface,
    },
    [VIF_TYPE_VIRTUAL] = {
        .drv_add                    =   eth_drv_add,
        .drv_delete                 =   eth_drv_del,
        .drv_add_sub_interface      =   eth_drv_add_sub_interface,
        .drv_delete_sub_interface   =   eth_drv_del_sub_interface,
    },
    [VIF_TYPE_VIRTUAL_VLAN] = {
        .drv_add                    =   vlan_drv_add,
        .drv_delete                 =   vlan_drv_del,
    },
    [VIF_TYPE_STATS] = {
        .drv_add                    =   eth_drv_add,
        .drv_delete                 =   eth_drv_del,
    },
    [VIF_TYPE_MONITORING] = {
        .drv_add                    =   vhost_drv_add,
        .drv_delete                 =   vhost_drv_del,
    },
};


unsigned int
vif_get_mtu(struct vr_interface *vif)
{
    return hif_ops->hif_get_mtu(vif);
}

static void
vif_free(struct vr_interface *vif)
{
    unsigned int i;

    if (!vif)
        return;

    for (i = 0; i < vr_num_cpus; i++) {
        if (vif->vif_stats[i].vis_queue_ierrors_to_lcore) {
            vr_free(vif->vif_stats[i].vis_queue_ierrors_to_lcore,
                VR_INTERFACE_TO_LCORE_ERRORS_OBJECT);
        }
    }

    if (vif->vif_stats)
        vr_free(vif->vif_stats, VR_INTERFACE_STATS_OBJECT);

    if (vif->vif_vrf_table) {
        vr_free(vif->vif_vrf_table, VR_INTERFACE_VRF_TABLE_OBJECT);
        vif->vif_vrf_table = NULL;
    }

    if (vif->vif_sub_interfaces) {
        vr_free(vif->vif_sub_interfaces, VR_INTERFACE_OBJECT);
        vif->vif_sub_interfaces = NULL;
    }

    if (vif->vif_btable) {
        vif_bridge_deinit(vif);
    }

    if (vif->vif_src_mac) {
        vr_free(vif->vif_src_mac, VR_INTERFACE_MAC_OBJECT);
        vif->vif_src_mac = NULL;
    }

    for (i = 0; i < VIF_FAT_FLOW_MAXPROTO_INDEX; i++) {
        if (vif->vif_fat_flow_config[i]) {
            vr_free(vif->vif_fat_flow_config[i],
                    VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
            vif->vif_fat_flow_config[i] = NULL;
        }

        if (vif->vif_fat_flow_ports[i]) {
            vif_fat_flow_free(vif->vif_fat_flow_ports[i]);
            vif->vif_fat_flow_ports[i] = NULL;
        }
    }

    vr_free(vif, VR_INTERFACE_OBJECT);

    return;
}

void
vrouter_put_interface(struct vr_interface *vif)
{
    if (!__sync_sub_and_fetch(&vif->vif_users, 1))
        vif_free(vif);

    return;
}

struct vr_interface *
__vrouter_get_interface(struct vrouter *router, unsigned int idx)
{
    if (!router || idx >= router->vr_max_interfaces)
        return NULL;

    return router->vr_interfaces[idx];
}

struct vr_interface *
__vrouter_get_interface_os(struct vrouter *router, unsigned int os_idx)
{
    unsigned int i;
    struct vr_interface *vif;

    for (i = 0; i < router->vr_max_interfaces; i++) {
        vif = __vrouter_get_interface(router, i);
        if (vif && vif->vif_os_idx == os_idx)
            return vif;
    }

    return NULL;
}


struct vr_interface *
vrouter_get_interface(unsigned int rid, unsigned int idx)
{
    struct vr_interface *vif;
    struct vrouter *router = vrouter_get(rid);

    vif = __vrouter_get_interface(router, idx);
    if (vif)
        vif->vif_users++;

    return vif;
}

static void
vrouter_del_interface(struct vr_interface *vif)
{
    struct vrouter *router;

    if (!vif || !(router = vrouter_get(vif->vif_rid)))
        return;

    if (vif->vif_idx >= router->vr_max_interfaces)
        return;

    if (router->vr_interfaces[vif->vif_idx] != vif)
        return;

    router->vr_interfaces[vif->vif_idx] = NULL;

    switch (vif->vif_type) {
    case VIF_TYPE_AGENT:
        router->vr_agent_if = NULL;
        break;

    case VIF_TYPE_HOST:
        router->vr_host_if = NULL;
        if (vif->vif_bridge) {
            vif->vif_bridge->vif_bridge = NULL;
            vif->vif_bridge = NULL;
        }

        break;

    case VIF_TYPE_PHYSICAL:
        if (vif->vif_bridge) {
            vif->vif_bridge->vif_bridge = NULL;
            vif->vif_bridge = NULL;
        }

        if (router->vr_eth_if == vif)
            router->vr_eth_if = NULL;

        break;

    case VIF_TYPE_VIRTUAL:
        break;

    default:
        break;
    }

    if (!vr_not_ready)
        vr_delay_op();

    vrouter_put_interface(vif);

    return;
}

static void
vrouter_setup_vif(struct vr_interface *vif)
{
    switch (vif->vif_type) {
    case VIF_TYPE_AGENT:
        agent_alive = true;
        vhost_remove_xconnect();
        break;

    case VIF_TYPE_HOST:
        if (!agent_alive) {
            vif_set_xconnect(vif);
            if (vif->vif_bridge)
                vif_set_xconnect(vif->vif_bridge);
        } else {
            vif_remove_xconnect(vif);
            if (vif->vif_bridge)
                vif_remove_xconnect(vif->vif_bridge);
        }

        break;

    default:
        break;
    }

    return;
}

/*
 * rewrite information is needed in cases where the packets are sent out
 * on cases other than from nexthops. one instance where having a rewrite
 * helps is for packets that are trapped to the agent from datapath.
 */
static void
vrouter_set_rewrite(struct vr_interface *vif)
{
    unsigned char *ptr;

    ptr = vif->vif_rewrite;
    /*
     * the DMAC would already have been set as part of
     * driver add
     */
    ptr += VR_ETHER_ALEN;
    memcpy(ptr, vif->vif_mac, VR_ETHER_ALEN);
    ptr += VR_ETHER_ALEN;
    *(unsigned short *)ptr = htons(VR_ETH_PROTO_IP);

    return;
}

/*
 * add the interface to the vrouter. essentially, we init the
 * reference count
 */
static int
vrouter_add_interface(struct vr_interface *vif, vr_interface_req *vifr)
{
    struct vrouter *router = vrouter_get(vif->vif_rid);
    struct vr_interface *eth_vif = NULL;

    if (!router)
        return -ENODEV;

    if (router->vr_interfaces[vif->vif_idx])
        return -EEXIST;

    if (vif->vif_type == VIF_TYPE_HOST) {
        if (vifr->vifr_cross_connect_idx < 0)
            return -EINVAL;

        eth_vif = __vrouter_get_interface_os(router, vifr->vifr_cross_connect_idx);
        if (!eth_vif)
            return -ENODEV;
    }

    vif->vif_router = router;
    vif->vif_users++;
    vif->vif_gen = vrouter_generation_num_get(router);
    router->vr_interfaces[vif->vif_idx] = vif;

    switch (vif->vif_type) {
    case VIF_TYPE_AGENT:
        router->vr_agent_if = vif;
        break;

    case VIF_TYPE_HOST:
        router->vr_host_if = vif;
        router->vr_eth_if = eth_vif;
        vif->vif_bridge = eth_vif;
        eth_vif->vif_bridge = vif;

        break;

    default:
        break;
    }

    vrouter_set_rewrite(vif);

    return 0;
}

void
vif_attach(struct vr_interface *vif)
{
    if (vif_drivers[vif->vif_type].drv_add)
        vif_drivers[vif->vif_type].drv_add(vif, NULL);

    return;
}

void
vif_detach(struct vr_interface *vif)
{
    if (vif_drivers[vif->vif_type].drv_delete)
        vif_drivers[vif->vif_type].drv_delete(vif);

    return;
}

static void
vif_drv_delete(struct vr_interface *vif)
{
    if (hif_ops->hif_lock)
        hif_ops->hif_lock();

    /*
     * setting name to NULL is important in preventing races. Races mainly
     * come from interfaces going away/coming back (from OS. mainly virtual
     * interfaces such as vlan, tap, bond etc.) and agent simultaneously
     * trying to add/delete vif. vif_find will be used by the OS specific
     * code when an interface goes away/comes back to find the vif corresponding
     * to the name. Setting name to NULL partially makes sure that vif is
     * not found in delete cases. the other safety we have is in the rtnl_lock.
     * the hos_if_* (add/del/tap) does some jugglery (which involves, checking
     * for name) under rtnl_lock to make sure that states are proper.
     */
    vif->vif_name[0] = '\0';
    if (vif_drivers[vif->vif_type].drv_delete)
        vif_drivers[vif->vif_type].drv_delete(vif);

    /*
     * the check is right. If you haven't defined unlock, you deserve the
     * crash
     */
    if (hif_ops->hif_lock)
        hif_ops->hif_unlock();

    return;
}

int
vif_delete(struct vr_interface *vif)
{
    vif_drv_delete(vif);
    vrouter_del_interface(vif);
    return 0;
}

struct vr_interface *
vif_find(struct vrouter *router, char *name)
{
    int i;
    struct vr_interface *vif;

    for (i = 0; i < router->vr_max_interfaces; i++) {
        vif = router->vr_interfaces[i];
        if (vif && !strncmp(vif->vif_name, name, sizeof(vif->vif_name)))
            return vif;
    }

    return NULL;
}

static int
vif_drv_add(struct vr_interface *vif, vr_interface_req *req)
{
    int ret = 0;

    if (vif_drivers[vif->vif_type].drv_add) {
        if (hif_ops->hif_lock)
            hif_ops->hif_lock();

        ret = vif_drivers[vif->vif_type].drv_add(vif, req);

        /*
         * the check is right. If you haven't defined unlock, you deserve the
         * crash
         */
        if (hif_ops->hif_lock)
            hif_ops->hif_unlock();

        if (ret)
            return ret;
    }

    vif->vif_driver = &vif_drivers[vif->vif_type];
    return 0;

}

static int
vr_interface_delete(vr_interface_req *req, bool need_response)
{
    int ret = 0;
    struct vr_interface *vif;
    struct vrouter *router = vrouter_get(req->vifr_rid);

    vif = __vrouter_get_interface(router, req->vifr_idx);
    if (!vif && (ret = -ENODEV))
        goto del_fail;

    vif_delete(vif);

del_fail:
    if (need_response)
        vr_send_response(ret);

    return ret;
}

static void
vif_set_flags(struct vr_interface *vif, vr_interface_req *req)
{
    vif->vif_flags = (vif->vif_flags & VIF_VR_CAP_MASK) |
                     (req->vifr_flags & ~VIF_VR_CAP_MASK);

    /*
     * If both L3 and L2 are disabled, enabled L3 with fallback bridging
     * by default to avoid total blackout of packets
     */
    if (!(vif->vif_flags & (VIF_FLAG_L3_ENABLED | VIF_FLAG_L2_ENABLED))) {
        vif->vif_flags |= (VIF_FLAG_L3_ENABLED | VIF_FLAG_L2_ENABLED);
    }

    return;
}

static int
vr_interface_change(struct vr_interface *vif, vr_interface_req *req)
{
    int ret = 0;

    if (req->vifr_flags & VIF_FLAG_SERVICE_IF &&
            !(vif->vif_flags & VIF_FLAG_SERVICE_IF)) {
        ret = vr_interface_service_enable(vif);
        if (ret)
            return ret;
    } else if ((vif->vif_flags & VIF_FLAG_SERVICE_IF) &&
            !(req->vifr_flags & VIF_FLAG_SERVICE_IF)) {
        vr_interface_service_disable(vif);
    }

    vif_set_flags(vif, req);

    vif->vif_mirror_id = req->vifr_mir_id;
    if (!(vif->vif_flags & VIF_FLAG_MIRROR_RX) &&
        !(vif->vif_flags & VIF_FLAG_MIRROR_TX)) {
        vif->vif_mirror_id = VR_MAX_MIRROR_INDICES;
    }
    if (req->vifr_vrf >= 0)
        vif->vif_vrf = req->vifr_vrf;

    if (req->vifr_mtu)
        vif->vif_mtu = req->vifr_mtu;

    vif->vif_nh_id = (unsigned short)req->vifr_nh_id;
    vif->vif_qos_map_index = req->vifr_qos_map_index;

    if ((ret = vif_fat_flow_add(vif, req)))
        return ret;

    return 0;
}

static bool
vif_transport_valid(vr_interface_req *req)
{
    switch (req->vifr_transport) {
    case VIF_TRANSPORT_VIRTUAL:
    case VIF_TRANSPORT_ETH:
    case VIF_TRANSPORT_PMD:
    case VIF_TRANSPORT_SOCKET:
        return true;

    default:
        break;
    }

    return false;
}

int
vr_interface_add(vr_interface_req *req, bool need_response)
{
    int i, ret = 0;
    struct vr_interface *vif = NULL;
    struct vrouter *router = vrouter_get(req->vifr_rid);

    if (!router || ((unsigned int)req->vifr_idx >= router->vr_max_interfaces)) {
        ret = -EINVAL;
        goto generate_resp;
    }

    if (req->vifr_type >= VIF_TYPE_MAX && (ret = -EINVAL))
        goto generate_resp;

    if (!vif_transport_valid(req))
        goto generate_resp;

    vif = __vrouter_get_interface(router, req->vifr_idx);
    if (vif) {
        ret = vr_interface_change(vif, req);
        goto generate_resp;
    }

    vif = vr_zalloc(sizeof(*vif), VR_INTERFACE_OBJECT);
    if (!vif) {
        ret = -ENOMEM;
        goto generate_resp;
    }

    vif->vif_stats = vr_zalloc(vr_num_cpus *
            sizeof(struct vr_interface_stats), VR_INTERFACE_STATS_OBJECT);
    if (!vif->vif_stats) {
        ret = -ENOMEM;
        goto generate_resp;
    }

    for (i = 0; i < vr_num_cpus; i++) {
        vif->vif_stats[i].vis_queue_ierrors_to_lcore = vr_zalloc(vr_num_cpus *
                sizeof(uint64_t), VR_INTERFACE_TO_LCORE_ERRORS_OBJECT);
        if (!vif->vif_stats[i].vis_queue_ierrors_to_lcore) {
            ret = -ENOMEM;
            goto generate_resp;
        }
    }

    vif->vif_type = req->vifr_type;

    vif_set_flags(vif, req);

    vif->vif_mirror_id = req->vifr_mir_id;
    if (!(vif->vif_flags & VIF_FLAG_MIRROR_RX) &&
        !(vif->vif_flags & VIF_FLAG_MIRROR_TX)) {
        vif->vif_mirror_id = VR_MAX_MIRROR_INDICES;
    }

    vif->vif_vrf = req->vifr_vrf;
    vif->vif_vlan_id = VLAN_ID_INVALID;
    vif->vif_mtu = req->vifr_mtu;
    vif->vif_idx = req->vifr_idx;
    vif->vif_transport = req->vifr_transport;
    vif->vif_os_idx = req->vifr_os_idx;
    if (req->vifr_os_idx == -1)
        vif->vif_os_idx = 0;
    vif->vif_rid = req->vifr_rid;
    vif->vif_nh_id = (unsigned short)req->vifr_nh_id;
    vif->vif_qos_map_index = req->vifr_qos_map_index;

    if (req->vifr_mac) {
        if (req->vifr_mac_size != sizeof(vif->vif_mac)) {
            ret = -EINVAL;
            goto generate_resp;
        }

        memcpy(vif->vif_mac, req->vifr_mac, sizeof(vif->vif_mac));
        memcpy(vif->vif_rewrite, req->vifr_mac, sizeof(vif->vif_mac));
    }

    vif->vif_ip = req->vifr_ip;

    if (req->vifr_name) {
        strncpy(vif->vif_name, req->vifr_name, sizeof(vif->vif_name) - 1);
    }

    ret = vif_fat_flow_add(vif, req);
    if (ret)
        goto generate_resp;

    /*
     * the order below is probably not intuitive, but we do this because
     * the moment we do a drv_add, packets will start coming in and find
     * that vif_router is not set. to avoid checks such as !vif_router in
     * datapath, the order has to be what is below.
     */
    vif->vif_rx = vif_discard_rx;
    vif->vif_tx = vif_discard_tx;
    ret = vrouter_add_interface(vif, req);
    if (ret)
        goto generate_resp;

    ret = vif_drv_add(vif, req);
    if (ret) {
        vif_delete(vif);
        vif = NULL;
    }

    if (!ret)
        vrouter_setup_vif(vif);

generate_resp:
    if (need_response)
        vr_send_response(ret);

    if (ret && vif)
        vif_free(vif);

    return ret;
}

static void
vr_interface_add_response(vr_interface_req *req,
                            struct vr_interface_stats *stats)
{
    int i;

    req->vifr_ibytes += stats->vis_ibytes;
    req->vifr_ipackets += stats->vis_ipackets;
    req->vifr_ierrors += stats->vis_ierrors;
    req->vifr_obytes += stats->vis_obytes;
    req->vifr_opackets += stats->vis_opackets;
    req->vifr_oerrors += stats->vis_oerrors;

    req->vifr_queue_ipackets += stats->vis_queue_ipackets;
    for (i = 0; i < vr_num_cpus; i++)
        req->vifr_queue_ierrors_to_lcore[i] += stats->vis_queue_ierrors_to_lcore[i];
    req->vifr_queue_ierrors_to_lcore_size = vr_num_cpus;
    req->vifr_queue_ierrors += stats->vis_queue_ierrors;
    req->vifr_queue_opackets += stats->vis_queue_opackets;
    req->vifr_queue_oerrors += stats->vis_queue_oerrors;

    req->vifr_port_ipackets += stats->vis_port_ipackets;
    req->vifr_port_ierrors += stats->vis_port_ierrors;
    req->vifr_port_isyscalls += stats->vis_port_isyscalls;
    req->vifr_port_inombufs += stats->vis_port_inombufs;
    req->vifr_port_opackets += stats->vis_port_opackets;
    req->vifr_port_oerrors += stats->vis_port_oerrors;
    req->vifr_port_osyscalls += stats->vis_port_osyscalls;

    req->vifr_dev_ibytes += stats->vis_dev_ibytes;
    req->vifr_dev_ipackets += stats->vis_dev_ipackets;
    req->vifr_dev_ierrors += stats->vis_dev_ierrors;
    req->vifr_dev_inombufs += stats->vis_dev_inombufs;
    req->vifr_dev_obytes += stats->vis_dev_obytes;
    req->vifr_dev_opackets += stats->vis_dev_opackets;
    req->vifr_dev_oerrors += stats->vis_dev_oerrors;
}

static void
__vr_interface_make_req(vr_interface_req *req, struct vr_interface *intf,
        unsigned int core)
{
    uint8_t proto;
    uint16_t port;
    unsigned int cpu, i, j, k = 0;

    struct vr_interface_settings settings;

    req->vifr_core = core;
    req->vifr_type = intf->vif_type;
    req->vifr_flags = intf->vif_flags;
    req->vifr_vrf = intf->vif_vrf;
    req->vifr_idx = intf->vif_idx;
    req->vifr_rid = intf->vif_rid;
    req->vifr_transport = intf->vif_transport;
    req->vifr_os_idx = intf->vif_os_idx;
    req->vifr_mtu = intf->vif_mtu;
    if (req->vifr_mac_size && req->vifr_mac)
        memcpy(req->vifr_mac, intf->vif_mac,
                MINIMUM(req->vifr_mac_size, sizeof(intf->vif_mac)));
    req->vifr_ip = intf->vif_ip;
    req->vifr_mir_id = intf->vif_mirror_id;

    req->vifr_ref_cnt = intf->vif_users;

    if (req->vifr_name) {
        strncpy(req->vifr_name, intf->vif_name, VR_INTERFACE_NAME_LEN - 1);
    }

    if (intf->vif_parent)
        req->vifr_parent_vif_idx = intf->vif_parent->vif_idx;
    else
        req->vifr_parent_vif_idx = -1;

    if (intf->vif_type == VIF_TYPE_VIRTUAL_VLAN) {
        req->vifr_vlan_id = intf->vif_vlan_id;
        req->vifr_ovlan_id = intf->vif_ovlan_id;
    }

    if (intf->vif_src_mac) {
        memcpy(req->vifr_src_mac, intf->vif_src_mac, VR_ETHER_ALEN);
        req->vifr_src_mac_size = VR_ETHER_ALEN;
        req->vifr_bridge_idx = vif_bridge_get_index(intf->vif_parent, intf);
    } else {
        /*
         * this is a small hack. we had already allocated the memory in
         * req_get and it is common for all interfaces. how do we tell
         * that the field is not valid - by setting the size to 0.
         */
        req->vifr_src_mac_size = 0;
    }

    /* vif counters */
    req->vifr_ibytes = 0;
    req->vifr_ipackets = 0;
    req->vifr_ierrors = 0;
    req->vifr_obytes = 0;
    req->vifr_opackets = 0;
    req->vifr_oerrors = 0;
    /* queue counters */
    req->vifr_queue_ipackets = 0;
    for (i = 0; i < VR_MAX_CPUS; i++)
        req->vifr_queue_ierrors_to_lcore[i] = 0;
    req->vifr_queue_ierrors = 0;
    req->vifr_queue_opackets = 0;
    req->vifr_queue_oerrors = 0;
    /* port counters */
    req->vifr_port_ipackets = 0;
    req->vifr_port_ierrors = 0;
    req->vifr_port_isyscalls = 0;
    req->vifr_port_inombufs = 0;
    req->vifr_port_opackets = 0;
    req->vifr_port_oerrors = 0;
    req->vifr_port_osyscalls = 0;
    /* device counters */
    req->vifr_dev_ibytes = 0;
    req->vifr_dev_ipackets = 0;
    req->vifr_dev_ierrors = 0;
    req->vifr_dev_inombufs = 0;
    req->vifr_dev_obytes = 0;
    req->vifr_dev_opackets = 0;
    req->vifr_dev_oerrors = 0;

    /* call host callback if available */
    if (hif_ops->hif_stats_update) {
        hif_ops->hif_stats_update(intf, core);
    }

    if (core == (unsigned)-1) {
        /* summed up stats */
        for (cpu = 0; cpu < vr_num_cpus; cpu++) {
            vr_interface_add_response(req, vif_get_stats(intf, cpu));
        }
    } else if (core < vr_num_cpus) {
        /* stats for a specific core */
        vr_interface_add_response(req, vif_get_stats(intf, core));
    }
    /* otherwise the conters will be zeros */

    req->vifr_speed = -1;
    req->vifr_duplex = -1;
    if (intf->vif_type == VIF_TYPE_PHYSICAL) {
        if (!hif_ops->hif_get_settings(intf, &settings)) {
            req->vifr_speed = settings.vis_speed;
            req->vifr_duplex = settings.vis_duplex;
        }
    }

    for (i = 0; i < VIF_FAT_FLOW_MAXPROTO_INDEX; i++) {
        switch (i) {
        case VIF_FAT_FLOW_TCP_INDEX:
            proto = VR_IP_PROTO_TCP;
            break;

        case VIF_FAT_FLOW_UDP_INDEX:
            proto = VR_IP_PROTO_UDP;
            break;

        case VIF_FAT_FLOW_SCTP_INDEX:
            proto = VR_IP_PROTO_SCTP;
            break;

        default:
            proto = 0;
            break;
        }

        if (req->vifr_fat_flow_protocol_port &&
                req->vifr_fat_flow_protocol_port_size) {
            for (j = 0; j < intf->vif_fat_flow_config_size[i]; j++) {
                port = intf->vif_fat_flow_config[i][j];
                if (vif_fat_flow_port_is_set(intf, i, port)) {
                    req->vifr_fat_flow_protocol_port[k++] = (proto << 16) | port;
                } else {
                    vr_printf("vif0/%u: FatFlow port %u in configuration,"
                            " but not in operational DB\n",
                            intf->vif_idx, port);
                }
            }
        }
    }

    req->vifr_qos_map_index = intf->vif_qos_map_index;
    return;
}

static int
vr_interface_make_req(vr_interface_req *req, struct vr_interface *vif,
        unsigned int core)
{
    unsigned int i, fat_flow_config_size;

    fat_flow_config_size = 0;
    for (i = 0; i < VIF_FAT_FLOW_MAXPROTO_INDEX; i++)
        fat_flow_config_size += vif->vif_fat_flow_config_size[i];

    if (fat_flow_config_size) {
        req->vifr_fat_flow_protocol_port =
            vr_zalloc(fat_flow_config_size * sizeof(uint32_t),
                    VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!req->vifr_fat_flow_protocol_port) {
            return -ENOMEM;
        }
        req->vifr_fat_flow_protocol_port_size = fat_flow_config_size;
    }

    __vr_interface_make_req(req, vif, core);

    return 0;
}

static vr_interface_req *
vr_interface_req_get(void)
{
    vr_interface_req *req;

    req = vr_zalloc(sizeof(*req), VR_INTERFACE_REQ_OBJECT);
    if (!req)
        return req;

    req->vifr_mac = vr_zalloc(VR_ETHER_ALEN, VR_INTERFACE_REQ_MAC_OBJECT);
    if (req->vifr_mac)
        req->vifr_mac_size = VR_ETHER_ALEN;

    req->vifr_src_mac = vr_zalloc(VR_ETHER_ALEN, VR_INTERFACE_REQ_MAC_OBJECT);
    if (req->vifr_src_mac)
        req->vifr_src_mac_size = 0;
    req->vifr_name = vr_zalloc(VR_INTERFACE_NAME_LEN,
            VR_INTERFACE_REQ_NAME_OBJECT);

    req->vifr_queue_ierrors_to_lcore = vr_zalloc(VR_MAX_CPUS * sizeof(uint64_t),
            VR_INTERFACE_REQ_TO_LCORE_ERRORS_OBJECT);
    if (req->vifr_queue_ierrors_to_lcore)
        req->vifr_queue_ierrors_to_lcore_size = 0;

    return req;
}


static void
vr_interface_req_free_fat_flow_config(vr_interface_req *req)
{
    if (req->vifr_fat_flow_protocol_port) {
        vr_free(req->vifr_fat_flow_protocol_port,
                VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        req->vifr_fat_flow_protocol_port = NULL;
        req->vifr_fat_flow_protocol_port_size = 0;
    }

    return;
}

static void
vr_interface_req_destroy(vr_interface_req *req)
{
    if (!req)
        return;

    if (req->vifr_mac) {
        vr_free(req->vifr_mac, VR_INTERFACE_REQ_MAC_OBJECT);
        req->vifr_mac_size = 0;
    }

    if (req->vifr_src_mac) {
        vr_free(req->vifr_src_mac, VR_INTERFACE_REQ_MAC_OBJECT);
        req->vifr_src_mac_size = 0;
    }

    if (req->vifr_name)
        vr_free(req->vifr_name, VR_INTERFACE_REQ_NAME_OBJECT);

    if (req->vifr_queue_ierrors_to_lcore) {
        vr_free(req->vifr_queue_ierrors_to_lcore,
            VR_INTERFACE_REQ_TO_LCORE_ERRORS_OBJECT);
        req->vifr_queue_ierrors_to_lcore_size = 0;
    }

    vr_interface_req_free_fat_flow_config(req);

    vr_free(req, VR_INTERFACE_REQ_OBJECT);

    return;
}

static int
vr_interface_get(vr_interface_req *req)
{
    int ret = 0;

    struct vr_interface *vif = NULL;
    struct vrouter *router;
    vr_interface_req *resp = NULL;

    router = vrouter_get(req->vifr_rid);
    if (!router) {
        ret = -ENODEV;
        goto generate_response;
    }

    if ((unsigned int)req->vifr_idx >= router->vr_max_interfaces)
        vif = __vrouter_get_interface_os(router, req->vifr_os_idx);
    else
        vif = __vrouter_get_interface(router, req->vifr_idx);

    if (vif) {
        resp = vr_interface_req_get();
        if (!resp) {
            ret = -ENOMEM;
            goto generate_response;
        }

        /* zero vifr_core means to sum up all the per-core stats */
        vr_interface_make_req(resp, vif, (unsigned)(req->vifr_core - 1));
    } else
        ret = -ENOENT;

generate_response:
    vr_message_response(VR_INTERFACE_OBJECT_ID, ret ? NULL : resp, ret);
    if (resp)
        vr_interface_req_destroy(resp);

    return 0;
}

static int
vr_interface_dump(vr_interface_req *r)
{
    int ret = 0;
    unsigned int i;
    vr_interface_req *resp = NULL;
    struct vr_interface *vif;
    struct vrouter *router = vrouter_get(r->vifr_vrf);
    struct vr_message_dumper *dumper = NULL;

    if (!router && (ret = -ENODEV))
        goto generate_response;

    if ((unsigned int)(r->vifr_marker + 1) >= router->vr_max_interfaces)
        goto generate_response;

    dumper = vr_message_dump_init(r);
    if (!dumper) {
        ret = -ENOMEM;
        goto generate_response;
    }

    resp = vr_interface_req_get();
    if (!resp) {
        ret = -ENOMEM;
        goto generate_response;
    }

    for (i = (unsigned int)(r->vifr_marker + 1);
            i < router->vr_max_interfaces; i++) {
        vif = router->vr_interfaces[i];
        if (vif) {
            /* zero vifr_core means to sum up all the per-core stats */
            vr_interface_make_req(resp, vif, (unsigned)(r->vifr_core - 1));
            ret = vr_message_dump_object(dumper, VR_INTERFACE_OBJECT_ID, resp);
            if (ret <= 0)
                break;
        }

        vr_interface_req_free_fat_flow_config(resp);
    }

generate_response:
    vr_message_dump_exit(dumper, ret);
    if (resp)
        vr_interface_req_destroy(resp);

    return 0;
}

void
vr_interface_req_process(void *s_req)
{
    int ret;
    vr_interface_req *req = (vr_interface_req *)s_req;
    bool need_response = true;

    switch (req->h_op) {
    case SANDESH_OP_ADD:
        ret = vr_interface_add(req, need_response);
        break;

    case SANDESH_OP_GET:
        ret = vr_interface_get(req);
        break;

    case SANDESH_OP_DELETE:
        ret = vr_interface_delete(req, need_response);
        break;

    case SANDESH_OP_DUMP:
        ret = vr_interface_dump(req);
        break;

    default:
        ret = -EOPNOTSUPP;
        goto error;
    }

    return;

error:
    vr_send_response(ret);
    return;
}

unsigned int
vif_vrf_table_get_nh(struct vr_interface *vif, unsigned short vlan)
{
    if (vlan >= VLAN_ID_INVALID || !vif_is_service(vif))
        return vif->vif_nh_id;

    if (!vif->vif_vrf_table)
        return vif->vif_nh_id;

    return vif->vif_vrf_table[vlan].va_nh_id;
}

int
vif_vrf_table_get(struct vr_interface *vif, vr_vrf_assign_req *req)
{
    if (!vif_is_service(vif))
        return -EINVAL;

    if (!vif->vif_vrf_table)
        return -ENOMEM;

    if (req->var_vlan_id >= VIF_VRF_TABLE_ENTRIES)
        return -EINVAL;

    req->var_vif_vrf = vif->vif_vrf_table[req->var_vlan_id].va_vrf;
    req->var_nh_id = vif->vif_vrf_table[req->var_vlan_id].va_nh_id;
    return 0;
}

/*
 * the logic here is slightly hacky. 'agent' cannot ensure that
 * the service flag is unset only after all vrf table entries are
 * deleted. so, it is possible that the service flag is unset and
 * requests can still come for deletion of vrf table entries, and
 * error cannot be returned in such cases. so,reference counts are
 * taken and the table is freed only when the reference count goes
 * to zero or when the interface is actually deleted
 */
int
vif_vrf_table_set(struct vr_interface *vif, unsigned int vlan,
        int vrf, unsigned int nh_id)
{
    int ret = 0;

    if (!vif->vif_vrf_table) {
        /*
         * 1. if the service flag is not set, then we make the interface
         *    as the service interface
         *
         * 2. service flag is set and we were not able to allocate
         *    the table
         */
        if (!vif_is_service(vif)) {
            ret = vr_interface_service_enable(vif);
            if (ret)
                return ret;
            vif->vif_flags |= VIF_FLAG_SERVICE_IF;
        } else {
            return -ENOMEM;
        }
    }

    if (vlan >= VIF_VRF_TABLE_ENTRIES)
        return -EINVAL;

    /*
     * increment reference count only when the old entry was -1
     * and the new entry is not equal to -1.
     *
     * decrement reference count only when the old entry was >= 0
     * and the new entry is < 0
     */
    if (vif->vif_vrf_table[vlan].va_vrf < 0) {
        if (vrf >= 0)
            vif->vif_vrf_table_users++;
    } else {
        if (vrf < 0)
            vif->vif_vrf_table_users--;
    }

    vif->vif_vrf_table[vlan].va_vrf = vrf;
    vif->vif_vrf_table[vlan].va_nh_id = nh_id;

    /*
     * on last delete, if the service flag is not set, free
     * the table
     */
    if (!(vif->vif_flags & VIF_FLAG_SERVICE_IF) &&
            !vif->vif_vrf_table_users) {
        vr_free(vif->vif_vrf_table, VR_INTERFACE_VRF_TABLE_OBJECT);
        vif->vif_vrf_table = NULL;
    }

    return 0;
}

unsigned int
vif_fat_flow_get_proto_index(uint8_t proto)
{
    unsigned int proto_index = VIF_FAT_FLOW_NOPROTO_INDEX;

    switch (proto) {
    case VR_IP_PROTO_TCP:
        proto_index = VIF_FAT_FLOW_TCP_INDEX;
        break;

    case VR_IP_PROTO_UDP:
        proto_index = VIF_FAT_FLOW_UDP_INDEX;
        break;

    case VR_IP_PROTO_SCTP:
        proto_index = VIF_FAT_FLOW_SCTP_INDEX;
        break;

    default:
        break;
    }

    return proto_index;
}

static uint8_t vif_fat_flow_mem_zero[VIF_FAT_FLOW_BITMAP_BYTES];

static void
__vif_fat_flow_free_defer_cb(struct vrouter *router, void *data)
{
    struct vr_defer_data *vdd = (struct vr_defer_data *)data;

    if (!vdd || !vdd->vdd_data)
        return;

    vr_free(vdd->vdd_data, VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
    return;
}

void
__vif_fat_flow_try_free(struct vr_interface *vif, unsigned int proto_index,
        unsigned int port_row)
{
    uint8_t *mem_column, **mem_row;
    struct vr_defer_data *vdd_row, *vdd_column;

    mem_row = vif->vif_fat_flow_ports[proto_index];
    if (!mem_row)
        return;
    mem_column = mem_row[port_row];

    if (!memcmp(mem_column, vif_fat_flow_mem_zero,
                sizeof(vif_fat_flow_mem_zero))) {
        vdd_column = vr_get_defer_data(sizeof(*vdd_column));
        if (!vdd_column)
            return;

        vif->vif_fat_flow_ports[proto_index][port_row] = NULL;
        vdd_column->vdd_data = (void *)mem_column;
        vr_defer(vif->vif_router, __vif_fat_flow_free_defer_cb, vdd_column);

        if (!memcmp(mem_row, vif_fat_flow_mem_zero,
                    VIF_FAT_FLOW_NUM_BITMAPS)) {
            vdd_row = vr_get_defer_data(sizeof(*vdd_row));
            if (!vdd_row)
                return;

            vif->vif_fat_flow_ports[proto_index] = NULL;
            vdd_row->vdd_data = (void *)mem_row;
            vr_defer(vif->vif_router, __vif_fat_flow_free_defer_cb, vdd_row);
        }


        return;
    }

    return;
}

static void
vif_fat_flow_free(uint8_t  **mem)
{
    int i;

    if (!mem)
        return;

    for (i = 0; i < VIF_FAT_FLOW_NUM_BITMAPS; i++) {
        if (mem[i]) {
            vr_free(mem[i], VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
            mem[i] = NULL;
        }
    }

    vr_free(mem, VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
    return;
}

int
__vif_fat_flow_delete(struct vr_interface *vif, unsigned int proto_index,
        uint16_t port)
{
    unsigned int port_row, port_word, port_bit;

    if (!vif->vif_fat_flow_ports[proto_index])
        return -EINVAL;

    port_row = (port / VIF_FAT_FLOW_BITMAP_SIZE);
    port_word = (port % VIF_FAT_FLOW_BITMAP_SIZE) / (sizeof(uint8_t) * 8);
    port_bit = (port % VIF_FAT_FLOW_BITMAP_SIZE) % (sizeof(uint8_t) * 8);

    if (!vif->vif_fat_flow_ports[proto_index][port_row])
        return -EINVAL;

    vif->vif_fat_flow_ports[proto_index][port_row][port_word] &=
        ~(1 << port_bit);

    __vif_fat_flow_try_free(vif, proto_index, port_row);

    return 0;
}

int
vif_fat_flow_delete(struct vr_interface *vif, uint8_t proto, uint16_t port)
{
    unsigned int proto_index;

    proto_index = vif_fat_flow_get_proto_index(proto);
    return __vif_fat_flow_delete(vif, proto_index, port);
}


int
__vif_fat_flow_add(struct vr_interface *vif, uint8_t proto, uint16_t port)
{
    unsigned int proto_index, port_row, port_word, port_bit;

    bool alloced = false;

    proto_index = vif_fat_flow_get_proto_index(proto);

    if (!vif->vif_fat_flow_ports[proto_index]) {
        vif->vif_fat_flow_ports[proto_index] =
            vr_zalloc(VIF_FAT_FLOW_NUM_BITMAPS * sizeof(unsigned int *),
                    VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!vif->vif_fat_flow_ports)
            return -ENOMEM;
        alloced = true;
    }

    port_row = (port / VIF_FAT_FLOW_BITMAP_SIZE);
    port_word = (port % VIF_FAT_FLOW_BITMAP_SIZE) / (sizeof(uint8_t) * 8);
    port_bit = (port % VIF_FAT_FLOW_BITMAP_SIZE) % (sizeof(uint8_t) * 8);

    if (!vif->vif_fat_flow_ports[proto_index][port_row]) {
        vif->vif_fat_flow_ports[proto_index][port_row] =
            vr_zalloc(VIF_FAT_FLOW_BITMAP_BYTES,
                    VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!vif->vif_fat_flow_ports[proto_index][port_row]) {
            if (alloced) {
                vr_free(vif->vif_fat_flow_ports[proto_index],
                        VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
                return -ENOMEM;
            }
        }
    }

    vif->vif_fat_flow_ports[proto_index][port_row][port_word] |=
        (1 << port_bit);

    return 0;
}

static int
vif_fat_flow_add(struct vr_interface *vif, vr_interface_req *req)
{
    uint8_t proto, proto_index;
    uint16_t port,
             old_fat_flow_config_sizes[VIF_FAT_FLOW_MAXPROTO_INDEX] = { 0 };
    uint16_t *vif_old_fat_flow_config[VIF_FAT_FLOW_MAXPROTO_INDEX] = { NULL };

    int i, j, ret;
    unsigned int size;
    bool add;

    if (!req->vifr_fat_flow_protocol_port_size) {
        if (!memcmp(vif->vif_fat_flow_config_size, old_fat_flow_config_sizes,
                sizeof(old_fat_flow_config_sizes))) {
            return 0;
        }
    } else {
        if (!req->vifr_fat_flow_protocol_port)
            return -EINVAL;
    }

    /*
     * we ideally have to take a difference between the old and the new
     * values and add only those that are new and delete those that are
     * not present in the new, but are present in the old
     *
     * So, first save the old values to a local array.
     */
    memcpy(old_fat_flow_config_sizes, vif->vif_fat_flow_config_size,
            sizeof(old_fat_flow_config_sizes));
    memset(vif->vif_fat_flow_config_size, 0,
            sizeof(vif->vif_fat_flow_config_size));

    memcpy(vif_old_fat_flow_config, vif->vif_fat_flow_config,
            sizeof(vif_old_fat_flow_config));
    memset(vif->vif_fat_flow_config, 0, sizeof(vif->vif_fat_flow_config));

    /*
     * sandesh is expensive. hence we would like to avoid adding more fields
     * to sandesh, if it can be helped. now, such a constraint presents a
     * challenge to know the number of ports present in the request -
     * information that is needed to allocate space to store the current
     * configuration. so, we loop and try to identify the number of ports
     * present per protocol in the request
     */
    for (i = 0; i < req->vifr_fat_flow_protocol_port_size; i++) {
        proto = VIF_FAT_FLOW_PROTOCOL(req->vifr_fat_flow_protocol_port[i]);
        proto_index = vif_fat_flow_get_proto_index(proto);

        vif->vif_fat_flow_config_size[proto_index]++;
    }

    /*
     * ...and then use that information to allocate the array that holds the
     * configuration
     */
    for (i = 0; i < VIF_FAT_FLOW_MAXPROTO_INDEX; i++) {
        if (vif->vif_fat_flow_config_size[i]) {
            vif->vif_fat_flow_config[i] =
                vr_zalloc(vif->vif_fat_flow_config_size[i] * sizeof(uint16_t),
                        VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
            if (!vif->vif_fat_flow_config[i])
                return -ENOMEM;

            /*
             * reset the size so that we can make use of the variable as an
             * index while storing ports
             */
            vif->vif_fat_flow_config_size[i] = 0;
        }
    }

    /* loop through the request and add the new ports */
    for (i = 0; i < req->vifr_fat_flow_protocol_port_size; i++) {
        add = true;

        proto = VIF_FAT_FLOW_PROTOCOL(req->vifr_fat_flow_protocol_port[i]);
        port = VIF_FAT_FLOW_PORT(req->vifr_fat_flow_protocol_port[i]);
        proto_index = vif_fat_flow_get_proto_index(proto);
        if (proto_index == VIF_FAT_FLOW_NOPROTO_INDEX)
            port = proto;


        /* store the port in the protocol specific config */
        if (vif->vif_fat_flow_config[proto_index]) {
            size = vif->vif_fat_flow_config_size[proto_index]++;
            vif->vif_fat_flow_config[proto_index][size] = port;
        }

        /*
         * strike out the common ports with the old configuration in the
         * old configuration so that we can delete the absentees in the
         * new configuration and not add ones that were already present
         * in the old configuration
         */
        for (j = 0; j < old_fat_flow_config_sizes[proto_index]; j++) {
            if (vif_old_fat_flow_config[proto_index][j] == port) {
                /* already present in the old configuration. hence no additon */
                vif_old_fat_flow_config[proto_index][j] = 0;
                add = false;
                break;
            }
        }

        /* add the new one... */
        if (add) {
            ret = __vif_fat_flow_add(vif, proto, port);
            if (ret)
                return ret;
        }
    }

    /* ..and finally delete the old configuration */
    for (i = 0; i < VIF_FAT_FLOW_MAXPROTO_INDEX; i++) {
        for (j = 0; j < old_fat_flow_config_sizes[i]; j++) {
            if (vif_old_fat_flow_config[i] && vif_old_fat_flow_config[i][j])
                __vif_fat_flow_delete(vif, i, vif_old_fat_flow_config[i][j]);
        }

        if (old_fat_flow_config_sizes[i] && vif_old_fat_flow_config[i]) {
            vr_free(vif_old_fat_flow_config[i],
                    VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
            vif_old_fat_flow_config[i] = NULL;
        }
    }

    return 0;
}

static bool
vif_fat_flow_port_is_set(struct vr_interface *vif, uint8_t proto_index,
        uint16_t port)
{
    unsigned int row, column, byte, bit;

    row = proto_index;
    column = port / VIF_FAT_FLOW_BITMAP_SIZE;

    if (vif->vif_fat_flow_ports[row]) {
        if (vif->vif_fat_flow_ports[row][column]) {
            byte = (port % VIF_FAT_FLOW_BITMAP_SIZE) / 8;
            bit = (port % VIF_FAT_FLOW_BITMAP_SIZE) % 8;
            if (vif->vif_fat_flow_ports[row][column][byte] &
                    (1 << bit))
                return true;
        }
    }

    return false;
}

fat_flow_port_mask_t
vif_fat_flow_lookup(struct vr_interface *vif, uint8_t proto,
        uint16_t sport, uint16_t dport)
{
    unsigned int proto_index;
    uint16_t h_sport, h_dport;
    bool sport_set = false, dport_set = false;

    proto_index = vif_fat_flow_get_proto_index(proto);
    if (!vif->vif_fat_flow_config[proto_index])
        return NO_PORT_MASK;

    if (proto_index == VIF_FAT_FLOW_NOPROTO_INDEX) {
        h_sport = h_dport = proto;
    } else {
        h_sport = ntohs(sport);
        h_dport = ntohs(dport);
    }

    sport_set = vif_fat_flow_port_is_set(vif, proto_index, h_sport);
    dport_set = vif_fat_flow_port_is_set(vif, proto_index, h_dport);
    if (sport_set && dport_set) {
        if (proto_index == VIF_FAT_FLOW_NOPROTO_INDEX) {
            return ALL_PORT_MASK;
        } else if (h_dport <= h_sport) {
            return SOURCE_PORT_MASK;
        } else {
            return DESTINATION_PORT_MASK;
        }
    } else if (sport_set) {
        return DESTINATION_PORT_MASK;
    } else if (dport_set) {
        return SOURCE_PORT_MASK;
    }

    return NO_PORT_MASK;
}


int
vr_gro_vif_add(struct vrouter *router, unsigned int os_idx, char *name,
        unsigned short idx)
{
    int ret = 0;
    vr_interface_req *req = vr_interface_req_get();

    if (!req)
        return -ENOMEM;

    req->h_op = SANDESH_OP_ADD;
    req->vifr_type = VIF_TYPE_STATS;
    req->vifr_flags = 0;
    req->vifr_vrf = 65535;
    req->vifr_idx = idx;
    req->vifr_rid = 0;
    req->vifr_transport = VIF_TRANSPORT_ETH;
    req->vifr_os_idx = os_idx;
    req->vifr_mtu = 9136;

    if (req->vifr_name) {
        strncpy(req->vifr_name, name, VR_INTERFACE_NAME_LEN - 1);
    }

    ret = vr_interface_add(req, false);
    vr_interface_req_destroy(req);

    return ret;
}

/*
 * this makes sure that packets no longer enter the module when
 * we remove the module
 */
void
vr_interface_shut(struct vrouter *router)
{
    unsigned int i;
    struct vr_interface *vif;

    if (!router->vr_interfaces)
        return;

    for (i = 0; i < router->vr_max_interfaces; i++) {
        if ((vif = router->vr_interfaces[i])) {
            vif->vif_tx = vif_discard_tx;
            vif->vif_rx = vif_discard_rx;
            vif_drv_delete(vif);
            vif->vif_flags = 0;
        }
    }

    vr_delay_op();
    /* after this, we have a free hand */

    return;
}

void
vr_interface_exit(struct vrouter *router, bool soft_reset)
{
    unsigned int i;
    struct vr_interface *vif;

    if (!router)
        return;

    if (router->vr_interfaces) {
        for (i = 0; i < router->vr_max_interfaces; i++)
            if ((vif = router->vr_interfaces[i]))
                vrouter_del_interface(vif);
    }


    if (!soft_reset) {
        vr_host_interface_exit();
        hif_ops = NULL;
    }

    if (!soft_reset && router->vr_interfaces) {
        vr_free(router->vr_interfaces, VR_INTERFACE_TABLE_OBJECT);
        router->vr_interfaces = NULL;
        router->vr_max_interfaces = 0;
    }

    return;
}

int
vr_interface_init(struct vrouter *router)
{
    int ret = 0;
    unsigned int table_memory = 0;

    if (!router->vr_interfaces) {
        router->vr_max_interfaces = VR_MAX_INTERFACES;
        table_memory = router->vr_max_interfaces *
            sizeof(struct vr_interface *);
        router->vr_interfaces = vr_zalloc(table_memory,
                VR_INTERFACE_TABLE_OBJECT);
        if (!router->vr_interfaces && (ret = -ENOMEM))
            return vr_module_error(ret, __FUNCTION__,
                    __LINE__, table_memory);
    }

    if (!hif_ops) {
        hif_ops = vr_host_interface_init();
        if (!hif_ops && (ret = -ENOMEM)) {
            vr_module_error(ret, __FUNCTION__, __LINE__, 0);
            goto cleanup;
        }
    }

    vr_host_vif_init(router);

    return 0;

cleanup:
    if (router->vr_interfaces) {
        vr_free(router->vr_interfaces, VR_INTERFACE_TABLE_OBJECT);
        router->vr_interfaces = NULL;
        router->vr_max_interfaces = 0;
    }

    return ret;
}

