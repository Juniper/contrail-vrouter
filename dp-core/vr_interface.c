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
#include "vr_btable.h"
#include "vr_route.h"
#include "vr_ip_mtrie.h"
#include "vr_offloads_dp.h"

unsigned int vr_interfaces = VR_MAX_INTERFACES;

volatile bool agent_alive = false;

static struct vr_host_interface_ops *hif_ops;

static int vm_srx(struct vr_interface *, struct vr_packet *, unsigned short);
static int vm_rx(struct vr_interface *, struct vr_packet *, unsigned short);
static int eth_rx(struct vr_interface *, struct vr_packet *, unsigned short);
static mac_response_t vm_mac_request(struct vr_interface *, struct vr_packet *,
                struct vr_forwarding_md *, unsigned char *);
static void vif_fat_flow_free(uint8_t **);
static int vif_fat_flow_add(struct vr_interface *, vr_interface_req *);
static uint8_t vif_fat_flow_port_get(struct vr_interface *, uint8_t,
                uint16_t);
static void __vif_fat_flow_free_all_rule_data_list(vr_fat_flow_prefix_rule_data_t *head);

int vr_gro_vif_add(struct vrouter *, unsigned int, char *, unsigned short);
struct vr_interface_stats *vif_get_stats(struct vr_interface *, unsigned short);
struct vr_interface *__vrouter_get_interface_os(struct vrouter *, unsigned int);

extern struct vr_host_interface_ops *vr_host_interface_init(void);
extern void vr_host_interface_exit(void);
extern void vr_host_vif_init(struct vrouter *);
extern struct vr_interface *vif_bridge_get_sub_interface(vr_htable_t,
        unsigned short, unsigned char *);
extern int vif_bridge_get_index(struct vr_interface *, struct
        vr_interface *, uint8_t *);
extern int vif_bridge_init(struct vr_interface *);
extern void vif_bridge_deinit(struct vr_interface *);
extern int vif_bridge_delete(struct vr_interface *, struct vr_interface
        *, uint8_t *);
extern int vif_bridge_add(struct vr_interface *, struct vr_interface *,
        uint8_t *);
extern void vhost_remove_xconnect(void);
extern void vr_drop_stats_get_vif_stats(vr_drop_stats_req *, struct vr_interface *);

static vr_fat_flow_prefix_rule_data_t dummy_rule = {0};
static int dummy_plen = 255;

#define MINIMUM(a, b) (((a) < (b)) ? (a) : (b))

static inline uint64_t
vr_htonll (uint64_t n)
{
    uint64_t t = 1;
    uint8_t *p, out[8];

    if (*((uint8_t *) &t) == 1) {
        p = (uint8_t *) &n;
        out[0] = *(p + 7);
        out[1] = *(p + 6);
        out[2] = *(p + 5);
        out[3] = *(p + 4);
        out[4] = *(p + 3);
        out[5] = *(p + 2);
        out[6] = *(p + 1);
        out[7] = *(p + 0);
        return (*((uint64_t *) out));
    }
    return n;
}

static inline void
fat_flow_ipv6_plen_to_mask (uint16_t plen, uint64_t *high_mask, uint64_t *low_mask)
{
    if (plen > 64) {
        *high_mask = 0xFFFFFFFFFFFFFFFF;
        *low_mask = vr_htonll((0xFFFFFFFFFFFFFFFF << (128 - plen)));
    } else {
        *low_mask = 0;
        *high_mask = vr_htonll((0xFFFFFFFFFFFFFFFF << (64 - plen)));
    }
}

struct vr_interface_stats *
vif_get_stats(struct vr_interface *vif, unsigned short cpu)
{
    return &vif->vif_stats[cpu & VR_CPU_MASK];
}

static int
vif_discard_tx(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    PKT_LOG(VP_DROP_INTERFACE_TX_DISCARD, pkt, 0, VR_INTERFACE_C, __LINE__);
    vr_pfree(pkt, VP_DROP_INTERFACE_TX_DISCARD);
    return 0;
}

static int
vif_discard_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id __attribute__unused__)
{
    PKT_LOG(VP_DROP_INTERFACE_RX_DISCARD, pkt, 0, VR_INTERFACE_C, __LINE__);
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

    PKT_LOG(VP_DROP_INTERFACE_DROP, pkt, 0, VR_INTERFACE_C, __LINE__);
    vr_pfree(pkt, VP_DROP_INTERFACE_DROP);
    return;
}


/*
 * in the rewrite case, we will assume the positive case of caller
 * passing us valid rewrite ptr and len and will not check for those
 */
static int
vif_cmn_rewrite(struct vr_interface *vif, struct vr_packet **pkt,
        struct vr_forwarding_md *fmd, unsigned char *rewrite,
        unsigned short len)
{
    unsigned char *head;
    struct vr_packet *expanded_pkt;

    if (!len)
        return 0;

    if (pkt_head_space(*pkt) < len) {
        expanded_pkt = vr_pexpand_head(*pkt, len - pkt_head_space(*pkt));
        if (!expanded_pkt)
            return -ENOMEM;
        *pkt = expanded_pkt;
    }

    head = pkt_push(*pkt, len);
    if (!head)
        return -ENOMEM;

    memcpy(head, rewrite, len);
    return len;
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

static inline void
vif_mirror(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd, unsigned int txrx_mirror)
{
    unsigned int mirror_type;
    struct vr_forwarding_md mfmd;
    uint16_t vlan_id;

    if (!txrx_mirror)
        return;

    if (txrx_mirror & VIF_FLAG_MIRROR_TX)
        mirror_type = MIRROR_TYPE_PORT_TX;
    else
        mirror_type = MIRROR_TYPE_PORT_RX;

    if (!fmd) {
        vr_init_forwarding_md(&mfmd);
    } else {
        mfmd = *fmd;
    }

    mfmd.fmd_dvrf = vif->vif_vrf;
    vr_fmd_put_mirror_if_id(&mfmd, vif->vif_idx);

    if (pkt->vp_type == VP_TYPE_NULL)
        vr_pkt_type(pkt, 0, &mfmd);

    vr_mirror(vif->vif_router, vif->vif_mirror_id, pkt, &mfmd, mirror_type);

    vlan_id = vr_fmd_get_mirror_vlan(&mfmd);
    if (vlan_id != FMD_MIRROR_INVALID_DATA)
        vr_fmd_put_mirror_vlan(fmd, vlan_id);

    return;
}

/* agent driver */
static int
agent_set_rewrite(struct vr_interface *vif, struct vr_packet **pkt,
        struct vr_forwarding_md *fmd, unsigned char *rewrite,
        unsigned short len)
{
    unsigned char *head;
    unsigned int hdr_len;
    struct agent_hdr *hdr;
    struct vr_packet *expanded_pkt;

    vr_preset(*pkt);

    hdr_len = sizeof(struct agent_hdr) + len;
    if (pkt_head_space(*pkt) < hdr_len) {
        expanded_pkt = vr_pexpand_head(*pkt, hdr_len - pkt_head_space(*pkt));
        if (!expanded_pkt)
            return -ENOMEM;
        *pkt = expanded_pkt;
    }

    head = pkt_push(*pkt, hdr_len);
    if (!head)
        return -ENOMEM;

    /* copy the rewrite first */
    memcpy(head, rewrite, len);

    hdr = (struct agent_hdr *)(head + len);
    hdr->hdr_ifindex = htons((*pkt)->vp_if->vif_idx);
    hdr->hdr_vrf = htons(fmd->fmd_dvrf);
    /* this needs some thought */
    hdr->hdr_cmd = htons(AGENT_TRAP_NEXTHOP);
    hdr->hdr_cmd_param = 0;

    return len;
}

static int
agent_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id __attribute__unused__)
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
        PKT_LOG(VP_DROP_PULL, pkt, 0, VR_INTERFACE_C, __LINE__);
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

        vr_init_forwarding_md(&fmd);
        vr_virtual_input(ntohs(hdr->hdr_vrf), agent_vif, pkt,
                &fmd, VLAN_ID_INVALID);

        break;

    case AGENT_CMD_SWITCH:
        vif = __vrouter_get_interface(vrouter_get(0), ntohs(hdr->hdr_ifindex));
        if (!vif) {
            stats->vis_ierrors++;
            PKT_LOG(VP_DROP_INVALID_IF, pkt, 0, VR_INTERFACE_C, __LINE__);
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
        PKT_LOG(VP_DROP_INVALID_PACKET, pkt, 0, VR_INTERFACE_C, __LINE__);
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
    case AGENT_TRAP_MAC_LEARN:
    case AGENT_TRAP_MAC_MOVE:
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
            PKT_LOG(VP_DROP_DUPLICATED, pkt, 0, VR_INTERFACE_C, __LINE__);
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
    case AGENT_TRAP_DIAG:
    case AGENT_TRAP_MAC_LEARN:
    case AGENT_TRAP_MAC_MOVE:
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
    PKT_LOG(VP_DROP_PUSH, pkt, 0, VR_INTERFACE_C, __LINE__);
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
        vr_interface_req *vifr __attribute__unused__)
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
    mac_response_t mr = MR_XCONNECT;

    /*
     * Handle all the special cases here. Invoke vm_mac_request(), if
     * the decision to respond is based on standard condittions of
     * overloay
     */
    if (pkt->vp_type == VP_TYPE_ARP) {

        /* Grat ARP, cross connect */
        sarp = (struct vr_arp *)pkt_data(pkt);
        if (vr_grat_arp(sarp))
            return MR_XCONNECT;

        if (IS_LINK_LOCAL_IP(sarp->arp_dpa) ||
                (vif->vif_type == VIF_TYPE_GATEWAY)) {
            VR_MAC_COPY(dmac, vif->vif_mac);
            return MR_PROXY;
        }

        mr = vm_mac_request(vif, pkt, fmd, dmac);
        if ((mr != MR_XCONNECT) && (mr != MR_PROXY)) {
            vr_printf("Vrouter: Vhost arp request Mr %d Dst %x src %x"
                    " converting to Xconnect\n", mr, sarp->arp_dpa,
                    sarp->arp_spa);

            mr = MR_XCONNECT;
        }
    } else {
        /* Handle V6 */
        if (vif->vif_type == VIF_TYPE_GATEWAY)
            mr = MR_DROP;
    }

    return mr;
}

static int
vhost_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id __attribute__unused__)
{
    struct vr_forwarding_md fmd;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    vr_init_forwarding_md(&fmd);
    fmd.fmd_dvrf = vif->vif_vrf;

    /*
     * TODO: Xconnect mode: Ideally all the flow processing need to happen
     * even in this mode. If there is no existing flow available, then
     * it can be chosen to be cross connected. For the time being, all
     * are cross connected
     */
    if (vif_mode_xconnect(vif))
        return vif_xconnect(vif, pkt, &fmd);

    vif_mirror(vif, pkt, &fmd, vif->vif_flags & VIF_FLAG_MIRROR_RX);

    return vr_fabric_input(vif, pkt, &fmd, vlan_id);
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
                    PKT_LOG(VP_DROP_PULL, pkt, 0, VR_INTERFACE_C, __LINE__);
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

    vif_mirror(vif, pkt, fmd, vif->vif_flags & VIF_FLAG_MIRROR_TX);

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
        vr_interface_req *vifr __attribute__unused__)
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
        unsigned short vlan_id __attribute__unused__)
{
    int8_t tos;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);
    struct vr_forwarding_md fmd;

    vr_init_forwarding_md(&fmd);
    pkt->vp_if = vif;

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    if (!(vif->vif_flags & VIF_FLAG_MIRROR_NOTAG))
        vif_mirror(vif, pkt, NULL, vif->vif_flags & VIF_FLAG_MIRROR_RX);

    tos = vr_vlan_get_tos(pkt_data(pkt));
    if (tos >= 0)
        pkt->vp_priority = tos;

    if (vr_untag_pkt(pkt)) {
        stats->vis_ierrors++;
        PKT_LOG(VP_DROP_PULL, pkt, 0, VR_INTERFACE_C, __LINE__);
        vr_pfree(pkt, VP_DROP_PULL);
        return 0;
    }

    vr_pset_data(pkt, pkt->vp_data);

    if (vif->vif_flags & VIF_FLAG_MIRROR_NOTAG)
        vif_mirror(vif, pkt, NULL, vif->vif_flags & VIF_FLAG_MIRROR_RX);

    return vr_virtual_input(vif->vif_vrf, vif, pkt, &fmd, VLAN_ID_INVALID);
}


static int
vlan_tx(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    bool force_tag = false;
    int ret = 0;
    struct vr_interface *pvif;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    if (!vr_pkt_is_gro(pkt)) {
        stats->vis_obytes += pkt_len(pkt);
        stats->vis_opackets++;
    }

    if (vif->vif_flags & VIF_FLAG_MIRROR_NOTAG)
        vif_mirror(vif, pkt, fmd, vif->vif_flags & VIF_FLAG_MIRROR_TX);

    if (vif_is_vlan(vif)) {
        if (vif->vif_ovlan_id) {
            /*
             * If the packet is already received with Tag on interface,
             * we can force this tag, as double tag is intended
             */
            if (fmd->fmd_vlan != VLAN_ID_INVALID)
                force_tag = true;

            if (vr_tag_pkt(&pkt, vif->vif_ovlan_id, force_tag)) {
                goto drop;
            }
            vr_pset_data(pkt, pkt->vp_data);
        } else {
            vr_vlan_set_priority(pkt);
        }
    }

    if (!(vif->vif_flags & VIF_FLAG_MIRROR_NOTAG))
        vif_mirror(vif, pkt, fmd, vif->vif_flags & VIF_FLAG_MIRROR_TX);

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
    PKT_LOG(VP_DROP_INVALID_IF, pkt, 0, VR_INTERFACE_C, __LINE__);
    vr_pfree(pkt, VP_DROP_INVALID_IF);
    stats->vis_oerrors++;

    return ret;
}

static int
vlan_sub_interface_manage(struct vr_interface *pvif,
        struct vr_interface *vif, int src_mac_num, uint8_t *src_macs)
{
    int i, j, ret;
    uint8_t *vif_mac_entry, *vifr_mac_entry, *free_entry;

    if (!vif || !pvif || !vif->vif_src_mac)
        return 0;

    vif_mac_entry = vif->vif_src_mac;
    for (i = 0; i < VIF_SRC_MACS; i++) {
        if (!IS_MAC_ZERO(vif_mac_entry)) {
            vifr_mac_entry = src_macs;
            for (j = 0; j < src_mac_num; j++) {
                if (VR_MAC_CMP(vifr_mac_entry, vif_mac_entry))
                    break;
                vifr_mac_entry += VR_ETHER_ALEN;
            }
            if (j == src_mac_num) {
                ret = vif_bridge_delete(pvif, vif, vif_mac_entry);
                if (!ret)
                    return ret;

                VR_MAC_RESET(vif_mac_entry);
            }
        }
        vif_mac_entry += VR_ETHER_ALEN;
    }

    vifr_mac_entry = src_macs;
    for (j = 0; j < src_mac_num; j++) {
        if (!IS_MAC_ZERO(vifr_mac_entry)) {

            vif_mac_entry = vif->vif_src_mac;
            free_entry = NULL;

            for (i = 0; i < VIF_SRC_MACS; i++) {

                if (!IS_MAC_ZERO(vif_mac_entry)) {
                    if (VR_MAC_CMP(vifr_mac_entry, vif_mac_entry))
                        break;
                } else if (!free_entry) {
                    free_entry = vif_mac_entry;
                }

                vif_mac_entry += VR_ETHER_ALEN;
            }

            if (i == VIF_SRC_MACS) {
                if (!free_entry)
                    return -ENOSPC;
                ret = vif_bridge_add(pvif, vif, vifr_mac_entry);
                if (ret)
                    return ret;
                VR_MAC_COPY(free_entry, vifr_mac_entry);
            }
        }

        vifr_mac_entry += VR_ETHER_ALEN;
    }


    return 0;
}

static int
vlan_drv_del(struct vr_interface *vif)
{
    int ret = 0;
    struct vr_interface *pvif;

    pvif = vif->vif_parent;
    if (!pvif)
        return 0;

    if (vif->vif_src_mac) {
        vlan_sub_interface_manage(pvif, vif, 0, NULL);
    } else {
        if (pvif->vif_sub_interfaces &&
                (pvif->vif_sub_interfaces[vif->vif_vlan_id] == vif)) {
            pvif->vif_sub_interfaces[vif->vif_vlan_id] = NULL;
        } else {
            ret = -EINVAL;
        }
    }

    if (pvif->vif_driver->drv_delete_sub_interface)
        pvif->vif_driver->drv_delete_sub_interface(pvif, vif);

    if (vif->vif_src_mac) {
        vr_free(vif->vif_src_mac, VR_INTERFACE_MAC_OBJECT);
        vif->vif_src_mac = NULL;
    }

    return ret;
}

static int
vlan_drv_add(struct vr_interface *vif, vr_interface_req *vifr)
{
    int ret = 0;
    struct vr_interface *pvif = NULL;

    if ((unsigned int)(vifr->vifr_parent_vif_idx) > VR_MAX_INTERFACES)
        return -EINVAL;

    if (((unsigned short)(vifr->vifr_vlan_id) >= VLAN_ID_MAX) ||
            ((unsigned short)(vifr->vifr_ovlan_id) >= VLAN_ID_MAX))
        return -EINVAL;

    pvif = vrouter_get_interface(vifr->vifr_rid, vifr->vifr_parent_vif_idx);
    if (!pvif)
        return -EINVAL;

    if (vifr->vifr_src_mac_size && vifr->vifr_src_mac) {
        if (vifr->vifr_src_mac_size % VR_ETHER_ALEN)
            return -EINVAL;
        if ((vifr->vifr_src_mac_size / VR_ETHER_ALEN) > VIF_SRC_MACS)
            return -EINVAL;
        if (!vif->vif_src_mac) {
            vif->vif_src_mac = vr_zalloc((VIF_SRC_MACS * VR_ETHER_ALEN), VR_INTERFACE_MAC_OBJECT);
            if (!vif->vif_src_mac)
                return -ENOMEM;
        }

        if (!pvif->vif_btable) {
            ret = vif_bridge_init(pvif);
            if (ret)
                return ret;
        }
    } else {
        if(!pvif->vif_sub_interfaces) {
            pvif->vif_sub_interfaces = vr_zalloc(
                    VLAN_ID_MAX * sizeof(struct vr_interface *),
                    VR_INTERFACE_OBJECT);
            if (!pvif->vif_sub_interfaces)
                return -ENOMEM;
        }
    }


    if (!vif->vif_mtu)
        vif->vif_mtu = 1514;

    vif->vif_set_rewrite = vif_cmn_rewrite;
    vif->vif_tx = vlan_tx;
    vif->vif_rx = vlan_rx;
    vif->vif_mac_request = vm_mac_request;
    vif->vif_vlan_id = vifr->vifr_vlan_id;
    vif->vif_ovlan_id = vifr->vifr_ovlan_id;


    vif->vif_parent = pvif;

    if (!pvif->vif_driver->drv_add_sub_interface)
        return -EINVAL;

    ret = pvif->vif_driver->drv_add_sub_interface(pvif, vif);
    if (ret)
        return ret;

    if (!vif->vif_src_mac) {
        if (pvif->vif_sub_interfaces[vif->vif_vlan_id])
            return -EEXIST;
        pvif->vif_sub_interfaces[vif->vif_vlan_id] = vif;
    } else {
        return vlan_sub_interface_manage(pvif, vif,
            (vifr->vifr_src_mac_size / VR_ETHER_ALEN), vifr->vifr_src_mac);

    }

    return 0;
}
/* end vlan driver */

/* eth driver */
static int
vm_srx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id)
{
    unsigned short vrf;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);
    struct vr_forwarding_md fmd;

    vr_init_forwarding_md(&fmd);

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    if (vlan_id >= VIF_VRF_TABLE_ENTRIES)
        vrf = vif->vif_vrf;
    else
        vrf = vif->vif_vrf_table[vlan_id].va_vrf;

    vif_mirror(vif, pkt, &fmd, vif->vif_flags & VIF_FLAG_MIRROR_RX);

    return vr_virtual_input(vrf, vif, pkt, &fmd, vlan_id);
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
    struct vr_forwarding_md fmd;
    struct vr_interface *sub_vif = NULL;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);
    struct vr_eth *eth = (struct vr_eth *)pkt_data(pkt);

    vr_init_forwarding_md(&fmd);
    fmd.fmd_dvrf = vif->vif_vrf;

    vif_mirror(vif, pkt, &fmd, vif->vif_flags & VIF_FLAG_MIRROR_RX);

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

    return vr_virtual_input(vif->vif_vrf, vif, pkt, &fmd, vlan_id);
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
        PKT_LOG(VP_DROP_INVALID_PACKET, pkt, 0, VR_INTERFACE_C, __LINE__);
        vr_pfree(pkt, VP_DROP_INVALID_PACKET);
        return 0;
    }

    pkt_set_network_header(pkt, pkt->vp_data);

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = vlan_id;
    fmd.fmd_dvrf = vif->vif_vrf;

    vif_mirror(vif, pkt, &fmd, vif->vif_flags & VIF_FLAG_MIRROR_RX);

    vr_l3_input(pkt, &fmd);

    return 0;
}

/*
 * This function is to handle the decrypted Rx packet. The
 * ipsec encrypted packet is sent up the stack where the
 * linux IPSec kernel handles it. Upon decrypting it
 * the packet is received by the VTI interface, which is
 * the L3 interface that is plumbed to the vrouter.
 * This packet is the L3VPN packet to be processed by vrouter.
 *
*/
static int
ipsec_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id)
{
    struct vrouter *router = vrouter_get(0);
    pkt->vp_if = router->vr_eth_if;
    return eth_rx(vif, pkt, vlan_id);
}

static int
eth_set_rewrite(struct vr_interface *vif, struct vr_packet **pkt,
        struct vr_forwarding_md *fmd, unsigned char *rewrite,
        unsigned short len)
{
    if (!len)
        return 0;

    /*
     * Retain the original headerof the HostOs if the packet is not
     * tunneled packet and not from Agent. Otherwise, apply the new
     * rewrite data
     */
    if (((*pkt)->vp_if->vif_type == VIF_TYPE_HOST) &&
            (!((*pkt)->vp_flags & VP_FLAG_FROM_DP)) &&
            (fmd->fmd_ecmp_src_nh_index == -1) &&
            (((*pkt)->vp_type == VP_TYPE_IP) || ((*pkt)->vp_type == VP_TYPE_IP6))) {
        vr_preset(*pkt);
        return 0;
    }

    return vif_cmn_rewrite(vif, pkt, fmd, rewrite, len);
}

static mac_response_t
eth_mac_request(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd, unsigned char *dmac)
{
    bool underlay_arp = false;
    struct vr_arp *sarp;
    mac_response_t mr;

    if (vif_mode_xconnect(vif))
        return MR_XCONNECT;

    /*
     * If there is a label or if the vrf is different, it is meant for VM's
     */

    sarp = (struct vr_arp *)pkt_data(pkt);
    if ((fmd->fmd_label == -1) && (fmd->fmd_dvrf == vif->vif_vrf)) {
        if (pkt->vp_type == VP_TYPE_ARP) {
            underlay_arp = true;
            if (vr_grat_arp(sarp))
                return MR_TRAP_X;
        }
    }

    mr = vm_mac_request(vif, pkt, fmd, dmac);
    if (underlay_arp && (mr != MR_XCONNECT) && (mr != MR_PROXY)) {
        vr_printf("Vrouter: Vhost arp request Mr %d Dst %x src %x"
                    " converting to Xconnect\n",
                    mr, sarp->arp_dpa, sarp->arp_spa);

        mr = MR_XCONNECT;
    }

    return mr;
}



static int
eth_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id)
{
    struct vr_forwarding_md fmd;
    struct vr_interface *sub_vif = NULL;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);
    struct vr_eth *eth = (struct vr_eth *)pkt_data(pkt);

    vr_init_forwarding_md(&fmd);

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    vif_mirror(vif, pkt, &fmd, vif->vif_flags & VIF_FLAG_MIRROR_RX);

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

    return vr_fabric_input(vif, pkt, &fmd, vlan_id);
}

static int
eth_tx(struct vr_interface *vif, struct vr_packet *pkt,
        struct vr_forwarding_md *fmd)
{
    bool stats_count = true, from_subvif = false, force_tag = true;
    int ret, handled;
    uint16_t vlan_id;

    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    vif_mirror(vif, pkt, fmd, vif->vif_flags & VIF_FLAG_MIRROR_TX);

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
        if (vr_pkt_is_gro(pkt))
            stats_count = false;

        if ((pkt->vp_nh && (pkt->vp_nh->nh_dev != vif)) ||
            ((pkt->vp_if->vif_type == VIF_TYPE_AGENT) &&
                 (fmd->fmd_vlan != VLAN_ID_INVALID))) {
                from_subvif = true;
                stats_count = false;
        }
    } else if (vif_is_fabric(vif)) {
        vlan_id = vr_fmd_get_mirror_vlan(fmd);
        if (vlan_id != FMD_MIRROR_INVALID_DATA) {
            vr_tag_pkt(&pkt, vlan_id, force_tag);
        }
    }

    if (stats_count) {
        stats->vis_obytes += pkt_len(pkt);
        stats->vis_opackets++;
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

    if (vif->vif_parent == pvif) {
        vif->vif_parent = NULL;
        vrouter_put_interface(pvif);
    }
    hif_ops->hif_del(vif);

    return 0;
}

static int
eth_drv_add_sub_interface(struct vr_interface *pvif, struct vr_interface *vif)
{
    return hif_ops->hif_add(vif);
}

static int
eth_drv_add(struct vr_interface *vif,
        vr_interface_req *vifr __attribute__unused__)
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
    } else if ((vif->vif_type == VIF_TYPE_PHYSICAL) &&
               ((hif_ops->hif_get_encap(vif) == VIF_ENCAP_TYPE_L3_DECRYPT))) {
            vif->vif_rx = ipsec_rx;
    }

    /*
     * as soon as we add the tap, packets will start traversing vrouter.
     * now, without a vhost interface getting added, such packets are
     * useless. Also, once reset happens, the physical interface sends
     * packets directly to vhost interface, bypassing vrouter. If we tap
     * here, such packets will be blackholed. hence, do not tap the interface
     * if the interface is set to be associated with a vhost interface.
     */
     /*
      * RX of the decrypted packet is handled.
      */
    if ((!(vif->vif_flags & VIF_FLAG_VHOST_PHYS)) ||
            (vif->vif_bridge) || (hif_ops->hif_get_encap(vif) == VIF_ENCAP_TYPE_L3_DECRYPT)) {
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

    if (vif->vif_bridge_table_lock) {
        vr_free(vif->vif_bridge_table_lock,
                VR_INTERFACE_BRIDGE_LOCK_OBJECT);
        vif->vif_bridge_table_lock = NULL;
    }

    if (vif->vif_hw_queues) {
        vr_free(vif->vif_hw_queues, VR_INTERFACE_QUEUE_OBJECT);
        vif->vif_hw_queues = NULL;
        vif->vif_num_hw_queues = 0;
    }

    if (vif->vif_src_mac) {
        vr_free(vif->vif_src_mac, VR_INTERFACE_MAC_OBJECT);
        vif->vif_src_mac = NULL;
    }

    for (i = 0; i < VIF_FAT_FLOW_MAXPROTO_INDEX; i++) {
        if (vif->vif_fat_flow_no_prefix_rules[i]) {
            vif_fat_flow_free(vif->vif_fat_flow_no_prefix_rules[i]);
            vif->vif_fat_flow_no_prefix_rules[i] = NULL;
        }
    }
    if (vif->vif_fat_flow_v4_src_prefix_rules) {
        vdata_mtrie_delete_all(vif->vif_fat_flow_v4_src_prefix_rules);
    }
    if (vif->vif_fat_flow_v4_dst_prefix_rules) {
        vdata_mtrie_delete_all(vif->vif_fat_flow_v4_dst_prefix_rules);
    }
    if (vif->vif_fat_flow_v6_src_prefix_rules) {
        vdata_mtrie_delete_all(vif->vif_fat_flow_v6_src_prefix_rules);
    }
    if (vif->vif_fat_flow_v6_dst_prefix_rules) {
        vdata_mtrie_delete_all(vif->vif_fat_flow_v6_dst_prefix_rules);
    }
    if (vif->vif_fat_flow_rule_data_list) {
        __vif_fat_flow_free_all_rule_data_list(vif->vif_fat_flow_rule_data_list);
    }
    if (vif->fat_flow_cfg) {
        vr_free(vif->fat_flow_cfg, VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
    }

    if (vif->vif_in_mirror_md) {
        vif->vif_in_mirror_md_len = 0;
        vif->vif_in_mirror_md_size = 0;
        vr_free(vif->vif_in_mirror_md, VR_INTERFACE_MIRROR_META_OBJECT);
        vif->vif_in_mirror_md = NULL;
    }

    if (vif->vif_out_mirror_md) {
        vif->vif_out_mirror_md_len = 0;
        vif->vif_out_mirror_md_size = 0;
        vr_free(vif->vif_out_mirror_md, VR_INTERFACE_MIRROR_META_OBJECT);
        vif->vif_out_mirror_md = NULL;
    }

    if (vif->vif_drop_stats) {
        vr_free(vif->vif_drop_stats, VR_DROP_STATS_OBJECT);
        vif->vif_drop_stats = NULL;
    }

    if (vif->vif_pcpu_drop_stats) {
        vr_btable_free(vif->vif_pcpu_drop_stats);
        vif->vif_pcpu_drop_stats = NULL;
    }

    vr_free(vif, VR_INTERFACE_OBJECT);

    return;
}

void
vrouter_put_interface(struct vr_interface *vif)
{
    if (!vr_sync_sub_and_fetch_32u(&vif->vif_users, 1))
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
        (void)vr_sync_add_and_fetch_32u(&vif->vif_users, 1);

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

    /* Interface can be deleted using vif name of OS interface name or
     * index
     */
    if (req->vifr_name) {
#ifdef _WIN32
        vif = vif_find(router, req->vifr_name);
#else
        if (2 == sscanf(req->vifr_name, "vif%u/%u", &req->vifr_rid,
                    &req->vifr_idx))
            vif = __vrouter_get_interface(vrouter_get(req->vifr_rid),
                    req->vifr_idx);
        else
            vif = vif_find(router, req->vifr_name);
#endif
    } else {
        vif = __vrouter_get_interface(router, req->vifr_idx);
    }

    if (!vif && (ret = -ENODEV))
        goto del_fail;

    vr_offload_interface_del(vif);

    vif_delete(vif);

del_fail:
    if (need_response)
        vr_send_response(ret);

    return ret;
}

static void
vif_free_bridge_table_lock(struct vrouter *router, void *data)
{
   struct vr_defer_data *vdd = (struct vr_defer_data *)data;

    if (!vdd)
        return;

    vr_free(vdd->vdd_data, VR_INTERFACE_BRIDGE_LOCK_OBJECT);

    return;
}

static int
vif_set_flags(struct vr_interface *vif, vr_interface_req *req)
{
    void *mem;
    struct vr_defer_data *vdd;

    if ((req->vifr_flags & VIF_FLAG_MAC_LEARN) || (vif_is_fabric(vif))) {
        if (!vif->vif_bridge_table_lock) {
            vif->vif_bridge_table_lock =
                vr_zalloc(vr_num_cpus * sizeof(uint8_t),
                        VR_INTERFACE_BRIDGE_LOCK_OBJECT);
            if (!vif->vif_bridge_table_lock) {
                return -ENOMEM;
            }
        }
    } else if (vif->vif_flags & VIF_FLAG_MAC_LEARN) {
        if (vif->vif_bridge_table_lock) {
            vdd = vr_get_defer_data(sizeof(*vdd));
            if (vdd) {
                mem = vif->vif_bridge_table_lock;
                vif->vif_bridge_table_lock = NULL;
                vdd->vdd_data = mem;
                vr_defer(vif->vif_router, vif_free_bridge_table_lock,
                        (void *)vdd);
            }
        }
    }

    vif->vif_flags = (vif->vif_flags & VIF_VR_CAP_MASK) |
                     (req->vifr_flags & ~VIF_VR_CAP_MASK);

    /*
     * If both L3 and L2 are disabled, enabled L3 with fallback bridging
     * by default to avoid total blackout of packets
     */
    if (!(vif->vif_flags & (VIF_FLAG_L3_ENABLED | VIF_FLAG_L2_ENABLED))) {
        vif->vif_flags |= (VIF_FLAG_L3_ENABLED | VIF_FLAG_L2_ENABLED);
    }

    return 0;
}

static int
vr_interface_mirror_md_set(struct vr_interface *vif, vr_interface_req *req)
{
    /*
     * If metadata is removed from request, make our metadata len to
     * zero, so that it does not get used in packet processeing. The
     * memory will get freed only at the time of deletion of interface
     * _size hold the allocated memory size, so that we would not over
     * shoot while copying.
     * It is also assumed that the interface metadata does not change
     * once allocated
     */
    if (!req->vifr_in_mirror_md_size)
        vif->vif_in_mirror_md_len = 0;

    if (!req->vifr_out_mirror_md_size)
        vif->vif_out_mirror_md_len = 0;

    if (req->vifr_in_mirror_md_size) {
        if (!vif->vif_in_mirror_md) {
            /*
             * If there is no mirror md already, ensure we dont create
             * more than the max size
             */
            if (req->vifr_in_mirror_md_size > VIF_MAX_MIRROR_MD_SIZE)
                req->vifr_in_mirror_md_size = VIF_MAX_MIRROR_MD_SIZE;

            vif->vif_in_mirror_md =
                vr_zalloc(req->vifr_in_mirror_md_size,
                                VR_INTERFACE_MIRROR_META_OBJECT);
            if (!vif->vif_in_mirror_md)
                return -ENOMEM;

            vif->vif_in_mirror_md_size = req->vifr_in_mirror_md_size;
        } else {
            /*
             * If mirror md already exists, we dont want the new len to
             * be more than that
             */
            if (req->vifr_in_mirror_md_size > vif->vif_in_mirror_md_size) {
                req->vifr_in_mirror_md_size = vif->vif_in_mirror_md_size;
            }
        }

        memcpy(vif->vif_in_mirror_md,
                    req->vifr_in_mirror_md, req->vifr_in_mirror_md_size);
        vif->vif_in_mirror_md_len = req->vifr_in_mirror_md_size;
    }

    if (req->vifr_out_mirror_md_size) {
        if (!vif->vif_out_mirror_md) {
            if (req->vifr_out_mirror_md_size > VIF_MAX_MIRROR_MD_SIZE)
                req->vifr_out_mirror_md_size = VIF_MAX_MIRROR_MD_SIZE;

            vif->vif_out_mirror_md =
                vr_zalloc(req->vifr_out_mirror_md_size,
                                VR_INTERFACE_MIRROR_META_OBJECT);
            if (!vif->vif_out_mirror_md)
                return -ENOMEM;

            vif->vif_out_mirror_md_size = req->vifr_out_mirror_md_size;
        } else {
            if (req->vifr_out_mirror_md_size > vif->vif_out_mirror_md_size) {
                req->vifr_out_mirror_md_size = vif->vif_out_mirror_md_size;
            }
        }

        memcpy(vif->vif_out_mirror_md,
                    req->vifr_out_mirror_md, req->vifr_out_mirror_md_size);
        vif->vif_out_mirror_md_len = req->vifr_out_mirror_md_size;
    }

    return 0;
}

static int
vr_interface_change(struct vr_interface *vif, vr_interface_req *req)
{
    int ret = 0;
    uint64_t *ip6;

    if (req->vifr_flags & VIF_FLAG_SERVICE_IF &&
            !(vif->vif_flags & VIF_FLAG_SERVICE_IF)) {
        ret = vr_interface_service_enable(vif);
        if (ret)
            return ret;
    } else if ((vif->vif_flags & VIF_FLAG_SERVICE_IF) &&
            !(req->vifr_flags & VIF_FLAG_SERVICE_IF)) {
        vr_interface_service_disable(vif);
    }

    ret = vif_set_flags(vif, req);
    if (ret)
        return ret;

    vif->vif_mirror_id = req->vifr_mir_id;
    if (!(vif->vif_flags & VIF_FLAG_MIRROR_RX) &&
        !(vif->vif_flags & VIF_FLAG_MIRROR_TX)) {
        vif->vif_mirror_id = VR_MAX_MIRROR_INDICES;
    }
    if (req->vifr_vrf >= 0)
        vif->vif_vrf = req->vifr_vrf;

    if (req->vifr_mcast_vrf >= 0)
        vif->vif_mcast_vrf = req->vifr_mcast_vrf;

    if (req->vifr_mtu)
        vif->vif_mtu = req->vifr_mtu;

    vif->vif_nh_id = (unsigned short)req->vifr_nh_id;
    vif->vif_qos_map_index = req->vifr_qos_map_index;
    vif->vif_isid = req->vifr_isid;
    if (req->vifr_pbb_mac_size)
        VR_MAC_COPY(vif->vif_pbb_mac, req->vifr_pbb_mac);

    vif->vif_ip = req->vifr_ip;
    ip6 = (uint64_t *)(vif->vif_ip6);
    *ip6 = req->vifr_ip6_u;
    *(ip6 + 1) = req->vifr_ip6_l;

    ret = vr_interface_mirror_md_set(vif, req);
    if (ret)
        return ret;

    if ((ret = vif_fat_flow_add(vif, req)))
        return ret;

    return vlan_sub_interface_manage(vif->vif_parent, vif,
                req->vifr_src_mac_size / VR_ETHER_ALEN, req->vifr_src_mac);

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
    uint64_t *ip6;
    struct vr_interface *vif = NULL;
    struct vrouter *router = vrouter_get(req->vifr_rid);

    if (!router || ((unsigned int)req->vifr_idx >= router->vr_max_interfaces)) {
        ret = -EINVAL;
        goto error;
    }

    if (req->vifr_type >= VIF_TYPE_MAX && (ret = -EINVAL))
        goto error;

    if (!vif_transport_valid(req))
        goto error;

    vif = __vrouter_get_interface(router, req->vifr_idx);
    if (vif) {
        ret = vr_interface_change(vif, req);
        /* notify hw offload of change, if enabled */
        if (!ret)
            ret = vr_offload_interface_add(vif);

        goto generate_resp;
    }

    vif = vr_zalloc(sizeof(*vif), VR_INTERFACE_OBJECT);
    if (!vif) {
        ret = -ENOMEM;
        goto error;
    }

    vif->vif_stats = vr_zalloc(vr_num_cpus *
            sizeof(struct vr_interface_stats), VR_INTERFACE_STATS_OBJECT);
    if (!vif->vif_stats) {
        ret = -ENOMEM;
        goto error;
    }

    for (i = 0; i < vr_num_cpus; i++) {
        vif->vif_stats[i].vis_queue_ierrors_to_lcore = vr_zalloc(vr_num_cpus *
                sizeof(uint64_t), VR_INTERFACE_TO_LCORE_ERRORS_OBJECT);
        if (!vif->vif_stats[i].vis_queue_ierrors_to_lcore) {
            ret = -ENOMEM;
            goto error;
        }
    }

    /*
     * The dropstats need to be available per interface. Incrementing
     * atomically the same statistics across many CPUs might attract
     * significatnt delay. Alternative approach of allocating memory for
     * every dropstat for every CPU will be large chunk of memory
     * considering large number of interfaces, number of dropstats,
     * number of CPUs and size of every counter.  To normalise both the
     * requirements, one set of dropstats of 64 bit size and another set
     * of dropstats of one byte per every cpu is allocated. The later is
     * incremented without any contention as it is per cpu. When the
     * one byte counter reaches its max value, it is added to the
     * 64 bit counter atomically. This results in decreasing the delay
     * as well decresing the memory requirement
     */
    vif->vif_drop_stats = vr_zalloc((VP_DROP_MAX * sizeof(uint64_t)),
                                               VR_DROP_STATS_OBJECT);
    if (!vif->vif_drop_stats) {
        ret = -ENOMEM;
        goto error;
    }

    /*
     * We continue to create the interface even if per cpu stats
     * allocation fails. In this case, we directly increment on
     * vif_drop_stats atomically
     */
    vif->vif_pcpu_drop_stats = vr_btable_alloc((vr_num_cpus * VP_DROP_MAX), 1);

    vif->vif_type = req->vifr_type;

    ret = vif_set_flags(vif, req);
    if (ret)
        goto error;

    vif->vif_vrf = req->vifr_vrf;
    vif->vif_mcast_vrf = req->vifr_mcast_vrf;
    vif->vif_vlan_id = VLAN_ID_INVALID;
    vif->vif_mtu = req->vifr_mtu;
    vif->vif_idx = req->vifr_idx;
    vif->vif_transport = req->vifr_transport;
    vif->vif_os_idx = req->vifr_os_idx;
    vif->vif_vhostuser_mode = req->vifr_vhostuser_mode;
    if (req->vifr_os_idx == -1)
        vif->vif_os_idx = 0;
    vif->vif_rid = req->vifr_rid;
    vif->vif_nh_id = (unsigned short)req->vifr_nh_id;
    vif->vif_qos_map_index = req->vifr_qos_map_index;
    vif->vif_isid = req->vifr_isid;
    if (req->vifr_pbb_mac_size)
        VR_MAC_COPY(vif->vif_pbb_mac, req->vifr_pbb_mac);

    vif->vif_mirror_id = req->vifr_mir_id;
    if (!(vif->vif_flags & VIF_FLAG_MIRROR_RX) &&
        !(vif->vif_flags & VIF_FLAG_MIRROR_TX)) {
        vif->vif_mirror_id = VR_MAX_MIRROR_INDICES;
    }
    ret = vr_interface_mirror_md_set(vif, req);
    if (ret)
        goto error;

    if (req->vifr_mac) {
        if (req->vifr_mac_size != sizeof(vif->vif_mac)) {
            ret = -EINVAL;
            goto error;
        }

        memcpy(vif->vif_mac, req->vifr_mac, sizeof(vif->vif_mac));
        memcpy(vif->vif_rewrite, req->vifr_mac, sizeof(vif->vif_mac));
    }

    vif->vif_ip = req->vifr_ip;
    ip6 = (uint64_t *)(vif->vif_ip6);
    *ip6 = req->vifr_ip6_u;
    *(ip6 + 1) = req->vifr_ip6_l;

    if (req->vifr_name) {
        strncpy(vif->vif_name, req->vifr_name, sizeof(vif->vif_name) - 1);
    }

    if (req->vifr_hw_queues_size) {
        vif->vif_hw_queues = vr_malloc(sizeof(uint16_t) *
                req->vifr_hw_queues_size, VR_INTERFACE_QUEUE_OBJECT);
        if (!vif->vif_hw_queues) {
            ret = -ENOMEM;
            goto error;
        }

        vif->vif_num_hw_queues = req->vifr_hw_queues_size;
        memcpy(vif->vif_hw_queues, req->vifr_hw_queues,
                req->vifr_hw_queues_size * sizeof(uint16_t));
    }

    ret = vif_fat_flow_add(vif, req);
    if (ret)
        goto error;

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
        goto error;

    ret = vif_drv_add(vif, req);
    if (ret) {
        vif_delete(vif);
        vif = NULL;
    }

    if (!ret) {
        vrouter_setup_vif(vif);
        vr_register_nic(vif, req);
    }

error:
    if (ret && vif)
        vif_free(vif);

    /* notify hw offload of change, if enabled */
    if (!ret) {
        ret = vr_offload_interface_add(vif);
        if (ret) {
            vif_delete(vif);
            vif = NULL;
        }
    }
generate_resp:
    if (need_response)
        vr_send_response(ret);

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

static uint64_t
vr_interface_get_drops(struct vr_interface *vif)
{
    uint8_t *count, cpu;
    int stats_index;
    uint64_t total_drops;

    total_drops = 0;
    for (stats_index = 0; stats_index < VP_DROP_MAX; stats_index++) {
        total_drops += vif->vif_drop_stats[stats_index];
        if (vif->vif_pcpu_drop_stats) {
            for (cpu = 0; cpu < vr_num_cpus; cpu++) {
                count = vr_btable_get(vif->vif_pcpu_drop_stats,
                            ((cpu * VP_DROP_MAX) + stats_index));
                total_drops += *count;
            }
        }
    }

    return total_drops;
}

static void
__vr_interface_make_req(vr_interface_req *req, struct vr_interface *intf,
        unsigned int core)
{
    unsigned int cpu, i;
    uint64_t *ip6;

    struct vr_interface_settings settings;

    req->vifr_core = core;
    req->vifr_type = intf->vif_type;
    req->vifr_flags = intf->vif_flags;
    req->vifr_vrf = intf->vif_vrf;
    req->vifr_mcast_vrf = intf->vif_mcast_vrf;
    req->vifr_idx = intf->vif_idx;
    req->vifr_rid = intf->vif_rid;
    req->vifr_transport = intf->vif_transport;
    req->vifr_os_idx = intf->vif_os_idx;
    req->vifr_mtu = intf->vif_mtu;
    req->vifr_nh_id = intf->vif_nh_id;
    if (req->vifr_mac_size && req->vifr_mac)
        memcpy(req->vifr_mac, intf->vif_mac,
                MINIMUM(req->vifr_mac_size, sizeof(intf->vif_mac)));
    req->vifr_ip = intf->vif_ip;
    ip6 = (uint64_t *)(intf->vif_ip6);
    req->vifr_ip6_u = *ip6;
    req->vifr_ip6_l = *(ip6 + 1);
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
        req->vifr_src_mac_size = 0;
        req->vifr_bridge_idx_size = 0;
        for (i = 0; i < VIF_SRC_MACS; i++) {
            if (IS_MAC_ZERO((intf->vif_src_mac + (i * VR_ETHER_ALEN))))
                continue;
            VR_MAC_COPY((req->vifr_src_mac + (i * VR_ETHER_ALEN)),
                    (intf->vif_src_mac + (i * VR_ETHER_ALEN)));
            req->vifr_src_mac_size += VR_ETHER_ALEN;
            req->vifr_bridge_idx[i] =
                vif_bridge_get_index(intf->vif_parent, intf,
                        intf->vif_src_mac + (i * VR_ETHER_ALEN));
            req->vifr_bridge_idx_size += sizeof(uint32_t);
        }
    } else {
        /*
         * this is a small hack. we had already allocated the memory in
         * req_get and it is common for all interfaces. how do we tell
         * that the field is not valid - by setting the size to 0.
         */
        req->vifr_src_mac_size = 0;
        req->vifr_bridge_idx_size = 0;
    }

    req->vifr_in_mirror_md_size = 0;
    if (intf->vif_in_mirror_md_len) {
        memcpy(req->vifr_in_mirror_md, intf->vif_in_mirror_md,
                intf->vif_in_mirror_md_len);
        req->vifr_in_mirror_md_size = intf->vif_in_mirror_md_len;
    }

    req->vifr_out_mirror_md_size = 0;
    if (intf->vif_out_mirror_md_len) {
        memcpy(req->vifr_out_mirror_md, intf->vif_out_mirror_md,
                intf->vif_out_mirror_md_len);
        req->vifr_out_mirror_md_size = intf->vif_out_mirror_md_len;
    }

    req->vifr_isid = intf->vif_isid;
    if (!IS_MAC_ZERO(intf->vif_pbb_mac) && req->vifr_pbb_mac) {
        req->vifr_pbb_mac_size = VR_ETHER_ALEN;
        VR_MAC_COPY(req->vifr_pbb_mac, intf->vif_pbb_mac);
    } else {
        req->vifr_pbb_mac_size = 0;
    }
    req->vifr_vhostuser_mode = intf->vif_vhostuser_mode;


    /* vif counters */
    req->vifr_ibytes = 0;
    req->vifr_ipackets = 0;
    req->vifr_ierrors = 0;
    req->vifr_obytes = 0;
    req->vifr_opackets = 0;
    req->vifr_oerrors = 0;
    /* queue counters */
    req->vifr_queue_ipackets = 0;
    for (i = 0; i < vr_num_cpus; i++)
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

    for (i = 0; i < intf->fat_flow_cfg_size; i++) {
        req->vifr_fat_flow_protocol_port[i] =
                      (intf->fat_flow_cfg[i].port) |
                      (((uint32_t)intf->fat_flow_cfg[i].protocol) << 16) |
                      (((uint32_t)intf->fat_flow_cfg[i].port_aggr_info) << 24);
        req->vifr_fat_flow_src_prefix_h[i] = intf->fat_flow_cfg[i].src_prefix_h;
        req->vifr_fat_flow_src_prefix_l[i] = intf->fat_flow_cfg[i].src_prefix_l;
        req->vifr_fat_flow_src_prefix_mask[i] =
                       intf->fat_flow_cfg[i].src_prefix_mask;
        req->vifr_fat_flow_src_aggregate_plen[i] =
                       intf->fat_flow_cfg[i].src_aggregate_plen;
        req->vifr_fat_flow_dst_prefix_h[i] =
                       intf->fat_flow_cfg[i].dst_prefix_h;
        req->vifr_fat_flow_dst_prefix_l[i] =
                       intf->fat_flow_cfg[i].dst_prefix_l;
        req->vifr_fat_flow_dst_prefix_mask[i] =
                       intf->fat_flow_cfg[i].dst_prefix_mask;
        req->vifr_fat_flow_dst_aggregate_plen[i] =
                       intf->fat_flow_cfg[i].dst_aggregate_plen;
    }

    /* Fill the ipv4 & ipv6 exclude lists; NOTE: The prefix lengths are not filled */
    for (i = 0; i < req->vifr_fat_flow_exclude_ip_list_size; i++) {
        req->vifr_fat_flow_exclude_ip_list[i] = (uint64_t) intf->vif_fat_flow_ipv4_exclude_list[i];
    }

    for (i = 0; i < req->vifr_fat_flow_exclude_ip6_u_list_size; i++) {
        req->vifr_fat_flow_exclude_ip6_u_list[i] = intf->vif_fat_flow_ipv6_high_exclude_list[i];
        req->vifr_fat_flow_exclude_ip6_l_list[i] = intf->vif_fat_flow_ipv6_low_exclude_list[i];
    }

    req->vifr_qos_map_index = intf->vif_qos_map_index;
    req->vifr_dpackets = vr_interface_get_drops(intf);
    return;
}

static int
vr_interface_make_req(vr_interface_req *req, struct vr_interface *vif,
        unsigned int core)
{
    unsigned int fat_flow_config_size;

    fat_flow_config_size = vif->fat_flow_cfg_size;

    if (fat_flow_config_size) {
        req->vifr_fat_flow_protocol_port =
            vr_zalloc(fat_flow_config_size * sizeof(uint32_t),
                    VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!req->vifr_fat_flow_protocol_port) {
            return -ENOMEM;
        }
        req->vifr_fat_flow_protocol_port_size = fat_flow_config_size;

        req->vifr_fat_flow_src_prefix_h =
                           vr_zalloc(fat_flow_config_size * sizeof(uint64_t),
                                     VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!req->vifr_fat_flow_src_prefix_h) {
             return -ENOMEM;
        }
        req->vifr_fat_flow_src_prefix_h_size = fat_flow_config_size;

        req->vifr_fat_flow_src_prefix_l =
                           vr_zalloc(fat_flow_config_size * sizeof(uint64_t),
                                     VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!req->vifr_fat_flow_src_prefix_l) {
             return -ENOMEM;
        }
        req->vifr_fat_flow_src_prefix_l_size = fat_flow_config_size;

        req->vifr_fat_flow_src_prefix_mask =
                           vr_zalloc(fat_flow_config_size * sizeof(uint8_t),
                                     VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!req->vifr_fat_flow_src_prefix_mask) {
             return -ENOMEM;
        }
        req->vifr_fat_flow_src_prefix_mask_size = fat_flow_config_size;

        req->vifr_fat_flow_src_aggregate_plen =
                           vr_zalloc(fat_flow_config_size * sizeof(uint8_t),
                                     VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!req->vifr_fat_flow_src_aggregate_plen) {
             return -ENOMEM;
        }
        req->vifr_fat_flow_src_aggregate_plen_size = fat_flow_config_size;

        req->vifr_fat_flow_dst_prefix_h =
                           vr_zalloc(fat_flow_config_size * sizeof(uint64_t),
                                     VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!req->vifr_fat_flow_dst_prefix_h) {
            return -ENOMEM;
        }
        req->vifr_fat_flow_dst_prefix_h_size = fat_flow_config_size;

        req->vifr_fat_flow_dst_prefix_l =
                           vr_zalloc(fat_flow_config_size * sizeof(uint64_t),
                                     VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!req->vifr_fat_flow_dst_prefix_l) {
            return -ENOMEM;
        }
        req->vifr_fat_flow_dst_prefix_l_size = fat_flow_config_size;

        req->vifr_fat_flow_dst_prefix_mask =
                           vr_zalloc(fat_flow_config_size * sizeof(uint8_t),
                                     VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!req->vifr_fat_flow_dst_prefix_mask) {
             return -ENOMEM;
        }
        req->vifr_fat_flow_dst_prefix_mask_size = fat_flow_config_size;

        req->vifr_fat_flow_dst_aggregate_plen =
                           vr_zalloc(fat_flow_config_size * sizeof(uint8_t),
                                     VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!req->vifr_fat_flow_dst_aggregate_plen) {
             return -ENOMEM;
        }
        req->vifr_fat_flow_dst_aggregate_plen_size = fat_flow_config_size;
    }

    if (vif->vif_fat_flow_ipv4_exclude_list_size) {
        req->vifr_fat_flow_exclude_ip_list = vr_zalloc(vif->vif_fat_flow_ipv4_exclude_list_size * sizeof(uint64_t),
                                                       VR_INTERFACE_FAT_FLOW_IPV4_EXCLUDE_LIST_OBJECT);
        if (!req->vifr_fat_flow_exclude_ip_list) {
            return -ENOMEM;
        }
        req->vifr_fat_flow_exclude_ip_list_size = vif->vif_fat_flow_ipv4_exclude_list_size;
    }

    if (vif->vif_fat_flow_ipv6_exclude_list_size) {
        req->vifr_fat_flow_exclude_ip6_u_list = vr_zalloc(vif->vif_fat_flow_ipv6_exclude_list_size * sizeof(uint64_t),
                                                          VR_INTERFACE_FAT_FLOW_IPV6_EXCLUDE_LIST_OBJECT);
        if (!req->vifr_fat_flow_exclude_ip6_u_list) {
            return -ENOMEM;
        }
        req->vifr_fat_flow_exclude_ip6_u_list_size = vif->vif_fat_flow_ipv6_exclude_list_size;
        req->vifr_fat_flow_exclude_ip6_l_list = vr_zalloc(vif->vif_fat_flow_ipv6_exclude_list_size * sizeof(uint64_t),
                                                          VR_INTERFACE_FAT_FLOW_IPV6_EXCLUDE_LIST_OBJECT);
        if (!req->vifr_fat_flow_exclude_ip6_l_list) {
            return -ENOMEM;
        }
        req->vifr_fat_flow_exclude_ip6_l_list_size = vif->vif_fat_flow_ipv6_exclude_list_size;
    }

    __vr_interface_make_req(req, vif, core);

    return 0;
}

unsigned int
vr_interface_req_get_size(void *req_p)
{
    unsigned int size;
    vr_interface_req *req = (vr_interface_req *)req_p;


    /*
     * Standard interface request size + both ingress and egress
     * metadata size
     */
    size = ((4 * sizeof(*req)) + (2 * VIF_MAX_MIRROR_MD_SIZE));
    if (req->vifr_queue_ierrors_to_lcore)
        size += (vr_num_cpus * sizeof(int64_t));

    return size;
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

    req->vifr_src_mac = vr_zalloc(VR_ETHER_ALEN * VIF_SRC_MACS, VR_INTERFACE_REQ_MAC_OBJECT);
    if (req->vifr_src_mac)
        req->vifr_src_mac_size = 0;

    req->vifr_bridge_idx = vr_zalloc(sizeof(uint32_t)* VIF_SRC_MACS,
            VR_INTERFACE_REQ_BRIDGE_ID_OBJECT);
    if (req->vifr_bridge_idx)
        req->vifr_bridge_idx_size = 0;

    req->vifr_name = vr_zalloc(VR_INTERFACE_NAME_LEN,
            VR_INTERFACE_REQ_NAME_OBJECT);

    req->vifr_queue_ierrors_to_lcore = vr_zalloc(vr_num_cpus * sizeof(uint64_t),
            VR_INTERFACE_REQ_TO_LCORE_ERRORS_OBJECT);
    if (req->vifr_queue_ierrors_to_lcore)
        req->vifr_queue_ierrors_to_lcore_size = 0;

    req->vifr_in_mirror_md_size = 0;
    req->vifr_in_mirror_md = vr_zalloc(VIF_MAX_MIRROR_MD_SIZE,
                                VR_INTERFACE_REQ_MIRROR_META_OBJECT);

    req->vifr_out_mirror_md_size = 0;
    req->vifr_out_mirror_md = vr_zalloc(VIF_MAX_MIRROR_MD_SIZE,
                                VR_INTERFACE_REQ_MIRROR_META_OBJECT);
    req->vifr_pbb_mac = vr_zalloc(VR_ETHER_ALEN,
            VR_INTERFACE_REQ_PBB_MAC_OBJECT);

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

    if (req->vifr_fat_flow_src_prefix_h) {
        vr_free(req->vifr_fat_flow_src_prefix_h,
                VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        req->vifr_fat_flow_src_prefix_h = NULL;
        req->vifr_fat_flow_src_prefix_h_size = 0;
    }

    if (req->vifr_fat_flow_src_prefix_l) {
        vr_free(req->vifr_fat_flow_src_prefix_l,
                VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        req->vifr_fat_flow_src_prefix_l = NULL;
        req->vifr_fat_flow_src_prefix_l_size = 0;
    }

    if (req->vifr_fat_flow_src_prefix_mask) {
        vr_free(req->vifr_fat_flow_src_prefix_mask,
                VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        req->vifr_fat_flow_src_prefix_mask = NULL;
        req->vifr_fat_flow_src_prefix_mask_size = 0;
    }

    if (req->vifr_fat_flow_src_aggregate_plen) {
        vr_free(req->vifr_fat_flow_src_aggregate_plen,
                VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        req->vifr_fat_flow_src_aggregate_plen = NULL;
        req->vifr_fat_flow_src_aggregate_plen_size = 0;
    }

    if (req->vifr_fat_flow_dst_prefix_h) {
        vr_free(req->vifr_fat_flow_dst_prefix_h,
                VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        req->vifr_fat_flow_dst_prefix_h = NULL;
        req->vifr_fat_flow_dst_prefix_h_size = 0;
    }

    if (req->vifr_fat_flow_dst_prefix_l) {
        vr_free(req->vifr_fat_flow_dst_prefix_l,
                VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        req->vifr_fat_flow_dst_prefix_l = NULL;
        req->vifr_fat_flow_dst_prefix_l_size = 0;
    }

    if (req->vifr_fat_flow_dst_prefix_mask) {
        vr_free(req->vifr_fat_flow_dst_prefix_mask,
                VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        req->vifr_fat_flow_dst_prefix_mask = NULL;
        req->vifr_fat_flow_dst_prefix_mask_size = 0;
    }

    if (req->vifr_fat_flow_dst_aggregate_plen) {
        vr_free(req->vifr_fat_flow_dst_aggregate_plen,
                VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        req->vifr_fat_flow_dst_aggregate_plen = NULL;
        req->vifr_fat_flow_dst_aggregate_plen_size = 0;
    }

    if (req->vifr_fat_flow_exclude_ip_list) {
        vr_free(req->vifr_fat_flow_exclude_ip_list, VR_INTERFACE_FAT_FLOW_IPV4_EXCLUDE_LIST_OBJECT);
        req->vifr_fat_flow_exclude_ip_list = NULL;
        req->vifr_fat_flow_exclude_ip_list_size = 0;
    }
    if (req->vifr_fat_flow_exclude_ip6_u_list) {
        vr_free(req->vifr_fat_flow_exclude_ip6_u_list, VR_INTERFACE_FAT_FLOW_IPV6_EXCLUDE_LIST_OBJECT);
        req->vifr_fat_flow_exclude_ip6_u_list = NULL;
        req->vifr_fat_flow_exclude_ip6_u_list_size = 0;
    }
    if (req->vifr_fat_flow_exclude_ip6_l_list) {
        vr_free(req->vifr_fat_flow_exclude_ip6_l_list, VR_INTERFACE_FAT_FLOW_IPV6_EXCLUDE_LIST_OBJECT);
        req->vifr_fat_flow_exclude_ip6_l_list = NULL;
        req->vifr_fat_flow_exclude_ip6_l_list_size = 0;
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

    if (req->vifr_bridge_idx) {
        vr_free(req->vifr_bridge_idx, VR_INTERFACE_REQ_BRIDGE_ID_OBJECT);
        req->vifr_bridge_idx_size = 0;
    }

    if (req->vifr_name)
        vr_free(req->vifr_name, VR_INTERFACE_REQ_NAME_OBJECT);

    if (req->vifr_queue_ierrors_to_lcore) {
        vr_free(req->vifr_queue_ierrors_to_lcore,
            VR_INTERFACE_REQ_TO_LCORE_ERRORS_OBJECT);
        req->vifr_queue_ierrors_to_lcore_size = 0;
    }

    if (req->vifr_in_mirror_md) {
        vr_free(req->vifr_in_mirror_md,
                VR_INTERFACE_REQ_MIRROR_META_OBJECT);
        req->vifr_in_mirror_md_size = 0;
        req->vifr_in_mirror_md = NULL;
    }

    if (req->vifr_out_mirror_md) {
        vr_free(req->vifr_out_mirror_md,
                VR_INTERFACE_REQ_MIRROR_META_OBJECT);
        req->vifr_out_mirror_md_size = 0;
        req->vifr_out_mirror_md = NULL;
    }

    if (req->vifr_pbb_mac) {
        vr_free(req->vifr_pbb_mac,
                VR_INTERFACE_REQ_PBB_MAC_OBJECT);
        req->vifr_pbb_mac = NULL;
        req->vifr_pbb_mac_size = 0;
    }

    vr_interface_req_free_fat_flow_config(req);

    vr_free(req, VR_INTERFACE_REQ_OBJECT);

    return;
}

static int
vr_interface_get(vr_interface_req *req)
{
    int ret = 0, obj_cnt = 0;
    struct vr_message_multi mm;
    vr_response resp;
    struct vrouter *router;
    vr_interface_req *vif_resp = NULL;
    vr_drop_stats_req *drop_resp = NULL;
    struct vr_interface *vif = NULL;

    resp.h_op = SANDESH_OP_RESPONSE;
    mm.vr_mm_object_type[obj_cnt] = VR_RESPONSE_OBJECT_ID;
    mm.vr_mm_object[obj_cnt] = &resp;
    obj_cnt++;

    router = vrouter_get(req->vifr_rid);
    if (!router) {
        ret = -ENODEV;
        goto generate_response;
    }

    if ((unsigned int)req->vifr_idx >= router->vr_max_interfaces)
        vif = __vrouter_get_interface_os(router, req->vifr_os_idx);
    else
        vif = __vrouter_get_interface(router, req->vifr_idx);

    if (!vif) {
        ret = -ENOENT;
        goto generate_response;
    }

    vif_resp = vr_interface_req_get();
    if (!vif_resp) {
        ret = -ENOMEM;
        goto generate_response;
    }

    ret = vr_interface_make_req(vif_resp, vif, (unsigned)(req->vifr_core - 1));
    if (ret < 0)
        goto generate_response;

    mm.vr_mm_object_type[obj_cnt] = VR_INTERFACE_OBJECT_ID;
    mm.vr_mm_object[obj_cnt] = vif_resp;
    obj_cnt++;

    if (req->vifr_flags & VIF_FLAG_GET_DROP_STATS) {
        drop_resp = vr_zalloc(sizeof(*drop_resp), VR_DROP_STATS_REQ_OBJECT);
        if (!drop_resp) {
            ret = -ENOMEM;
            goto generate_response;
        }

        if (!vif->vif_pcpu_drop_stats)
            drop_resp->vds_pcpu_stats_failure_status = 1;

        vr_drop_stats_get_vif_stats(drop_resp, vif);

        mm.vr_mm_object_type[obj_cnt] = VR_DROP_STATS_OBJECT_ID;
        mm.vr_mm_object[obj_cnt] = drop_resp;
        obj_cnt++;

        /* zero vifr_core means to sum up all the per-core stats */
        vr_interface_make_req(vif_resp, vif, (unsigned)(req->vifr_core - 1));
        /* adds in stats for pkts which were offloaded on NIC and does debug
           comparison to check if matching entry is programmed on NIC */
        ret = vr_offload_interface_get(vif_resp);
    }

generate_response:
    mm.vr_mm_object_count = obj_cnt;
    resp.resp_code = ret;
    vr_message_multi_response(&mm);

    if (vif_resp)
        vr_interface_req_destroy(vif_resp);

    if (drop_resp)
        vr_free(drop_resp, VR_DROP_STATS_REQ_OBJECT);

    return 0;
}

static int
vr_interface_dump(vr_interface_req *r)
{
    int ret = 0;
    unsigned int i;
    vr_interface_req *resp = NULL;
    struct vr_interface *vif;
    struct vrouter *router = vrouter_get(r->vifr_rid);
    struct vr_message_dumper *dumper = NULL;
    vr_drop_stats_req *drop_resp = NULL;

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

    drop_resp = vr_zalloc(sizeof(*drop_resp), VR_DROP_STATS_REQ_OBJECT);
    if (!drop_resp) {
        ret = -ENOMEM;
        goto generate_response;
    }

    for (i = (unsigned int)(r->vifr_marker + 1);
            i < router->vr_max_interfaces; i++) {
        vif = router->vr_interfaces[i];
        if (vif) {
            /* zero vifr_core means to sum up all the per-core stats */
            vr_interface_make_req(resp, vif, (unsigned)(r->vifr_core - 1));

            /* let hw offload fill in relevant fields */
            vr_offload_interface_get(resp);

            ret = vr_message_dump_object(dumper, VR_INTERFACE_OBJECT_ID, resp);
            if (ret <= 0)
                break;

            if (r->vifr_flags & VIF_FLAG_GET_DROP_STATS) {
                if (!vif->vif_pcpu_drop_stats)
                    drop_resp->vds_pcpu_stats_failure_status = 1;

                vr_drop_stats_get_vif_stats(drop_resp, vif);

                ret = vr_message_dump_object(dumper, VR_DROP_STATS_OBJECT_ID, drop_resp);
                /*
                 * If we succed in interface dump, but fail to add drop
                 * stats dump, the caller would retry the interface
                 * again
                 */
                if (ret <= 0)
                    break;
            }
            vr_interface_req_free_fat_flow_config(resp);
        }
    }

generate_response:
    vr_message_dump_exit(dumper, ret);
    if (resp)
        vr_interface_req_destroy(resp);

    if (drop_resp)
        vr_free(drop_resp, VR_DROP_STATS_REQ_OBJECT);

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

    case SANDESH_OP_DEL:
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
    int i;
    struct vr_defer_data *vdd_row, *vdd_column;

    mem_row = vif->vif_fat_flow_no_prefix_rules[proto_index];
    if (!mem_row)
        return;
    mem_column = mem_row[port_row];

    if (!memcmp(mem_column, vif_fat_flow_mem_zero,
                sizeof(vif_fat_flow_mem_zero))) {
        vdd_column = vr_get_defer_data(sizeof(*vdd_column));
        if (!vdd_column)
            return;

        vif->vif_fat_flow_no_prefix_rules[proto_index][port_row] = NULL;
        vdd_column->vdd_data = (void *)mem_column;
        vr_defer(vif->vif_router, __vif_fat_flow_free_defer_cb, vdd_column);

        for (i = 0; i < VIF_FAT_FLOW_NUM_BITMAPS; i++) {
            if (vif->vif_fat_flow_no_prefix_rules[proto_index][i])
                return;
        }

        vdd_row = vr_get_defer_data(sizeof(*vdd_row));
        if (!vdd_row)
            return;

        vif->vif_fat_flow_no_prefix_rules[proto_index] = NULL;
        vdd_row->vdd_data = (void *)mem_row;
        vr_defer(vif->vif_router, __vif_fat_flow_free_defer_cb, vdd_row);


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

    if (!vif->vif_fat_flow_no_prefix_rules[proto_index])
        return -EINVAL;

    port_row = port / VIF_FAT_FLOW_PORTS_PER_BITMAP;
    port_word = ((port % VIF_FAT_FLOW_PORTS_PER_BITMAP) * 2)  / (sizeof(uint8_t) * 8);
    port_bit =  ((port % VIF_FAT_FLOW_PORTS_PER_BITMAP) * 2) % (sizeof(uint8_t) * 8);

    if (!vif->vif_fat_flow_no_prefix_rules[proto_index][port_row])
        return -EINVAL;

    vif->vif_fat_flow_no_prefix_rules[proto_index][port_row][port_word] &=
        ~(VIF_FAT_FLOW_DATA_MASK << port_bit);

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


static int
__vif_fat_flow_add_no_prefix_rule(uint8_t **no_prefix_rules[VIF_FAT_FLOW_MAXPROTO_INDEX],
                                  uint8_t proto, uint16_t port, uint8_t port_data)
{
    uint8_t port_val = VIF_FAT_FLOW_PORT_SET;
    unsigned int proto_index, port_row, port_word, port_bit;

    bool alloced = false;

    proto_index = vif_fat_flow_get_proto_index(proto);

    if (!no_prefix_rules[proto_index]) {
        no_prefix_rules[proto_index] =
            vr_zalloc(VIF_FAT_FLOW_NUM_BITMAPS * sizeof(unsigned int *),
                    VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!no_prefix_rules[proto_index])
            return -ENOMEM;
        alloced = true;
    }

    port_row = port / VIF_FAT_FLOW_PORTS_PER_BITMAP;
    port_word = ((port % VIF_FAT_FLOW_PORTS_PER_BITMAP) * 2)  / (sizeof(uint8_t) * 8);
    port_bit =  ((port % VIF_FAT_FLOW_PORTS_PER_BITMAP) * 2) % (sizeof(uint8_t) * 8);

    if (!no_prefix_rules[proto_index][port_row]) {
        no_prefix_rules[proto_index][port_row] =
            vr_zalloc(VIF_FAT_FLOW_BITMAP_BYTES,
                    VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!no_prefix_rules[proto_index][port_row]) {
            if (alloced) {
                vr_free(no_prefix_rules[proto_index],
                        VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
                no_prefix_rules[proto_index] = NULL;
                return -ENOMEM;
            }
        }
    }

    if ((port_data == VIF_FAT_FLOW_PORT_SIP_IGNORE) ||
            (port_data == VIF_FAT_FLOW_PORT_DIP_IGNORE))
        port_val = port_data;

    /* First reset the old value */
    no_prefix_rules[proto_index][port_row][port_word] &=
        ~(VIF_FAT_FLOW_DATA_MASK << port_bit);

    /* Set the new val*/
    no_prefix_rules[proto_index][port_row][port_word] |=
        (port_val  << port_bit);

    return 0;
}

static int
__vif_is_fat_flow_src_prefix_rule(vr_fat_flow_cfg_t *cfg)
{
    switch (VIF_FAT_FLOW_CFG_PREFIX_AGGR_DATA(cfg->port_aggr_info)) {
        case VR_AGGREGATE_SRC_IPV4:
        case VR_AGGREGATE_SRC_IPV6:
             return 1;
        default:
             return 0;
    }
    return 0;
}

static int
__vif_is_fat_flow_dst_prefix_rule(vr_fat_flow_cfg_t *cfg)
{
    switch (VIF_FAT_FLOW_CFG_PREFIX_AGGR_DATA(cfg->port_aggr_info)) {
        case VR_AGGREGATE_DST_IPV4:
        case VR_AGGREGATE_DST_IPV6:
             return 1;
        default:
             return 0;
    }
    return 0;
}

static int
__vif_is_fat_flow_src_dst_prefix_rule(vr_fat_flow_cfg_t *cfg)
{
    switch (VIF_FAT_FLOW_CFG_PREFIX_AGGR_DATA(cfg->port_aggr_info)) {
        case VR_AGGREGATE_SRC_DST_IPV4:
        case VR_AGGREGATE_SRC_DST_IPV6:
             return 1;
        default:
             return 0;
    }
    return 0;
}

static int
__vif_is_fat_flow_v4_prefix_rule(vr_fat_flow_cfg_t *cfg)
{
    switch (VIF_FAT_FLOW_CFG_PREFIX_AGGR_DATA(cfg->port_aggr_info)) {
        case VR_AGGREGATE_SRC_IPV4:
        case VR_AGGREGATE_DST_IPV4:
        case VR_AGGREGATE_SRC_DST_IPV4:
             return 1;
        default:
             return 0;
    }
    return 0;
}


static int
vif_fat_flow_cfg_is_changed(struct vr_interface *vif, vr_interface_req *req)
{
    int i;
    vr_fat_flow_cfg_t new_cfg;

    if (vif->fat_flow_cfg_size != req->vifr_fat_flow_protocol_port_size) {
        return 1;
    }
    for (i = 0; i < vif->fat_flow_cfg_size; i++) {
         new_cfg.protocol =
                 VIF_FAT_FLOW_PROTOCOL(req->vifr_fat_flow_protocol_port[i]);
         new_cfg.port =
                 VIF_FAT_FLOW_PORT(req->vifr_fat_flow_protocol_port[i]);
         new_cfg.port_aggr_info =
                 VIF_FAT_FLOW_PORT_AGGR_INFO(req->vifr_fat_flow_protocol_port[i]);
         new_cfg.src_prefix_h = req->vifr_fat_flow_src_prefix_h[i];
         new_cfg.src_prefix_l = req->vifr_fat_flow_src_prefix_l[i];
         new_cfg.src_prefix_mask = req->vifr_fat_flow_src_prefix_mask[i];
         new_cfg.src_aggregate_plen = req->vifr_fat_flow_src_aggregate_plen[i];
         new_cfg.dst_prefix_h = req->vifr_fat_flow_dst_prefix_h[i];
         new_cfg.dst_prefix_l = req->vifr_fat_flow_dst_prefix_l[i];
         new_cfg.dst_prefix_mask = req->vifr_fat_flow_dst_prefix_mask[i];
         new_cfg.dst_aggregate_plen = req->vifr_fat_flow_dst_aggregate_plen[i];
         if (memcmp(&new_cfg, &vif->fat_flow_cfg[i], sizeof(vr_fat_flow_cfg_t)) != 0) {
             return 1;
         }
    }
    return 0;
}

static int
vif_fat_flow_cfg_build(vr_interface_req *req,
                       vr_fat_flow_cfg_t **new_fat_flow_cfg,
                       uint16_t *new_fat_flow_cfg_size,
                       uint16_t *new_fat_flow_num_rules)
{
    vr_fat_flow_cfg_t cfg;
    int i;

    /* If there is no new cfg, return */
    if (!req->vifr_fat_flow_protocol_port_size) {
        *new_fat_flow_cfg = NULL;
        *new_fat_flow_cfg_size = 0;
        return 0;
    }

    *new_fat_flow_cfg = vr_zalloc(sizeof(vr_fat_flow_cfg_t) *
                                  req->vifr_fat_flow_protocol_port_size,
                                  VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
    if (!(*new_fat_flow_cfg)) {
         return -ENOMEM;
    }
    *new_fat_flow_cfg_size = req->vifr_fat_flow_protocol_port_size;
    for (i = 0; i < req->vifr_fat_flow_protocol_port_size; i++) {
         cfg.protocol =
             VIF_FAT_FLOW_PROTOCOL(req->vifr_fat_flow_protocol_port[i]);
         cfg.port =
             VIF_FAT_FLOW_PORT(req->vifr_fat_flow_protocol_port[i]);
         cfg.port_aggr_info =
             VIF_FAT_FLOW_PORT_AGGR_INFO(req->vifr_fat_flow_protocol_port[i]);
         cfg.src_prefix_h = req->vifr_fat_flow_src_prefix_h[i];
         cfg.src_prefix_l = req->vifr_fat_flow_src_prefix_l[i];
         cfg.src_prefix_mask = req->vifr_fat_flow_src_prefix_mask[i];
         cfg.src_aggregate_plen = req->vifr_fat_flow_src_aggregate_plen[i];
         cfg.dst_prefix_h = req->vifr_fat_flow_dst_prefix_h[i];
         cfg.dst_prefix_l = req->vifr_fat_flow_dst_prefix_l[i];
         cfg.dst_prefix_mask = req->vifr_fat_flow_dst_prefix_mask[i];
         cfg.dst_aggregate_plen = req->vifr_fat_flow_dst_aggregate_plen[i];
         (*new_fat_flow_cfg)[i] = cfg;
         new_fat_flow_num_rules[vif_fat_flow_get_proto_index(cfg.protocol)]++;
    }
    return 0;
}

static void
vif_fat_flow_cfg_swap(struct vr_interface *vif,
                      vr_fat_flow_cfg_t *new_fat_flow_cfg,
                      uint16_t new_fat_flow_cfg_size,
                      uint16_t *new_fat_flow_num_rules,
                      vr_fat_flow_cfg_t **old_fat_flow_cfg)
{
    *old_fat_flow_cfg = vif->fat_flow_cfg;
    vif->fat_flow_cfg = new_fat_flow_cfg;
    vif->fat_flow_cfg_size = new_fat_flow_cfg_size;
    memcpy(vif->fat_flow_num_rules, new_fat_flow_num_rules,
           sizeof(vif->fat_flow_num_rules));
}

static void
vif_fat_flow_cfg_free(vr_fat_flow_cfg_t *old_fat_flow_cfg)
{
    if (old_fat_flow_cfg) {
        vr_free(old_fat_flow_cfg, VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
    }
}

/*
 * Function to allocate a prefix rule data structure;
 *
 * Some notes on the design:
 * All the prefix based fat flow rules are stored in mtries based
 * on the ip address type & prefix type
 * A prefix based fat flow rule can be of 3 types:-
 * 1) Fat flow rule with only src prefix
 * 2) Fat flow rule with only dst prefix
 * 3) Fat flow rule with both src and dst prefix
 * The src and src+dst based rules are store in the src_prefix mtrie
 * whereas the dst based rule is stored in the dst_prefix mtrie;
 * The 3 types of rules are represented as below -
 * src prefix rule
 *     src_prefix -> rule_data -> proto_info[proto] -> port_itable -> port_data
 * dst prefix rule
 *     dst_prefix -> rule_data -> proto_info[proto] -> port_itable -> port_data
 * src+ dst prefix rule
 *     src_prefix -> rule_data -> proto_info[proto] \
 *                                     -> port_itable -> port_data -> dst_prefix
 */
static vr_fat_flow_prefix_rule_data_t *
__vif_fat_flow_alloc_prefix_rule_data(vr_fat_flow_cfg_t *cfg)
{
    vr_fat_flow_prefix_rule_data_t *rdata = NULL;
    int i, proto_index;
    vr_itable_t ptable = NULL;
    vr_fat_flow_prefix_rule_port_data_t *port_data = NULL;
    struct vr_route_req  vr_req;
    uint64_t prefix[2];
    int ret;

    /* Allocate the rule and fill in the rule details */
    rdata = vr_zalloc(sizeof(vr_fat_flow_prefix_rule_data_t),
                      VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
    if (!rdata) {
         goto err;
    }
    rdata->proto_info = vr_zalloc(sizeof(vr_fat_flow_prefix_rule_proto_info_t),
                                  VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
    if (!rdata->proto_info) {
         goto err;
    }
    for (i = 0; i < VIF_FAT_FLOW_MAXPROTO_INDEX; i++) {
         rdata->proto_info->proto[i] = NULL;
    }
    rdata->next = NULL;
    proto_index = vif_fat_flow_get_proto_index(cfg->protocol);
    ptable = vr_itable_create(16, 2, 8, 8);
    if (!ptable) {
        goto err;
    }
    rdata->proto_info->proto[proto_index] = ptable;

    port_data = vr_zalloc(sizeof(*port_data), VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
    if (!port_data) {
        goto err;
    }
    port_data->second_prefix = NULL;
    /* Add the port data to itable */
    if (vr_itable_set(ptable, cfg->port, (void *)port_data) == VR_ITABLE_ERR_PTR) {
        vr_printf("%s: Failed to add to itable port %d port_data %p\n",
                  __FUNCTION__, cfg->port, port_data);
        goto err;
    }

    if (__vif_is_fat_flow_src_dst_prefix_rule(cfg)) {
        port_data->rule_type = PREFIX_RULE_TYPE_DUAL_PREFIX;
    } else {
        port_data->rule_type = PREFIX_RULE_TYPE_SINGLE_PREFIX;
        if (VIF_FAT_FLOW_CFG_PORT_DATA(cfg->port_aggr_info) ==
                                       VIF_FAT_FLOW_PORT_SIP_IGNORE) {
            port_data->rule_type |= PREFIX_RULE_HAS_IGNORE_SRC;
        } else if (VIF_FAT_FLOW_CFG_PORT_DATA(cfg->port_aggr_info) ==
                                              VIF_FAT_FLOW_PORT_DIP_IGNORE) {
            port_data->rule_type |= PREFIX_RULE_HAS_IGNORE_DST;
        }
    }
    if (__vif_is_fat_flow_dst_prefix_rule(cfg)) {
        port_data->aggr_plen = cfg->dst_aggregate_plen;
    } else {
        port_data->aggr_plen = cfg->src_aggregate_plen;
    }
    /* Insert the dst/second prefix also into the rule */
    if (__vif_is_fat_flow_src_dst_prefix_rule(cfg)) {
       port_data->second_prefix = vdata_mtrie_init(0, &dummy_plen);
       if (!port_data->second_prefix) {
           goto err;
       }
       memset(&vr_req, 0, sizeof(vr_route_req));
       if (__vif_is_fat_flow_v4_prefix_rule(cfg)) {
           vr_req.rtr_req.rtr_family = AF_INET;
           vr_req.rtr_req.rtr_prefix_size = 4;
           prefix[0] = cfg->dst_prefix_l;
           prefix[1] = cfg->dst_prefix_h;
       } else {
           vr_req.rtr_req.rtr_family = AF_INET6;
           vr_req.rtr_req.rtr_prefix_size = 16;
           prefix[0] = cfg->dst_prefix_h;
           prefix[1] = cfg->dst_prefix_l;
       }
       vr_req.rtr_req.rtr_prefix = (int8_t *) prefix;
       vr_req.rtr_req.rtr_prefix_len = cfg->dst_prefix_mask;
       vr_req.rtr_nh = (struct vr_nexthop *) cfg->dst_aggregate_plen;
       /* Add the prefix into mtrie */
       ret = vdata_mtrie_add(port_data->second_prefix, &vr_req);
       if (ret != 0) {
           goto err;
       }
    }
    return rdata;

err:
    if (port_data) {
        if (port_data->second_prefix) {
            vdata_mtrie_delete_all(port_data->second_prefix);
        }
        vr_free(port_data, VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
    }
    if (ptable) {
        vr_itable_delete(ptable, NULL);
    }
    if (rdata) {
        if (rdata->proto_info) {
            vr_free(rdata->proto_info, VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        }
        vr_free(rdata, VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
    }
    return NULL;
}


static int
__vif_fat_flow_update_prefix_rule_data(vr_fat_flow_prefix_rule_data_t *rdata,
                                       vr_fat_flow_cfg_t *cfg)
{
    int proto_index;
    vr_itable_t ptable;
    vr_fat_flow_prefix_rule_port_data_t *port_data;
    struct vr_route_req  vr_req;
    uint64_t prefix[2];
    int ret;

    /* Lookup the protocol */
    proto_index = vif_fat_flow_get_proto_index(cfg->protocol);
    ptable = rdata->proto_info->proto[proto_index];
    if (!ptable) {
        ptable = vr_itable_create(16, 2, 8, 8);
        if (!ptable) {
            return -1;
        }
        rdata->proto_info->proto[proto_index] = ptable;
    }
    /* Lookup the port */
    port_data = (vr_fat_flow_prefix_rule_port_data_t *) vr_itable_get(ptable, cfg->port);
    if (!port_data) {
        port_data = vr_zalloc(sizeof(*port_data), VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        if (!port_data) {
            return -1;
        }
        /* Add the port data to itable */
        vr_itable_set(ptable, cfg->port, (void *)port_data);
    }

    /* Update port data */
    if (__vif_is_fat_flow_src_dst_prefix_rule(cfg)) {
        port_data->rule_type |= PREFIX_RULE_TYPE_DUAL_PREFIX;
    } else {
        port_data->rule_type |= PREFIX_RULE_TYPE_SINGLE_PREFIX;
        if (VIF_FAT_FLOW_CFG_PORT_DATA(cfg->port_aggr_info) ==
                                       VIF_FAT_FLOW_PORT_SIP_IGNORE) {
            port_data->rule_type |= PREFIX_RULE_HAS_IGNORE_SRC;
        } else if (VIF_FAT_FLOW_CFG_PORT_DATA(cfg->port_aggr_info) ==
                                              VIF_FAT_FLOW_PORT_DIP_IGNORE) {
            port_data->rule_type |= PREFIX_RULE_HAS_IGNORE_DST;
        }
    }
    if (__vif_is_fat_flow_dst_prefix_rule(cfg)) {
        port_data->aggr_plen = cfg->dst_aggregate_plen;
    } else {
        port_data->aggr_plen = cfg->src_aggregate_plen;
    }
    /* Insert the dst/second prefix also into the rule */
    if (__vif_is_fat_flow_src_dst_prefix_rule(cfg)) {
       if (!port_data->second_prefix) {
           port_data->second_prefix = vdata_mtrie_init(0, &dummy_plen);
           if (!port_data->second_prefix) {
               return -1;
           }
       }
       memset(&vr_req, 0, sizeof(vr_route_req));
       if (__vif_is_fat_flow_v4_prefix_rule(cfg)) {
           vr_req.rtr_req.rtr_family = AF_INET;
           vr_req.rtr_req.rtr_prefix_size = 4;
           prefix[0] = cfg->dst_prefix_l;
           prefix[1] = cfg->dst_prefix_h;
       } else {
           vr_req.rtr_req.rtr_family = AF_INET6;
           vr_req.rtr_req.rtr_prefix_size = 16;
           prefix[0] = cfg->dst_prefix_h;
           prefix[1] = cfg->dst_prefix_l;
       }
       vr_req.rtr_req.rtr_prefix = (int8_t *)prefix;
       vr_req.rtr_req.rtr_prefix_len = cfg->dst_prefix_mask;
       vr_req.rtr_nh = (struct vr_nexthop *) cfg->dst_aggregate_plen;
       /* Add the prefix into mtrie */
       ret = vdata_mtrie_add(port_data->second_prefix, &vr_req);
       if (ret != 0) {
           return -1;
       }
    }

    return 0;
}

static int
__vif_fat_flow_add_prefix_rule(struct ip_mtrie *rules, vr_fat_flow_cfg_t *cfg,
                               vr_fat_flow_prefix_rule_data_t **rule_data)
{
    struct vr_route_req  vr_req, add_req;
    uint64_t prefix[2];
    vr_fat_flow_prefix_rule_data_t *rdata = NULL;
    int ret, prefix_len;

    /* Check if the src/dst prefix already exists */
    memset(&vr_req, 0, sizeof(vr_route_req));
    memset(&add_req, 0, sizeof(vr_route_req));

    if (__vif_is_fat_flow_v4_prefix_rule(cfg)) {
        vr_req.rtr_req.rtr_family = AF_INET;
        vr_req.rtr_req.rtr_prefix_size = 4;
    } else {
        vr_req.rtr_req.rtr_family = AF_INET6;
        vr_req.rtr_req.rtr_prefix_size = 16;
    }
    if (__vif_is_fat_flow_src_prefix_rule(cfg) ||
        __vif_is_fat_flow_src_dst_prefix_rule(cfg)) {
        if (__vif_is_fat_flow_v4_prefix_rule(cfg)) {
            prefix[0] = cfg->src_prefix_l;
            prefix[1] = cfg->src_prefix_h;
        } else {
            /* for v6 it is other way round */
            prefix[0] = cfg->src_prefix_h;
            prefix[1] = cfg->src_prefix_l;
        }
        vr_req.rtr_req.rtr_prefix_len = cfg->src_prefix_mask;
    } else {
        if (__vif_is_fat_flow_v4_prefix_rule(cfg)) {
            prefix[0] = cfg->dst_prefix_l;
            prefix[1] = cfg->dst_prefix_h;
        } else {
            prefix[0] = cfg->dst_prefix_h;
            prefix[1] = cfg->dst_prefix_l;
        }
        vr_req.rtr_req.rtr_prefix_len = cfg->dst_prefix_mask;
    }
    prefix_len = vr_req.rtr_req.rtr_prefix_len;
    vr_req.rtr_req.rtr_prefix = (int8_t *)prefix;
    add_req = vr_req;

    rdata = vdata_mtrie_lookup(rules, &vr_req);

    /* This is a new prefix */
    if (!rdata || (prefix_len != vr_req.rtr_req.rtr_prefix_len)) {
        rdata = __vif_fat_flow_alloc_prefix_rule_data(cfg);
        if (!rdata) {
             return -1;
        }
        /* Add the rule data to the list */
        if (*rule_data) {
            rdata->next = *rule_data;
        }
        *rule_data = rdata;
        add_req.rtr_nh = (struct vr_nexthop *) rdata;
        /* Add the prefix into mtrie */
        ret = vdata_mtrie_add(rules, &add_req);
        if (ret != 0) {
            return ret;
        }
    } else {
        /* Update the existing prefix's rule data */
        ret = __vif_fat_flow_update_prefix_rule_data(rdata, cfg);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}

static void
__vif_flat_flow_free_no_prefix_rules_cb(struct vrouter *router, void *data)
{
    struct vr_defer_data *vdd = (struct vr_defer_data *)data;
    uint8_t **no_prefix_rules = NULL;

    if (!vdd || !vdd->vdd_data)
        return;
    no_prefix_rules = (uint8_t **) vdd->vdd_data;

    if (no_prefix_rules) {
        vif_fat_flow_free(no_prefix_rules);
    }
}

static void
__vif_fat_flow_delete_all_no_prefix_rules(
                        uint8_t **no_prefix_rules[VIF_FAT_FLOW_MAXPROTO_INDEX])
{
    struct vr_defer_data *vdd_npr;
    int i;

    for (i = 0; i < VIF_FAT_FLOW_MAXPROTO_INDEX; i++) {
        vdd_npr = vr_get_defer_data(sizeof(*vdd_npr));
        if (!vdd_npr)
            return;
        vdd_npr->vdd_data = (void *) no_prefix_rules[i];
        vr_defer(vrouter_get(0), __vif_flat_flow_free_no_prefix_rules_cb, vdd_npr);
    }
}

static void
__vif_flat_flow_free_prefix_rules_cb(struct vrouter *router, void *data)
{
    struct ip_mtrie *prefix_rules;
    struct vr_defer_data *vdd = (struct vr_defer_data *)data;

    if (!vdd || !vdd->vdd_data)
        return;
    prefix_rules = (struct ip_mtrie *) vdd->vdd_data;
    vdata_mtrie_delete_all(prefix_rules);
}

static void
__vif_fat_flow_delete_all_prefix_rules(struct ip_mtrie *prefix_rules)
{
    struct vr_defer_data *vdd_pr;

    vdd_pr = vr_get_defer_data(sizeof(*vdd_pr));
    if (!vdd_pr)
        return;
    vdd_pr->vdd_data = (void *) prefix_rules;
    vr_defer(vrouter_get(0), __vif_flat_flow_free_prefix_rules_cb, vdd_pr);
}

static void
__vif_fat_flow_free_port_data_cb(unsigned int index, void *data)
{
    vr_fat_flow_prefix_rule_port_data_t *port_data;
    if (!data) {
        return;
    }
    port_data = (vr_fat_flow_prefix_rule_port_data_t *) data;
    if (port_data->second_prefix) {
        vdata_mtrie_delete_all(port_data->second_prefix);
    }
    vr_free(port_data, VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
}

static void
__vif_fat_flow_free_all_rule_data_list(vr_fat_flow_prefix_rule_data_t *head)
{
    vr_fat_flow_prefix_rule_data_t *nextent;
    int i;

    while (head) {
        nextent = head->next;

        for (i = 0; i < VIF_FAT_FLOW_MAXPROTO_INDEX; i++) {
             if (!head->proto_info->proto[i])
                 continue;
             vr_itable_delete(head->proto_info->proto[i],
                              __vif_fat_flow_free_port_data_cb);
        }
        vr_free(head->proto_info, VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
        vr_free(head, VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);

        head = nextent;
    }
}

static void
__vif_fat_flow_free_rule_data_defer_cb(struct vrouter *router, void *data)
{
    struct vr_defer_data *vdd = (struct vr_defer_data *)data;
    vr_fat_flow_prefix_rule_data_t *rdata;
    int i;

    if (!vdd || !vdd->vdd_data)
        return;

    rdata = (vr_fat_flow_prefix_rule_data_t *) vdd->vdd_data;
    for (i = 0; i < VIF_FAT_FLOW_MAXPROTO_INDEX; i++) {
         if (!rdata->proto_info->proto[i])
             continue;
         vr_itable_delete(rdata->proto_info->proto[i],
                          __vif_fat_flow_free_port_data_cb);
    }
    vr_free(rdata->proto_info, VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
    vr_free(rdata, VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT);
    return;
}

static void
__vif_fat_flow_delete_all_rule_data_list(vr_fat_flow_prefix_rule_data_t *head)
{
    vr_fat_flow_prefix_rule_data_t *nextent;
    struct vr_defer_data *vdd_rd;

    while (head) {
        nextent = head->next;
        vdd_rd = vr_get_defer_data(sizeof(*vdd_rd));
        if (!vdd_rd)
             return;
        vdd_rd->vdd_data = (void *) head;
        vr_defer(vrouter_get(0), __vif_fat_flow_free_rule_data_defer_cb, vdd_rd);
        head = nextent;
    }
}

static int
vif_fat_flow_rules_build(vr_fat_flow_cfg_t *new_cfg, uint16_t new_cfg_size,
                         struct vr_interface *vif)
{
    uint8_t **no_prefix_rules[VIF_FAT_FLOW_MAXPROTO_INDEX] = {NULL},
            **old_no_prefix_rules[VIF_FAT_FLOW_MAXPROTO_INDEX] = {NULL};
    struct ip_mtrie *v4_src_prefix_rules = NULL,
                    *old_v4_src_prefix_rules = NULL;
    struct ip_mtrie *v4_dst_prefix_rules = NULL,
                    *old_v4_dst_prefix_rules = NULL;
    struct ip_mtrie *v6_src_prefix_rules = NULL,
                    *old_v6_src_prefix_rules = NULL;
    struct ip_mtrie *v6_dst_prefix_rules = NULL,
                    *old_v6_dst_prefix_rules = NULL;
    struct ip_mtrie **prefix_rules = NULL;
    vr_fat_flow_prefix_rule_data_t *rule_data_list = NULL,
                                   *old_rule_data_list = NULL;
    uint8_t prefix_aggr;
    uint8_t proto, proto_index, port_data;
    uint16_t port;
    int i, ret = 0;

    for (i = 0; i < new_cfg_size; i++) {
         prefix_aggr = VIF_FAT_FLOW_CFG_PREFIX_AGGR_DATA(new_cfg[i].port_aggr_info);
         switch (prefix_aggr) {
             case VR_AGGREGATE_NONE:
                  proto = new_cfg[i].protocol;
                  port = new_cfg[i].port;
                  proto_index = vif_fat_flow_get_proto_index(proto);
                  port_data = VIF_FAT_FLOW_CFG_PORT_DATA(new_cfg[i].port_aggr_info);
                  if (proto_index == VIF_FAT_FLOW_NOPROTO_INDEX)
                      port = proto;
                  ret = __vif_fat_flow_add_no_prefix_rule(no_prefix_rules,
                                                          proto, port, port_data);
                  if (ret) {
                      goto err;
                  }
                  break;
             case VR_AGGREGATE_SRC_IPV4:
             case VR_AGGREGATE_SRC_IPV6:
             case VR_AGGREGATE_DST_IPV4:
             case VR_AGGREGATE_DST_IPV6:
             case VR_AGGREGATE_SRC_DST_IPV4:
             case VR_AGGREGATE_SRC_DST_IPV6:
                  if ((prefix_aggr == VR_AGGREGATE_SRC_IPV4) ||
                      (prefix_aggr == VR_AGGREGATE_SRC_DST_IPV4)) {
                      prefix_rules = &v4_src_prefix_rules;
                  } else if ((prefix_aggr == VR_AGGREGATE_SRC_IPV6) ||
                             (prefix_aggr == VR_AGGREGATE_SRC_DST_IPV6)) {
                      prefix_rules = &v6_src_prefix_rules;
                  } else if (prefix_aggr == VR_AGGREGATE_DST_IPV4) {
                      prefix_rules = &v4_dst_prefix_rules;
                  } else {
                      prefix_rules = &v6_dst_prefix_rules;
                  }
                  if (!(*prefix_rules)) {
                       *prefix_rules = vdata_mtrie_init(0, &dummy_rule);
                       if (!(*prefix_rules)) {
                            ret = -ENOMEM;
                            goto err;
                       }
                  }
                  ret = __vif_fat_flow_add_prefix_rule((*prefix_rules),
                                                       &new_cfg[i], &rule_data_list);
                  if (ret != 0) {
                      goto err;
                  }
                  break;
             default:
                  break;
         }
    }
    /* Save the old rules */
    for (i = 0; i < VIF_FAT_FLOW_MAXPROTO_INDEX; i++) {
         old_no_prefix_rules[i] = vif->vif_fat_flow_no_prefix_rules[i];
    }
    old_v4_src_prefix_rules = vif->vif_fat_flow_v4_src_prefix_rules;
    old_v4_dst_prefix_rules = vif->vif_fat_flow_v4_dst_prefix_rules;
    old_v6_src_prefix_rules = vif->vif_fat_flow_v6_src_prefix_rules;
    old_v6_dst_prefix_rules = vif->vif_fat_flow_v6_dst_prefix_rules;
    old_rule_data_list = vif->vif_fat_flow_rule_data_list;

    /* Copy the new rules to vif */
    for (i = 0; i < VIF_FAT_FLOW_MAXPROTO_INDEX; i++) {
         vif->vif_fat_flow_no_prefix_rules[i] = no_prefix_rules[i];
    }
    vif->vif_fat_flow_v4_src_prefix_rules = v4_src_prefix_rules;
    vif->vif_fat_flow_v4_dst_prefix_rules = v4_dst_prefix_rules;
    vif->vif_fat_flow_v6_src_prefix_rules = v6_src_prefix_rules;
    vif->vif_fat_flow_v6_dst_prefix_rules = v6_dst_prefix_rules;
    vif->vif_fat_flow_rule_data_list = rule_data_list;

    /* Defer delete the old rules */
    __vif_fat_flow_delete_all_no_prefix_rules(old_no_prefix_rules);
    if (old_v4_src_prefix_rules)
        __vif_fat_flow_delete_all_prefix_rules(old_v4_src_prefix_rules);
    if (old_v4_dst_prefix_rules)
        __vif_fat_flow_delete_all_prefix_rules(old_v4_dst_prefix_rules);
    if (old_v6_src_prefix_rules)
        __vif_fat_flow_delete_all_prefix_rules(old_v6_src_prefix_rules);
    if (old_v6_dst_prefix_rules)
        __vif_fat_flow_delete_all_prefix_rules(old_v6_dst_prefix_rules);
    if (old_rule_data_list)
        __vif_fat_flow_delete_all_rule_data_list(old_rule_data_list);

    return 0;

err:
    __vif_fat_flow_delete_all_no_prefix_rules(no_prefix_rules);
    if (v4_src_prefix_rules)
        __vif_fat_flow_delete_all_prefix_rules(v4_src_prefix_rules);
    if (v4_dst_prefix_rules)
        __vif_fat_flow_delete_all_prefix_rules(v4_dst_prefix_rules);
    if (v6_src_prefix_rules)
        __vif_fat_flow_delete_all_prefix_rules(v6_src_prefix_rules);
    if (v6_dst_prefix_rules)
        __vif_fat_flow_delete_all_prefix_rules(v6_dst_prefix_rules);
    if (rule_data_list)
        __vif_fat_flow_delete_all_rule_data_list(rule_data_list);
    return ret;
}


static int
vif_fat_flow_add(struct vr_interface *vif, vr_interface_req *req)
{
    int rc;
    vr_fat_flow_cfg_t *old_fat_flow_cfg, *new_fat_flow_cfg;
    uint16_t new_fat_flow_cfg_size;
    uint16_t new_fat_flow_num_rules[VIF_FAT_FLOW_MAXPROTO_INDEX] = {0};

    int i;
    uint32_t v4_prefix, v4_prefix_len, v4_mask;
    uint64_t v6_prefix_h, v6_prefix_l, v6_mask_l, v6_mask_h;
    uint16_t v6_prefix_len;

    /* Populate the ipv4 & ipv6 exclude lists */
    if (!req->vifr_fat_flow_exclude_ip_list_size) {
        memset(vif->vif_fat_flow_ipv4_exclude_list, 0,
               FAT_FLOW_IPV4_EXCLUDE_LIST_MAX_SIZE * sizeof(uint32_t));
        memset(vif->vif_fat_flow_ipv4_exclude_plen_list, 0,
               FAT_FLOW_IPV4_EXCLUDE_LIST_MAX_SIZE * sizeof(uint8_t));
        vif->vif_fat_flow_ipv4_exclude_list_size = 0;
    } else {
        if (req->vifr_fat_flow_exclude_ip_list_size > FAT_FLOW_IPV4_EXCLUDE_LIST_MAX_SIZE) {
            return -EINVAL;
        }
        /* copy the exclude list and size */
        for (i = 0; i < req->vifr_fat_flow_exclude_ip_list_size; i++) {
             v4_prefix_len = FAT_FLOW_EXCLUDE_IPV4_PREFIX_LEN(req->vifr_fat_flow_exclude_ip_list[i]);
             v4_prefix = FAT_FLOW_EXCLUDE_IPV4_PREFIX(req->vifr_fat_flow_exclude_ip_list[i]);
             v4_mask = FAT_FLOW_IPV4_PLEN_TO_MASK(v4_prefix_len);
             vif->vif_fat_flow_ipv4_exclude_list[i] = v4_prefix & v4_mask;
             vif->vif_fat_flow_ipv4_exclude_plen_list[i] = (uint8_t) v4_prefix_len;
        }
        vif->vif_fat_flow_ipv4_exclude_list_size = req->vifr_fat_flow_exclude_ip_list_size;
    }

    if (!req->vifr_fat_flow_exclude_ip6_l_list_size) {
        memset(vif->vif_fat_flow_ipv6_low_exclude_list, 0,
               FAT_FLOW_IPV6_EXCLUDE_LIST_MAX_SIZE * sizeof(uint64_t));
        memset(vif->vif_fat_flow_ipv6_high_exclude_list, 0,
               FAT_FLOW_IPV6_EXCLUDE_LIST_MAX_SIZE * sizeof(uint64_t));
        memset(vif->vif_fat_flow_ipv6_exclude_plen_list, 0,
               FAT_FLOW_IPV6_EXCLUDE_LIST_MAX_SIZE * sizeof(uint8_t));
        vif->vif_fat_flow_ipv6_exclude_list_size = 0;
    } else {
        if ((req->vifr_fat_flow_exclude_ip6_l_list_size != req->vifr_fat_flow_exclude_ip6_u_list_size) ||
            (req->vifr_fat_flow_exclude_ip6_l_list_size != req->vifr_fat_flow_exclude_ip6_plen_list_size) ||
            (req->vifr_fat_flow_exclude_ip6_l_list_size > FAT_FLOW_IPV6_EXCLUDE_LIST_MAX_SIZE)) {
             return -EINVAL;
        }
        /* copy the exclude list and size */
        for (i = 0; i < req->vifr_fat_flow_exclude_ip6_l_list_size; i++) {
             v6_prefix_l = req->vifr_fat_flow_exclude_ip6_l_list[i];
             v6_prefix_h = req->vifr_fat_flow_exclude_ip6_u_list[i];
             v6_prefix_len = req->vifr_fat_flow_exclude_ip6_plen_list[i];
             fat_flow_ipv6_plen_to_mask(v6_prefix_len, &v6_mask_h, &v6_mask_l);
             vif->vif_fat_flow_ipv6_low_exclude_list[i] = v6_prefix_l & v6_mask_l;
             vif->vif_fat_flow_ipv6_high_exclude_list[i] = v6_prefix_h & v6_mask_h;
             vif->vif_fat_flow_ipv6_exclude_plen_list[i] = (uint8_t) v6_prefix_len;
        }
        vif->vif_fat_flow_ipv6_exclude_list_size = req->vifr_fat_flow_exclude_ip6_l_list_size;
    }

    /* Do rest of fat flow config processing */

    /*
     * Check if fat flow config has changed. If so, then build the new config and rules;
     * Free the old ones.
     */
    if (vif_fat_flow_cfg_is_changed(vif, req)) {
        /* Build the new cfg and rules */
        rc = vif_fat_flow_cfg_build(req, &new_fat_flow_cfg, &new_fat_flow_cfg_size,
                                    new_fat_flow_num_rules);
        if (rc < 0) {
            return rc;
        }
        rc = vif_fat_flow_rules_build(new_fat_flow_cfg, new_fat_flow_cfg_size, vif);
        if (rc < 0) {
            vif_fat_flow_cfg_free(new_fat_flow_cfg);
            return rc;
        }
        /* Swap the old cfg with the new one */
        vif_fat_flow_cfg_swap(vif, new_fat_flow_cfg, new_fat_flow_cfg_size,
                              new_fat_flow_num_rules, &old_fat_flow_cfg);
        /* Free the old cfg */
        vif_fat_flow_cfg_free(old_fat_flow_cfg);
    }

    return 0;
}

static uint8_t
vif_fat_flow_port_get(struct vr_interface *vif, uint8_t proto_index,
        uint16_t port)
{
    unsigned int row, column, byte, bit;

    row = proto_index;
    column = port / VIF_FAT_FLOW_PORTS_PER_BITMAP;

    if (vif->vif_fat_flow_no_prefix_rules[row]) {
        if (vif->vif_fat_flow_no_prefix_rules[row][column]) {
            byte = ((port % VIF_FAT_FLOW_PORTS_PER_BITMAP) * 2) / 8;
            bit = ((port % VIF_FAT_FLOW_PORTS_PER_BITMAP) * 2) % 8;
            return (vif->vif_fat_flow_no_prefix_rules[row][column][byte] >> bit) &
                VIF_FAT_FLOW_DATA_MASK;
        }
    }

    return 0;
}


static uint8_t
vif_fat_flow_exclude_list_lookup (struct vr_interface *vif, unsigned int *saddr, unsigned int *daddr,
                                  unsigned char *ip6_src, unsigned char *ip6_dst)
{
    int i;
    uint64_t v6_prefix_h, v6_prefix_l, v6_mask_h, v6_mask_l;
    uint32_t v4_mask;

    if (saddr) {
        if (!vif->vif_fat_flow_ipv4_exclude_list_size) {
            return 0;
        }
        for (i = 0; i < vif->vif_fat_flow_ipv4_exclude_list_size; i++) {
             v4_mask = FAT_FLOW_IPV4_PLEN_TO_MASK(vif->vif_fat_flow_ipv4_exclude_plen_list[i]);
             if (((*saddr & v4_mask) == vif->vif_fat_flow_ipv4_exclude_list[i]) ||
                 ((*daddr & v4_mask) == vif->vif_fat_flow_ipv4_exclude_list[i])) {
                  return 1;
             }
        }
    } else if (ip6_src) {
        if (!vif->vif_fat_flow_ipv6_exclude_list_size) {
            return 0;
        }
        for (i = 0; i < vif->vif_fat_flow_ipv6_exclude_list_size; i++) {
             fat_flow_ipv6_plen_to_mask(vif->vif_fat_flow_ipv6_exclude_plen_list[i], &v6_mask_h, &v6_mask_l);
             /* compare src ip */
             memcpy(&v6_prefix_h, (uint8_t *) ip6_src, 8);
             memcpy(&v6_prefix_l, ((uint8_t *) ip6_src) + 8, 8);
             if (((v6_prefix_l & v6_mask_l) == vif->vif_fat_flow_ipv6_low_exclude_list[i]) &&
                 ((v6_prefix_h & v6_mask_h) == vif->vif_fat_flow_ipv6_high_exclude_list[i])) {
                  return 1;
             }
             /* compare dst ip */
             memcpy(&v6_prefix_h, (uint8_t *) ip6_dst, 8);
             memcpy(&v6_prefix_l, ((uint8_t *) ip6_dst) + 8, 8);
             if (((v6_prefix_l & v6_mask_l) == vif->vif_fat_flow_ipv6_low_exclude_list[i]) &&
                 ((v6_prefix_h & v6_mask_h) == vif->vif_fat_flow_ipv6_high_exclude_list[i])) {
                  return 1;
             }
        }
    }
    return 0;
}

static int
__vif_fat_flow_ip_prefix_lookup(struct ip_mtrie *mtrie, unsigned int *ip,
                                unsigned char *ip6, uint8_t *aggr_mask)
{
    struct vr_route_req  vr_req;
    uint64_t prefix[2];
    void *ret = NULL;

    if (!mtrie) {
        return 0;
    }
    memset(&vr_req, 0, sizeof(vr_req));

    if (ip) {
        vr_req.rtr_req.rtr_family = AF_INET;
        vr_req.rtr_req.rtr_prefix_size = 4;
        vr_req.rtr_req.rtr_prefix_len = 32;
        prefix[0] = (uint64_t) *ip;
        prefix[1] = 0;
    } else {
        vr_req.rtr_req.rtr_family = AF_INET6;
        vr_req.rtr_req.rtr_prefix_size = 16;
        vr_req.rtr_req.rtr_prefix_len = 128;
        prefix[0] = *((uint64_t *)ip6);
        prefix[1] = *((uint64_t *)((uint8_t *)ip6+8));
    }

    vr_req.rtr_req.rtr_prefix = (int8_t *)prefix;
    ret = vdata_mtrie_lookup(mtrie, &vr_req);
    if (!ret || (vr_req.rtr_req.rtr_prefix_len == 0)) {
        return 0;
    }
    *aggr_mask = (uint8_t) ret;
    return 1;
}

static int
vif_fat_flow_prefix_proto_port_match(uint8_t rule_type, int incoming_vif,
                                     vr_fat_flow_prefix_rule_data_t *rdata,
                                     unsigned int *dip, unsigned char *dip6,
                                     uint8_t proto, uint16_t sport, uint16_t dport,
                                     uint8_t *aggr_mask, uint8_t *aggr_mask1,
                                     uint16_t *fat_flow_mask)
{
    int proto_index;
    vr_fat_flow_prefix_rule_port_data_t *src_port_info = NULL,
                                        *dst_port_info = NULL,
                                        *zero_port_info = NULL;
    vr_itable_t ptable = NULL;

    proto_index = vif_fat_flow_get_proto_index(proto);
    ptable = rdata->proto_info->proto[proto_index];

    /* Match protocol and src, dst and 0 port numbers */
    if (ptable) {
        /* Set the respective port infos first for the ruletype passed */
        src_port_info = (vr_fat_flow_prefix_rule_port_data_t *) vr_itable_get(ptable, sport);
        if (src_port_info && (!(src_port_info->rule_type & rule_type))) {
            src_port_info = NULL;
        }

        dst_port_info = (vr_fat_flow_prefix_rule_port_data_t *) vr_itable_get(ptable, dport);
        if (dst_port_info && (!(dst_port_info->rule_type & rule_type))) {
            dst_port_info = NULL;
        }

        zero_port_info = (vr_fat_flow_prefix_rule_port_data_t *) vr_itable_get(ptable, 0);
        if (zero_port_info && (!(zero_port_info->rule_type & rule_type))) {
            zero_port_info = NULL;
        }

        /* Now evaluate based on port number precedence */
        if (sport < dport) {
            if (src_port_info) {
                if (rule_type == PREFIX_RULE_TYPE_SINGLE_PREFIX) {
                    *aggr_mask = src_port_info->aggr_plen;
                    *fat_flow_mask = VR_FAT_FLOW_DST_PORT_MASK;
                    if (src_port_info->rule_type & PREFIX_RULE_HAS_IGNORE_SRC) {
                        *fat_flow_mask |= VR_FAT_FLOW_SRC_IP_MASK;
                    }
                    if (src_port_info->rule_type & PREFIX_RULE_HAS_IGNORE_DST) {
                        *fat_flow_mask |= VR_FAT_FLOW_DST_IP_MASK;
                    }
                    return 1;
                } else { /* src+dst rule */
                    if (__vif_fat_flow_ip_prefix_lookup(src_port_info->second_prefix, dip,
                                                        dip6, aggr_mask1)) {
                        *aggr_mask = src_port_info->aggr_plen;
                        *fat_flow_mask = VR_FAT_FLOW_DST_PORT_MASK;
                        return 1;
                    }
                }
            }
            if (dst_port_info) {
                if (rule_type == PREFIX_RULE_TYPE_SINGLE_PREFIX) {
                    *aggr_mask = dst_port_info->aggr_plen;
                    *fat_flow_mask = VR_FAT_FLOW_SRC_PORT_MASK;
                    if (dst_port_info->rule_type & PREFIX_RULE_HAS_IGNORE_SRC) {
                        *fat_flow_mask |= VR_FAT_FLOW_SRC_IP_MASK;
                    }
                    if (dst_port_info->rule_type & PREFIX_RULE_HAS_IGNORE_DST) {
                        *fat_flow_mask |= VR_FAT_FLOW_DST_IP_MASK;
                    }
                    return 1;
                } else {
                    if (__vif_fat_flow_ip_prefix_lookup(dst_port_info->second_prefix, dip,
                                                        dip6, aggr_mask1)) {
                        *aggr_mask = dst_port_info->aggr_plen;
                        *fat_flow_mask = VR_FAT_FLOW_SRC_PORT_MASK;
                        return 1;
                    }
                }
            }
        } else {
            if (dst_port_info) {
                if (rule_type == PREFIX_RULE_TYPE_SINGLE_PREFIX) {
                    *aggr_mask = dst_port_info->aggr_plen;
                    *fat_flow_mask = VR_FAT_FLOW_SRC_PORT_MASK;
                    if (dst_port_info->rule_type & PREFIX_RULE_HAS_IGNORE_SRC) {
                        *fat_flow_mask |= VR_FAT_FLOW_SRC_IP_MASK;
                    }
                    if (dst_port_info->rule_type & PREFIX_RULE_HAS_IGNORE_DST) {
                        *fat_flow_mask |= VR_FAT_FLOW_DST_IP_MASK;
                    }
                    return 1;
                } else {
                    if (__vif_fat_flow_ip_prefix_lookup(dst_port_info->second_prefix,
                                                        dip, dip6, aggr_mask1)) {
                        *aggr_mask = dst_port_info->aggr_plen;
                        *fat_flow_mask = VR_FAT_FLOW_SRC_PORT_MASK;
                        return 1;
                    }
                }
            }
            if (src_port_info) {
                if (rule_type == PREFIX_RULE_TYPE_SINGLE_PREFIX) {
                    *aggr_mask = src_port_info->aggr_plen;
                    *fat_flow_mask = VR_FAT_FLOW_DST_PORT_MASK;
                    if (src_port_info->rule_type & PREFIX_RULE_HAS_IGNORE_SRC) {
                        *fat_flow_mask |= VR_FAT_FLOW_SRC_IP_MASK;
                    }
                    if (src_port_info->rule_type & PREFIX_RULE_HAS_IGNORE_DST) {
                        *fat_flow_mask |= VR_FAT_FLOW_DST_IP_MASK;
                    }
                    return 1;
                } else {
                    if (__vif_fat_flow_ip_prefix_lookup(src_port_info->second_prefix,
                                                        dip, dip6, aggr_mask1)) {
                        *aggr_mask = src_port_info->aggr_plen;
                        *fat_flow_mask = VR_FAT_FLOW_DST_PORT_MASK;
                        return 1;
                    }
                }
            }
        }
        if (zero_port_info) {
            if (rule_type == PREFIX_RULE_TYPE_SINGLE_PREFIX) {
                *aggr_mask = zero_port_info->aggr_plen;
                *fat_flow_mask =
                      (VR_FAT_FLOW_DST_PORT_MASK | VR_FAT_FLOW_SRC_PORT_MASK);
                if (zero_port_info->rule_type & PREFIX_RULE_HAS_IGNORE_SRC) {
                    *fat_flow_mask |= VR_FAT_FLOW_SRC_IP_MASK;
                }
                if (zero_port_info->rule_type & PREFIX_RULE_HAS_IGNORE_DST) {
                    *fat_flow_mask |= VR_FAT_FLOW_DST_IP_MASK;
                }
                return 1;
            } else {
                if (__vif_fat_flow_ip_prefix_lookup(zero_port_info->second_prefix,
                                                    dip, dip6, aggr_mask1)) {
                    *aggr_mask = zero_port_info->aggr_plen;
                    *fat_flow_mask =
                           (VR_FAT_FLOW_DST_PORT_MASK | VR_FAT_FLOW_SRC_PORT_MASK);
                    return 1;
                }
            }
        }
    }
    return 0;
}

static uint16_t
vif_fat_flow_prefix_rule_match(int incoming_vif, struct vr_interface *vif, uint8_t proto,
                 uint16_t sport, uint16_t dport, unsigned int *saddr, unsigned int *daddr,
                 unsigned char *ip6_src, unsigned char *ip6_dst)
{
    unsigned int *sip_flow = (incoming_vif? saddr: daddr);
    unsigned int *dip_flow = (incoming_vif? daddr: saddr);
    uint16_t *sport_flow = &sport;
    uint16_t *dport_flow = &dport;
    unsigned char *sip6_flow = (incoming_vif? ip6_src: ip6_dst);
    unsigned char *dip6_flow = (incoming_vif? ip6_dst: ip6_src);
    struct vr_route_req  vr_req = { { 0, 0} };
    uint64_t prefix[2];
    vr_fat_flow_prefix_rule_data_t *rdata_src = NULL,
                                   *rdata_dst = NULL;
    struct ip_mtrie *mtrie_src, *mtrie_dst;
    uint16_t fat_flow_mask = 0;
    uint8_t aggr_mask, aggr_mask1;
    uint64_t *ip6_h = NULL, *ip6_l = NULL, ip6_mask_h, ip6_mask_l;

    /* Lookup with srcip first */
    if (saddr) {
        vr_req.rtr_req.rtr_family = AF_INET;
        vr_req.rtr_req.rtr_prefix_size = 4;
        vr_req.rtr_req.rtr_prefix_len = 32;
        mtrie_src = vif->vif_fat_flow_v4_src_prefix_rules;
        mtrie_dst = vif->vif_fat_flow_v4_dst_prefix_rules;
        prefix[0] = (uint64_t) *sip_flow;
        prefix[1] = 0;
    } else {
        vr_req.rtr_req.rtr_family = AF_INET6;
        vr_req.rtr_req.rtr_prefix_size = 16;
        vr_req.rtr_req.rtr_prefix_len = 128;
        mtrie_src = vif->vif_fat_flow_v6_src_prefix_rules;
        mtrie_dst = vif->vif_fat_flow_v6_dst_prefix_rules;
        prefix[0] = *((uint64_t *)sip6_flow);
        prefix[1] = *((uint64_t *)((uint8_t *)sip6_flow+8));
        ip6_h = (uint64_t *) sip6_flow;
        ip6_l = (uint64_t *)((uint8_t *)sip6_flow+8);
    }

    vr_req.rtr_req.rtr_prefix = (int8_t *)prefix;
    rdata_src = vdata_mtrie_lookup(mtrie_src, &vr_req);
    if (rdata_src && (vr_req.rtr_req.rtr_prefix_len != 0)) {

        if (vif_fat_flow_prefix_proto_port_match(PREFIX_RULE_TYPE_SINGLE_PREFIX,
                                                 incoming_vif, rdata_src, NULL,
                                                 NULL, proto, *sport_flow,
                                                 *dport_flow, &aggr_mask, NULL,
                                                 &fat_flow_mask)) {
            if (saddr) {
                *sip_flow = (*sip_flow) & FAT_FLOW_IPV4_PLEN_TO_MASK(aggr_mask);
            } else {
                fat_flow_ipv6_plen_to_mask(aggr_mask, &ip6_mask_h, &ip6_mask_l);
                *ip6_h = (*ip6_h) & ip6_mask_h;
                *ip6_l = (*ip6_l) & ip6_mask_l;
            }
            return fat_flow_mask;
        }
    } else {
        /* reset rdata_src */
        rdata_src = NULL;
    }

    /* Lookup with dstip now */
    if (daddr) {
        prefix[0] = (uint64_t) *dip_flow;
        prefix[1] = 0;
        vr_req.rtr_req.rtr_prefix_len = 32;
    } else {
        prefix[0] = *((uint64_t *)dip6_flow);
        prefix[1] = *((uint64_t *)((uint8_t *)dip6_flow+8));
        vr_req.rtr_req.rtr_prefix_len = 128;
        ip6_h = (uint64_t *)dip6_flow;
        ip6_l = (uint64_t *)((uint8_t *)dip6_flow+8);
    }
    vr_req.rtr_req.rtr_prefix = (int8_t *)prefix;
    rdata_dst = vdata_mtrie_lookup(mtrie_dst, &vr_req);

    if (rdata_dst && (vr_req.rtr_req.rtr_prefix_len != 0)) {
        if (vif_fat_flow_prefix_proto_port_match(PREFIX_RULE_TYPE_SINGLE_PREFIX,
                                                 incoming_vif, rdata_dst, NULL,
                                                 NULL, proto, *sport_flow,
                                                 *dport_flow, &aggr_mask, NULL,
                                                 &fat_flow_mask)) {
            if (daddr) {
                *dip_flow = (*dip_flow) & FAT_FLOW_IPV4_PLEN_TO_MASK(aggr_mask);
            } else {
                fat_flow_ipv6_plen_to_mask(aggr_mask, &ip6_mask_h, &ip6_mask_l);
                *ip6_h = (*ip6_h) & ip6_mask_h;
                *ip6_l = (*ip6_l) & ip6_mask_l;
            }
            return fat_flow_mask;
        }
    }

    /* Check for src+dst rule now */
    if (rdata_src) {
        if (vif_fat_flow_prefix_proto_port_match(PREFIX_RULE_TYPE_DUAL_PREFIX,
                                                 incoming_vif, rdata_src,
                                                 dip_flow, dip6_flow, proto,
                                                 *sport_flow, *dport_flow,
                                                 &aggr_mask, &aggr_mask1,
                                                 &fat_flow_mask)) {
            if (saddr) {
                *sip_flow = (*sip_flow) & FAT_FLOW_IPV4_PLEN_TO_MASK(aggr_mask);
            } else {
                fat_flow_ipv6_plen_to_mask(aggr_mask, &ip6_mask_h, &ip6_mask_l);
                ip6_h = (uint64_t *) sip6_flow;
                ip6_l = (uint64_t *)((uint8_t *)sip6_flow+8);
                *ip6_h = (*ip6_h) & ip6_mask_h;
                *ip6_l = (*ip6_l) & ip6_mask_l;
            }
            if (daddr) {
                *dip_flow = (*dip_flow) & FAT_FLOW_IPV4_PLEN_TO_MASK(aggr_mask1);
            } else {
                fat_flow_ipv6_plen_to_mask(aggr_mask1, &ip6_mask_h, &ip6_mask_l);
                ip6_h = (uint64_t *)dip6_flow;
                ip6_l = (uint64_t *)((uint8_t *)dip6_flow+8);
                *ip6_h = (*ip6_h) & ip6_mask_h;
                *ip6_l = (*ip6_l) & ip6_mask_l;
            }
            return fat_flow_mask;
        }
    }
    return fat_flow_mask;
}


uint16_t
vif_fat_flow_lookup(int incoming_vif, struct vr_interface *vif, uint8_t proto,
        uint16_t sport, uint16_t dport, unsigned int *saddr, unsigned int *daddr,
        unsigned char *ip6_src, unsigned char *ip6_dst)
{
    uint8_t fat_flow_mask = 0, sport_mask = 0, dport_mask = 0;
    uint16_t h_sport, h_dport;
    unsigned int proto_index;

    /* Check if the IPs belong to exclude list, if so return NO_MASK */
    if (vif_fat_flow_exclude_list_lookup(vif, saddr, daddr, ip6_src, ip6_dst)) {
        return fat_flow_mask;
    }

    proto_index = vif_fat_flow_get_proto_index(proto);
    if (!vif->fat_flow_num_rules[proto_index])
        return fat_flow_mask;

    if (proto_index == VIF_FAT_FLOW_NOPROTO_INDEX) {
        /*
         * Both ICMPv6 and ICMP rules are stored with proto 1,
         * hence override in case of ICMPv6
         */
        if (proto == VR_IP_PROTO_ICMP6) {
            proto = VR_IP_PROTO_ICMP;
        }
        h_sport = h_dport = proto;
    } else {
        h_sport = ntohs(sport);
        h_dport = ntohs(dport);
    }

    /*
     * If there is a specific port configuration exists - it takes
     * precedence
     * If both ports have configuration - smallest port takes precedence
     * If no specific port configuration exists, but port "0"
     * configuration exists, use that as fat flow config
     */
    sport_mask = vif_fat_flow_port_get(vif, proto_index, h_sport);
    dport_mask = vif_fat_flow_port_get(vif, proto_index, h_dport);

    if (sport_mask || dport_mask) {
        if (sport_mask && dport_mask) {
            if (proto_index != VIF_FAT_FLOW_NOPROTO_INDEX) {
                if (h_dport <= h_sport)
                    sport_mask = 0;
                else
                    dport_mask = 0;
            }
        }
    } else {
        sport_mask = vif_fat_flow_port_get(vif, proto_index, 0);
        if (sport_mask) {
            fat_flow_mask |= (VR_FAT_FLOW_DST_PORT_MASK |
                        VR_FAT_FLOW_SRC_PORT_MASK);
        }
    }

    if (sport_mask == VIF_FAT_FLOW_PORT_SET)
        fat_flow_mask |= VR_FAT_FLOW_DST_PORT_MASK;

    if (dport_mask == VIF_FAT_FLOW_PORT_SET)
        fat_flow_mask |= VR_FAT_FLOW_SRC_PORT_MASK;

    if (sport_mask == VIF_FAT_FLOW_PORT_SIP_IGNORE)
        fat_flow_mask |= (VR_FAT_FLOW_SRC_IP_MASK | VR_FAT_FLOW_DST_PORT_MASK);

    if (sport_mask == VIF_FAT_FLOW_PORT_DIP_IGNORE)
        fat_flow_mask |= (VR_FAT_FLOW_DST_IP_MASK | VR_FAT_FLOW_DST_PORT_MASK);

    if (dport_mask == VIF_FAT_FLOW_PORT_SIP_IGNORE)
        fat_flow_mask |= (VR_FAT_FLOW_SRC_IP_MASK | VR_FAT_FLOW_SRC_PORT_MASK);

    if (dport_mask == VIF_FAT_FLOW_PORT_DIP_IGNORE)
        fat_flow_mask |= (VR_FAT_FLOW_DST_IP_MASK | VR_FAT_FLOW_SRC_PORT_MASK);

    if (fat_flow_mask) {
        return fat_flow_mask;
    }

    /* Check prefix aggregation rules to see if there is a match there */
    return vif_fat_flow_prefix_rule_match(incoming_vif, vif, proto,
                                          h_sport, h_dport, saddr, daddr,
                                          ip6_src, ip6_dst);
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
    req->vifr_mcast_vrf = 65535;
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
        router->vr_max_interfaces = vr_interfaces;
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
