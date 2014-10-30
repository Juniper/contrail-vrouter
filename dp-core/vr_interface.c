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

volatile bool agent_alive = false;

static struct vr_host_interface_ops *hif_ops;

static int vm_srx(struct vr_interface *, struct vr_packet *, unsigned short);
static int vm_rx(struct vr_interface *, struct vr_packet *, unsigned short);
static int eth_rx(struct vr_interface *, struct vr_packet *, unsigned short);

void vif_attach(struct vr_interface *);
void vif_detach(struct vr_interface *);
int vr_gro_vif_add(struct vrouter *, unsigned int, char *);
struct vr_interface_stats *vif_get_stats(struct vr_interface *, unsigned short);
struct vr_interface *__vrouter_get_interface_os(struct vrouter *, unsigned int);

extern struct vr_host_interface_ops *vr_host_interface_init(void);
extern void  vr_host_interface_exit(void);
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
vif_discard_tx(struct vr_interface *vif, struct vr_packet *pkt)
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
        unsigned char *rewrite, unsigned short len)
{
    unsigned char *head;

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
                VIF_VRF_TABLE_ENTRIES);
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
        vr_free(vif->vif_vrf_table);
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
vif_xconnect(struct vr_interface *vif, struct vr_packet *pkt)
{
    struct vr_interface *bridge;
    
    if (!vif)
        goto free_pkt;

    bridge = vif->vif_bridge;
    if (bridge) {
        vr_preset(pkt);
        return bridge->vif_tx(bridge, pkt);
    }

free_pkt:
    if (vif)
        vif_drop_pkt(vif, pkt, 1);
    return 0;
}

/* agent driver */
#define AGENT_PKT_HEAD_SPACE (sizeof(struct vr_eth) + \
        sizeof(struct agent_hdr))

static unsigned char *
agent_set_rewrite(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned char *rewrite, unsigned short len)
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
    hdr->hdr_vrf = htons(pkt->vp_if->vif_vrf);
    /* this needs some thought */
    hdr->hdr_cmd = htons(AGENT_TRAP_NEXTHOP);
    hdr->hdr_cmd_param = 0;

    return head;
}

static int
agent_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id __attribute__((unused)))
{
    struct agent_hdr *hdr;
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
    if (ntohs(hdr->hdr_cmd) & AGENT_CMD_ROUTE) {
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
        vr_virtual_input(ntohs(hdr->hdr_vrf), agent_vif, pkt, VLAN_ID_INVALID);
    } else {
        vif = __vrouter_get_interface(vrouter_get(0), ntohs(hdr->hdr_ifindex));
        if (!vif) {
            stats->vis_ierrors++;
            vr_pfree(pkt, VP_DROP_INVALID_IF);
            return 0;
        }

        pkt->vp_type = VP_TYPE_AGENT;
        pkt_set_network_header(pkt, pkt->vp_data + sizeof(struct vr_eth));
        pkt_set_inner_network_header(pkt, 
                                     pkt->vp_data + sizeof(struct vr_eth));
        return vif->vif_tx(vif, pkt);
    }

    return 0;
}

static int
agent_tx(struct vr_interface *vif, struct vr_packet *pkt)
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
    case AGENT_TRAP_ECMP_RESOLVE:
    case AGENT_TRAP_HANDLE_DF:
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
    int len;
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

    if (params->trap_reason == AGENT_TRAP_HANDLE_DF) {
        if (pkt_len(pkt) > VR_AGENT_MIN_PACKET_LEN)
            truncate = true;
    }

    if (truncate || pkt_head_space(pkt) < AGENT_PKT_HEAD_SPACE) {
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
        if (params->trap_param) {
            fta = (struct vr_flow_trap_arg *)(params->trap_param);
            hdr->hdr_cmd_param = htonl(fta->vfta_index);
            hdr->hdr_cmd_param_1 = htonl(fta->vfta_nh_index);
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
        break;
    }

    rewrite = pkt_push(pkt, VR_ETHER_HLEN);
    if (!rewrite)
        goto drop;

    memcpy(rewrite, vif->vif_rewrite, VR_ETHER_HLEN);

    return vif->vif_tx(vif, pkt);

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
    vif->vif_tx = agent_tx;
    vif->vif_rx = agent_rx;
    vif->vif_send = agent_send;

    ret = hif_ops->hif_add(vif);
    if (ret) {
        return ret;
    }

    ret = hif_ops->hif_add_tap(vif);
    if (ret)
        hif_ops->hif_del(vif);

    return ret;
}
/* end agent driver */

/* vhost driver */
static int
vhost_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id __attribute__((unused)))
{
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    /* please see the text on xconnect mode */
    if (vif_mode_xconnect(vif))
        return vif_xconnect(vif, pkt);

    return vr_fabric_input(vif, pkt, vlan_id);
}

static int
vhost_tx(struct vr_interface *vif, struct vr_packet *pkt)
{
    int ret;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);
    unsigned short eth_proto, pull_len = 0;
    unsigned char *new_eth, *eth;
    struct vr_vlan_hdr *vlan;


    stats->vis_obytes += pkt_len(pkt);
    stats->vis_opackets++;

    if (vif->vif_type == VIF_TYPE_XEN_LL_HOST)
        memcpy(pkt_data(pkt), vif->vif_mac, sizeof(vif->vif_mac));
    else if (vif->vif_type == VIF_TYPE_HOST) {

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

    if (!vif->vif_os_idx)
        return -EINVAL;

    if (!vif->vif_mtu)
        vif->vif_mtu = 1514;

    vif->vif_set_rewrite = vif_cmn_rewrite;
    vif->vif_tx = vhost_tx;
    vif->vif_rx = vhost_rx;

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
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    pkt->vp_if = vif;

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    if (vr_untag_pkt(pkt)) {
        stats->vis_ierrors++;
        vr_pfree(pkt, VP_DROP_PULL);
        return 0;
    }

    vr_pset_data(pkt, pkt->vp_data);

    return vr_virtual_input(vif->vif_vrf, vif, pkt, VLAN_ID_INVALID);
}


static int
vlan_tx(struct vr_interface *vif, struct vr_packet *pkt)
{
    int ret = 0;
    struct vr_interface *pvif;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    stats->vis_obytes += pkt_len(pkt);
    stats->vis_opackets++;

    if (vif_is_vlan(vif) && vif->vif_ovlan_id) {
        if (vr_tag_pkt(pkt, vif->vif_ovlan_id)) {
            goto drop;
        }
        vr_pset_data(pkt, pkt->vp_data);
    }


    pvif = vif->vif_parent;
    if (!pvif)
        goto drop;

    pkt->vp_if = pvif;

    ret = pvif->vif_tx(pvif, pkt);
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
    struct vr_interface *pvif;

    pvif = vif->vif_parent;
    if (!pvif)
        return 0;

    if (pvif->vif_driver->drv_delete_sub_interface)
        pvif->vif_driver->drv_delete_sub_interface(pvif, vif);

    return 0;
}

static int
vlan_drv_add(struct vr_interface *vif, vr_interface_req *vifr)
{
    int ret;
    struct vr_interface *pvif = NULL;

    if ((unsigned int)(vifr->vifr_parent_vif_idx) > VR_MAX_INTERFACES)
        return -EINVAL;

    if (((unsigned short)(vifr->vifr_vlan_id) >= VLAN_ID_MAX) ||
            ((unsigned short)(vifr->vifr_ovlan_id) >= VLAN_ID_MAX))
        return -EINVAL;

    if (vifr->vifr_src_mac_size && vifr->vifr_src_mac) {
        if (vifr->vifr_src_mac_size != VR_ETHER_ALEN)
            return -EINVAL;

        vif->vif_src_mac = vr_malloc(VR_ETHER_ALEN);
        if (!vif->vif_src_mac)
            return -ENOMEM;

        memcpy(vif->vif_src_mac, vifr->vifr_src_mac, VR_ETHER_ALEN);
    }

    if (!vif->vif_mtu)
        vif->vif_mtu = 1514;

    vif->vif_set_rewrite = vif_cmn_rewrite;
    vif->vif_tx = vlan_tx;
    vif->vif_rx = vlan_rx;
    vif->vif_vlan_id = vifr->vifr_vlan_id;
    vif->vif_ovlan_id = vifr->vifr_ovlan_id;

    pvif = vrouter_get_interface(vifr->vifr_rid, vifr->vifr_parent_vif_idx);
    if (!pvif)
        return -EINVAL;

    vif->vif_parent = pvif;

    if (!pvif->vif_driver->drv_add_sub_interface) {
        ret = -EINVAL;
        goto add_fail;
    }

    ret = pvif->vif_driver->drv_add_sub_interface(pvif, vif);
    if (ret)
        goto add_fail;

    return 0;

add_fail:
    if (pvif) {
        vif->vif_parent = NULL;
        vrouter_put_interface(pvif);
    }

    return ret;
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

static int
vm_rx(struct vr_interface *vif, struct vr_packet *pkt,
      unsigned short vlan_id)
{
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    return vr_virtual_input(vif->vif_vrf, vif, pkt, vlan_id);
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

    if (vif->vif_flags & VIF_FLAG_NATIVE_VLAN_TAG)
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
eth_tx(struct vr_interface *vif, struct vr_packet *pkt)
{
    int ret;
    struct vr_forwarding_md fmd;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    /*
     * GRO packets come here twice - once with VP_FLAG_GRO set and
     * once without the flag set. Don't count them twice.
     */
    if (((pkt->vp_flags & VP_FLAG_GRO) == 0) ||
             (!vif_is_virtual(vif))) {
        stats->vis_obytes += pkt_len(pkt);
        stats->vis_opackets++;
    }

    if (vif->vif_flags & VIF_FLAG_MIRROR_TX) {
        vr_init_forwarding_md(&fmd);
        fmd.fmd_dvrf = vif->vif_vrf;
        vr_mirror(vif->vif_router, vif->vif_mirror_id, pkt, &fmd);
    }
        
    ret = hif_ops->hif_tx(vif, pkt);
    if (ret != 0) {
        ret = 0;
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
    if (vif->vif_src_mac) {
        if (pvif->vif_btable)
            return vif_bridge_delete(pvif, vif);
        return -EINVAL;
    }

    if (!pvif->vif_sub_interfaces)
        return -EINVAL;

    if (pvif->vif_sub_interfaces[vif->vif_vlan_id] != vif)
        return -EINVAL;

    pvif->vif_sub_interfaces[vif->vif_vlan_id] = NULL;
    vrouter_put_interface(pvif);
    vif->vif_parent = NULL;

    return 0;
}

static int
eth_drv_add_sub_interface(struct vr_interface *pvif, struct vr_interface *vif)
{
    int ret;

    if (vif->vif_src_mac) {
        if (!pvif->vif_btable) {
            ret = vif_bridge_init(pvif);
            if (ret)
                return ret;
        }

        return vif_bridge_add(pvif, vif);
    }

    if (!pvif->vif_sub_interfaces) {
        pvif->vif_sub_interfaces = vr_zalloc(VLAN_ID_MAX *
                sizeof(struct vr_interface *));
        if (!pvif->vif_sub_interfaces)
            return -ENOMEM;
        /* 
         * we are not going to free this memory, since it is not guaranteed
         * that we will get contiguous memory. so hold on to it for the life
         * time of the interface
         */
    }

    pvif->vif_sub_interfaces[vif->vif_vlan_id] = vif;

    return 0;
}

static int
eth_drv_add(struct vr_interface *vif,
        vr_interface_req *vifr __attribute__((unused)))
{
    int ret = 0;

    if (!vif->vif_os_idx)
        return -EINVAL;

    if (!vif->vif_mtu) {
        vif->vif_mtu = 9160;
        if (vif->vif_type == VIF_TYPE_PHYSICAL)
            vif->vif_mtu = 1514;
    }

    vif->vif_set_rewrite = vif_cmn_rewrite;

    if (vif->vif_type != VIF_TYPE_STATS) {
        vif->vif_tx = eth_tx;
        if (vif_is_virtual(vif))
            vif->vif_rx = vm_rx;
        else
            vif->vif_rx = eth_rx;
    }

    if (vif->vif_flags & VIF_FLAG_SERVICE_IF) {
        ret = vr_interface_service_enable(vif);
        if (ret)
            goto exit_add;
    }

    ret = hif_ops->hif_add(vif);
    if (ret)
        goto exit_add;

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
    },
    [VIF_TYPE_VIRTUAL_VLAN] = {
        .drv_add                    =   vlan_drv_add,
        .drv_delete                 =   vlan_drv_del,
    },
    [VIF_TYPE_STATS] = {
        .drv_add        =   eth_drv_add,
        .drv_delete     =   eth_drv_del,
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
    if (!vif)
        return;

    if (vif->vif_stats)
        vr_free(vif->vif_stats);

    if (vif->vif_vrf_table) {
        vr_free(vif->vif_vrf_table);
        vif->vif_vrf_table = NULL;
    }

    if (vif->vif_sub_interfaces) {
        vr_free(vif->vif_sub_interfaces);
        vif->vif_sub_interfaces = NULL;
    }

    if (vif->vif_btable) {
        vif_bridge_deinit(vif);
    }

    vr_free(vif);

    return;
}

void
vrouter_put_interface(struct vr_interface *vif)
{
    if (!--vif->vif_users)
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
    vif->vif_flags = req->vifr_flags;

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

    return 0;
}

int
vr_interface_add(vr_interface_req *req, bool need_response)
{
    int ret;
    struct vr_interface *vif = NULL;
    struct vrouter *router = vrouter_get(req->vifr_rid);

    if (!router || ((unsigned int)req->vifr_idx >= router->vr_max_interfaces)) {
        ret = -EINVAL;
        goto generate_resp;
    }

    if (req->vifr_type >= VIF_TYPE_MAX && (ret = -EINVAL))
        goto generate_resp;

    vif = __vrouter_get_interface(router, req->vifr_idx);
    if (vif) {
        ret = vr_interface_change(vif, req);
        goto generate_resp;
    }

    vif = vr_zalloc(sizeof(*vif));
    if (!vif) {
        ret = -ENOMEM;
        goto generate_resp;
    }

    vif->vif_stats = vr_zalloc(vr_num_cpus *
            sizeof(struct vr_interface_stats));
    if (!vif->vif_stats) {
        ret = -ENOMEM;
        goto generate_resp;
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
    vif->vif_os_idx = req->vifr_os_idx;
    vif->vif_rid = req->vifr_rid;
    vif->vif_nh_id = (unsigned short)req->vifr_nh_id;

    if ((req->vifr_mac_size != sizeof(vif->vif_mac)) || !req->vifr_mac) {
        ret = -EINVAL;
        goto generate_resp;
    }

    memcpy(vif->vif_mac, req->vifr_mac, sizeof(vif->vif_mac));
    memcpy(vif->vif_rewrite, req->vifr_mac, sizeof(vif->vif_mac));

    vif->vif_ip = req->vifr_ip;

    if (req->vifr_name) {
        strncpy(vif->vif_name, req->vifr_name, sizeof(vif->vif_name));
        vif->vif_name[sizeof(vif->vif_name) - 1] = '\0';
    }

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
vr_interface_make_req(vr_interface_req *req, struct vr_interface *intf)
{
    unsigned int i;
    struct vr_interface_stats *stats;
    struct vr_interface_settings settings;

    req->vifr_type = intf->vif_type;
    req->vifr_flags = intf->vif_flags;
    req->vifr_vrf = intf->vif_vrf;
    req->vifr_idx = intf->vif_idx;
    req->vifr_rid = intf->vif_rid;
    req->vifr_os_idx = intf->vif_os_idx;
    req->vifr_mtu = intf->vif_mtu;
    if (req->vifr_mac_size && req->vifr_mac)
        memcpy(req->vifr_mac, intf->vif_mac,
                MINIMUM(req->vifr_mac_size, sizeof(intf->vif_mac)));
    req->vifr_ip = intf->vif_ip;

    req->vifr_ref_cnt = intf->vif_users;

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

    req->vifr_ibytes = 0;
    req->vifr_ipackets = 0;
    req->vifr_ierrors = 0;
    req->vifr_obytes = 0;
    req->vifr_opackets = 0;
    req->vifr_oerrors = 0;

    for (i = 0; i < vr_num_cpus; i++) {
        stats = vif_get_stats(intf, i);
        req->vifr_ibytes += stats->vis_ibytes;
        req->vifr_ipackets += stats->vis_ipackets;
        req->vifr_ierrors += stats->vis_ierrors;
        req->vifr_obytes += stats->vis_obytes;
        req->vifr_opackets += stats->vis_opackets;
        req->vifr_oerrors += stats->vis_oerrors;
    }

    req->vifr_speed = -1;
    req->vifr_duplex = -1;
    if (intf->vif_type == VIF_TYPE_PHYSICAL) {
        if (!hif_ops->hif_get_settings(intf, &settings)) {
            req->vifr_speed = settings.vis_speed;
            req->vifr_duplex = settings.vis_duplex;
        }
    }

    return;
}

static vr_interface_req *
vr_interface_req_get(void)
{
    vr_interface_req *req;

    req = vr_zalloc(sizeof(*req));
    if (!req)
        return req;

    req->vifr_mac = vr_zalloc(VR_ETHER_ALEN);
    if (req->vifr_mac)
        req->vifr_mac_size = VR_ETHER_ALEN;

    req->vifr_src_mac = vr_zalloc(VR_ETHER_ALEN);
    if (req->vifr_src_mac)
        req->vifr_src_mac_size = 0;
    req->vifr_name = vr_zalloc(VR_INTERFACE_NAME_LEN);

    return req;
}


static void
vr_interface_req_destroy(vr_interface_req *req)
{
    if (!req)
        return;

    if (req->vifr_mac) {
        vr_free(req->vifr_mac);
        req->vifr_mac_size = 0;
    }

    if (req->vifr_src_mac) {
        vr_free(req->vifr_src_mac);
        req->vifr_src_mac_size = 0;
    }

    if (req->vifr_name)
        vr_free(req->vifr_name);

    vr_free(req);
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

        vr_interface_make_req(resp, vif);
    } else
        ret = -ENOENT;

generate_response:
    vr_message_response(VR_INTERFACE_OBJECT_ID, resp, ret);
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
            vr_interface_make_req(resp, vif);
            ret = vr_message_dump_object(dumper, VR_INTERFACE_OBJECT_ID, resp);
            if (ret <= 0)
                break;
        }
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
        short vrf, unsigned short nh_id)
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
        vr_free(vif->vif_vrf_table);
        vif->vif_vrf_table = NULL;
    }

    return 0;
}


int
vr_gro_vif_add(struct vrouter *router, unsigned int os_idx, char *name)
{
    int ret = 0;
    vr_interface_req *req = vr_interface_req_get();

    if (!req)
        return -ENOMEM;

    req->h_op = SANDESH_OP_ADD;
    req->vifr_type = VIF_TYPE_STATS;
    req->vifr_flags = 0;
    req->vifr_vrf = 65535;
    req->vifr_idx = router->vr_max_interfaces - 1;
    req->vifr_rid = 0;
    req->vifr_os_idx = os_idx;
    req->vifr_mtu = 9136;

    if (req->vifr_name) {
        strncpy(req->vifr_name, name, VR_INTERFACE_NAME_LEN);
        req->vifr_name[VR_INTERFACE_NAME_LEN - 1] = '\0';
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
        vr_free(router->vr_interfaces);
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
        router->vr_interfaces = vr_zalloc(table_memory);
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
        vr_free(router->vr_interfaces);
        router->vr_interfaces = NULL;
        router->vr_max_interfaces = 0;
    }

    return ret;
}

