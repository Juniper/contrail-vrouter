/*
 * vr_interface.c -- router interface management
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include "vr_message.h"
#include "vr_sandesh.h"
#include "vr_mirror.h"

static struct vr_host_interface_ops *hif_ops;

static int eth_srx(struct vr_interface *, struct vr_packet *, unsigned short);
static int eth_rx(struct vr_interface *, struct vr_packet *, unsigned short);

extern struct vr_host_interface_ops *vr_host_interface_init(void);
extern void  vr_host_interface_exit(void);
extern unsigned int vr_l3_input(unsigned short, struct vr_packet *, 
                                              struct vr_forwarding_md *);
extern unsigned int vr_l2_input(unsigned short, struct vr_packet *, 
                                               struct vr_forwarding_md *);

#define MINIMUM(a, b) (((a) < (b)) ? (a) : (b))

static inline struct vr_interface_stats *
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
 * vr_interface_input() is invoked if a packet ingresses an interface. 
 * This function demultiplexes the packet to right input 
 * function depending on the protocols enabled on the VIF
 */
static unsigned int
vr_interface_input(unsigned short vrf, struct vr_interface *vif, struct vr_packet *pkt)
{
    struct vr_forwarding_md fmd;
    unsigned int ret;

    vr_init_forwarding_md(&fmd);

    if (vif->vif_flags & VIF_FLAG_MIRROR_RX) {
        fmd.fmd_dvrf = vif->vif_vrf;
        vr_mirror(vif->vif_router, vif->vif_mirror_id, pkt, &fmd);
    }

    if (vif->vif_flags & VIF_FLAG_L3_ENABLED) {
        ret = vr_l3_input(vrf, pkt, &fmd);
        if (ret != PKT_RET_FALLBACK_BRIDGING)
            return ret;
    }

    if (vif->vif_flags & VIF_FLAG_L2_ENABLED)
        return vr_l2_input(vrf, pkt, &fmd);

    vif_drop_pkt(vif, pkt, 1);
    return 0;
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
        vif->vif_vrf_table = vr_malloc(sizeof(short) *
                VIF_VRF_TABLE_ENTRIES);
        if (!vif->vif_vrf_table)
            return -ENOMEM;

        for (i = 0; i < VIF_VRF_TABLE_ENTRIES; i++)
            vif->vif_vrf_table[i] = -1;

        /* for the new table, there are no users */
        vif->vif_vrf_table_users = 0;
    }

    vif->vif_rx = eth_srx;

    return 0;
}


static void
vr_interface_service_disable(struct vr_interface *vif)
{
    vif->vif_rx = eth_rx;

    /*
     * once everybody sees the change, we are free to do whatever
     * we want with the vrf assign table
     */
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
        vr_interface_input(ntohs(hdr->hdr_vrf), agent_vif, pkt);
    } else {
        vif = __vrouter_get_interface(vrouter_get(0), ntohs(hdr->hdr_ifindex));
        if (!vif) {
            stats->vis_ierrors++;
            vr_pfree(pkt, VP_DROP_INVALID_IF);
            return 0;
        }

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

    vr_preset(pkt);

    if (pkt_head_space(pkt) < AGENT_PKT_HEAD_SPACE) {
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

    hdr = (struct agent_hdr *)pkt_push(pkt, sizeof(struct agent_hdr));
    if (!hdr)
        goto drop;

    hdr->hdr_ifindex = htons(pkt->vp_if->vif_idx);
    hdr->hdr_vrf = htons(params->trap_vrf);
    hdr->hdr_cmd = htons(params->trap_reason);

    switch (params->trap_reason) {
    case AGENT_TRAP_FLOW_MISS:
    case AGENT_TRAP_ECMP_RESOLVE:
    case AGENT_TRAP_SOURCE_MISMATCH:
        if (params->trap_param)
            hdr->hdr_cmd_param = htonl(*(unsigned int *)(params->trap_param));
        break;

    case AGENT_TRAP_DIAG:
        if (params->trap_param)
            hdr->hdr_cmd_param = htonl(*(unsigned int *)(params->trap_param));
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
    return hif_ops->hif_del(vif);
}

static int
agent_drv_add(struct vr_interface *vif)
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

    return vr_interface_input(vif->vif_vrf, vif, pkt);
}

static int
vhost_tx(struct vr_interface *vif, struct vr_packet *pkt)
{
    int ret;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    stats->vis_obytes += pkt_len(pkt);
    stats->vis_opackets++;

    if (vif->vif_type == VIF_TYPE_XEN_LL_HOST)
        memcpy(pkt_data(pkt), vif->vif_mac, sizeof(vif->vif_mac));

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
    return hif_ops->hif_del(vif);
}

static int
vhost_drv_add(struct vr_interface *vif)
{
    if (!vif->vif_os_idx)
        return -EINVAL;

    if (!vif->vif_mtu)
        vif->vif_mtu = 1514;

    vif->vif_set_rewrite = vif_cmn_rewrite;
    vif->vif_tx = vhost_tx;
    vif->vif_rx = vhost_rx;

    return hif_ops->hif_add(vif);
}
/* end vhost driver */

/* eth driver */
static int
eth_srx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id)
{
    unsigned short vrf;
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

    stats->vis_ibytes += pkt_len(pkt);
    stats->vis_ipackets++;

    if (vlan_id >= VIF_VRF_TABLE_ENTRIES)
        vrf = vif->vif_vrf;
    else
        vrf = vif->vif_vrf_table[vlan_id];

    return vr_interface_input(vrf, vif, pkt);
}

static int
eth_rx(struct vr_interface *vif, struct vr_packet *pkt,
        unsigned short vlan_id __attribute__((unused)))
{
    struct vr_interface_stats *stats = vif_get_stats(vif, pkt->vp_cpu);

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

    return vr_interface_input(vif->vif_vrf, vif, pkt);
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
             (vif->vif_type != VIF_TYPE_VIRTUAL)) {
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
    ret = hif_ops->hif_del(vif);
    if (vif->vif_flags & VIF_FLAG_SERVICE_IF)
        vr_interface_service_disable(vif);
    return ret;
}


static int
eth_drv_add(struct vr_interface *vif)
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
    vif->vif_tx = eth_tx;
    vif->vif_rx = eth_rx;

    if (vif->vif_flags & VIF_FLAG_SERVICE_IF) {
        ret = vr_interface_service_enable(vif);
        if (ret)
            goto exit_add;
    }

    ret = hif_ops->hif_add(vif);
    if (ret)
        goto exit_add;

    ret = hif_ops->hif_add_tap(vif);
    if (ret)
        hif_ops->hif_del(vif);

exit_add:
    if (ret)
        if (vif->vif_flags & VIF_FLAG_SERVICE_IF)
            vr_interface_service_disable(vif);

    return ret;
}
/* end eth driver */

static struct vr_interface_driver {
    int     (*drv_add)(struct vr_interface *);
    int     (*drv_change)(struct vr_interface *);
    int     (*drv_delete)(struct vr_interface *);
} drivers[VIF_TYPE_MAX] = {
    [VIF_TYPE_HOST] = {
        .drv_add        =   vhost_drv_add,
        .drv_delete     =   vhost_drv_del,
    },
    [VIF_TYPE_XEN_LL_HOST] = {
        .drv_add        =   vhost_drv_add,
        .drv_delete     =   vhost_drv_del,
    },
    [VIF_TYPE_GATEWAY] = {
        .drv_add        =   vhost_drv_add,
        .drv_delete     =   vhost_drv_del,
    },
    [VIF_TYPE_AGENT] = {
        .drv_add        =   agent_drv_add,
        .drv_delete     =   agent_drv_del,
    },
    [VIF_TYPE_PHYSICAL] = {
        .drv_add        =   eth_drv_add,
        .drv_delete     =   eth_drv_del,
    },
    [VIF_TYPE_VIRTUAL] = {
        .drv_add        =   eth_drv_add,
        .drv_delete     =   eth_drv_del,
    },
};


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
        router->vr_eth_if = NULL;
        if (vif->vif_bridge) {
            vif->vif_bridge->vif_bridge = NULL;
            vif->vif_bridge = NULL;
        }

        break;

    case VIF_TYPE_VIRTUAL:
        break;

    default:
        break;
    }

    vr_delay_op();
    vrouter_put_interface(vif);

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
vrouter_add_interface(struct vr_interface *vif)
{
    struct vrouter *router = vrouter_get(vif->vif_rid);

    if (!router)
        return -ENODEV;

    if (router->vr_interfaces[vif->vif_idx])
        return -EEXIST;

    vif->vif_router = router;
    vif->vif_users++;
    router->vr_interfaces[vif->vif_idx] = vif;

    switch (vif->vif_type) {
    case VIF_TYPE_AGENT:
        router->vr_agent_if = vif;
        break;

    case VIF_TYPE_HOST:
        router->vr_host_if = vif;
        if (router->vr_eth_if) {
            vif->vif_bridge = router->vr_eth_if;
            router->vr_eth_if->vif_bridge = vif;
        }

        break;

    case VIF_TYPE_PHYSICAL:
        router->vr_eth_if = vif;
        if (router->vr_host_if) {
            vif->vif_bridge = router->vr_host_if;
            router->vr_host_if->vif_bridge = vif;
        }

        break;

    default:
        break;
    }

    vrouter_set_rewrite(vif);

    return 0;
}

int
vif_delete(struct vr_interface *vif)
{
    if (drivers[vif->vif_type].drv_delete)
        drivers[vif->vif_type].drv_delete(vif);

    vrouter_del_interface(vif);
    return 0;
}


static int
vr_interface_delete(vr_interface_req *req)
{
    int ret = 0;
    struct vr_interface *vif;
    struct vrouter *router = vrouter_get(req->vifr_rid);

    vif = __vrouter_get_interface(router, req->vifr_idx);
    if (!vif && (ret = -ENODEV))
        goto del_fail;

    vif_delete(vif);
del_fail:
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

    return 0;
}

int
vr_interface_add(vr_interface_req *req)
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
    vif->vif_mtu = req->vifr_mtu;
    vif->vif_idx = req->vifr_idx;
    vif->vif_os_idx = req->vifr_os_idx;
    vif->vif_rid = req->vifr_rid;

    if ((req->vifr_mac_size != sizeof(vif->vif_mac)) || !req->vifr_mac) {
        ret = -EINVAL;
        goto generate_resp;
    }

    memcpy(vif->vif_mac, req->vifr_mac, sizeof(vif->vif_mac));
    memcpy(vif->vif_rewrite, req->vifr_mac, sizeof(vif->vif_mac));
    vif->vif_ip = req->vifr_ip;

    if (req->vifr_name) {
        strncpy((char *)vif->vif_name, req->vifr_name, VR_INTERFACE_NAME_LEN);
        vif->vif_name[VR_INTERFACE_NAME_LEN - 1] = '\0';
    }

    /*
     * the order below is probably not intuitive, but we do this because
     * the moment we do a drv_add, packets will start coming in and find
     * that vif_router is not set. to avoid checks such as !vif_router in
     * datapath, the order has to be what is below.
     */
    ret = vrouter_add_interface(vif);
    if (ret)
        goto generate_resp;

    if (drivers[vif->vif_type].drv_add) {
        ret = drivers[vif->vif_type].drv_add(vif);
        if (ret) {
            vrouter_del_interface(vif);
            vif = NULL;
        }
    }


generate_resp:
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

    return req;
}


static void
vr_interface_req_destroy(vr_interface_req *req)
{
    if (!req)
        return;

    if (req->vifr_mac)
        vr_free(req->vifr_mac);

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

    switch (req->h_op) {
    case SANDESH_OP_ADD:
        ret = vr_interface_add(req);
        break;

    case SANDESH_OP_GET:
        ret = vr_interface_get(req);
        break;

    case SANDESH_OP_DELETE:
        ret = vr_interface_delete(req);
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

int
vif_vrf_table_get(struct vr_interface *vif, vr_vrf_assign_req *req)
{
    if (!(vif->vif_flags & VIF_FLAG_SERVICE_IF))
        return -EINVAL;

    if (!vif->vif_vrf_table)
        return -ENOMEM;

    if (req->var_vlan_id >= VIF_VRF_TABLE_ENTRIES)
        return -EINVAL;

    req->var_vif_vrf = vif->vif_vrf_table[req->var_vlan_id];
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
        short vrf)
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
        if (!(vif->vif_flags & VIF_FLAG_SERVICE_IF)) {
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
    if (vif->vif_vrf_table[vlan] < 0) {
        if (vrf >= 0)
            vif->vif_vrf_table_users++;
    } else {
        if (vrf < 0)
            vif->vif_vrf_table_users--;
    }

    vif->vif_vrf_table[vlan] = vrf;

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
            vif->vif_flags = 0;
            if (drivers[vif->vif_type].drv_delete)
                drivers[vif->vif_type].drv_delete(vif);
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


    if (!soft_reset && hif_ops) {
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

    return 0;

cleanup:
    if (router->vr_interfaces) {
        vr_free(router->vr_interfaces);
        router->vr_interfaces = NULL;
        router->vr_max_interfaces = 0;
    }

    return ret;
}

