/*
 * vr_interface.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_INTERFACE_H__
#define __VR_INTERFACE_H__

#include "vr_defs.h"
#include "vr_types.h"

#define VR_MAX_INTERFACES           256

#define VIF_TYPE_HOST               0
#define VIF_TYPE_AGENT              1
#define VIF_TYPE_PHYSICAL           2
#define VIF_TYPE_VIRTUAL            3
#define VIF_TYPE_XEN_LL_HOST        4
#define VIF_TYPE_GATEWAY            5
#define VIF_TYPE_MAX                6

#define vif_is_tap(vif)             ((vif->vif_type == VIF_TYPE_VIRTUAL) ||\
                                        (vif->vif_type == VIF_TYPE_AGENT))
#define vif_is_vhost(vif)           ((vif->vif_type == VIF_TYPE_HOST) ||\
                                        (vif->vif_type == VIF_TYPE_XEN_LL_HOST) ||\
                                        (vif->vif_type == VIF_TYPE_GATEWAY))

#define VR_INTERFACE_NAME_LEN       64

#define VR_IF_ADD                   0
#define VR_IF_DEL                   1

#define VIF_FLAG_POLICY_ENABLED     0x1
#define VIF_FLAG_XCONNECT           0x2
#define VIF_FLAG_SERVICE_IF         0x4
#define VIF_FLAG_MIRROR_RX          0x8
#define VIF_FLAG_MIRROR_TX          0x10
#define VIF_FLAG_TX_CSUM_OFFLOAD    0x20
#define VIF_FLAG_L3_ENABLED         0x40
#define VIF_FLAG_L2_ENABLED         0x80


#define VIF_VRF_TABLE_ENTRIES       1024
#define VIF_VRF_INVALID             ((unsigned short)-1)

#define vif_mode_xconnect(vif)      (vif->vif_flags & VIF_FLAG_XCONNECT)

struct vr_interface_stats {
    uint64_t vis_ibytes;
    uint64_t vis_ipackets;
    uint64_t vis_ierrors;
    uint64_t vis_obytes;
    uint64_t vis_opackets;
    uint64_t vis_oerrors;
};

struct vr_packet;

struct agent_send_params {
    unsigned short trap_reason;
    unsigned short trap_vrf;
    void *trap_param;
};

struct vr_interface {
    unsigned short vif_type;
    unsigned short vif_vrf;
    unsigned short vif_rid;
    unsigned short vif_mtu;

    unsigned int vif_flags;
    unsigned int vif_idx;
    unsigned int vif_users;
    unsigned int vif_os_idx;

    uint8_t vif_mirror_id;

    struct vrouter *vif_router;
    struct vr_interface *vif_parent;
    struct vr_interface *vif_bridge;
    struct vr_interface_stats *vif_stats;

    unsigned short vif_vrf_table_users;
    /*
     * unsigned short does not cut it, because initial value for
     * each entry in the table is -1. negative value of table
     * entries is also vital for table_users calculation.
     */
    short *vif_vrf_table;

    void *vif_os;
    int (*vif_send)(struct vr_interface *, struct vr_packet *, void *);
    unsigned char *(*vif_set_rewrite)(struct vr_interface *, struct vr_packet *,
            unsigned char *, unsigned short);
    int (*vif_tx)(struct vr_interface *, struct vr_packet *);
    /*
     * we are forced to pass the final argument, vlan id, since linux
     * untags the packet and stores the id in skb member. with no space
     * in vr_packet to add more fields (unless, we delink vr_packet from
     * skb), the only way left is to pass the id as an argument. sucks
     * for sure...
     */
    int (*vif_rx)(struct vr_interface *, struct vr_packet *, unsigned short);

    unsigned char vif_rewrite[VR_ETHER_HLEN];
    unsigned char vif_mac[VR_ETHER_ALEN];
    unsigned char vif_name[VR_INTERFACE_NAME_LEN];
    unsigned int  vif_ip;
#ifdef __KERNEL__
    struct napi_struct vr_napi;
    struct sk_buff_head vr_skb_inputq;
#endif
};

struct vr_interface_settings {
    uint32_t vis_speed;
    uint32_t vis_duplex;
};

struct vr_host_interface_ops {
    int (*hif_add)(struct vr_interface *);
    int (*hif_del)(struct vr_interface *);
    int (*hif_add_tap)(struct vr_interface *);
    int (*hif_del_tap)(struct vr_interface *);
    int (*hif_tx)(struct vr_interface *, struct vr_packet *);
    int (*hif_rx)(struct vr_interface *, struct vr_packet *);
    int (*hif_get_settings)(struct vr_interface *,
            struct vr_interface_settings *);
};

extern int vr_interface_init(struct vrouter *);
extern void vr_interface_exit(struct vrouter *, bool);
extern void vr_interface_shut(struct vrouter *);
extern struct vr_interface *vrouter_get_interface(unsigned int, unsigned int);
extern struct vr_interface *__vrouter_get_interface(struct vrouter *, unsigned int);
extern void vrouter_put_interface(struct vr_interface *);
extern int vr_interface_dump_wrapper(vr_interface_req *);
extern int vr_interface_add(vr_interface_req *);

extern int vif_delete(struct vr_interface *);
extern void vif_set_xconnect(struct vr_interface *);
extern void vif_remove_xconnect(struct vr_interface *);
extern int vif_xconnect(struct vr_interface *, struct vr_packet *);
extern void vif_drop_pkt(struct vr_interface *, struct vr_packet *, bool);
extern int vif_vrf_table_get(struct vr_interface *, vr_vrf_assign_req *);
extern int vif_vrf_table_set(struct vr_interface *, unsigned int, short);

#endif /* __VR_INTERFACE_H__ */
