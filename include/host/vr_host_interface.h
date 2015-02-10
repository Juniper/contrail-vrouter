/*
 * vr_host_interface.h -- host interface definitions
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __HOST_VR_HOST_INTERFACE_H__
#define __HOST_VR_HOST_INTERFACE_H__

/*
 * has to be a power of 2. increasing this will need some
 * more changes in the sources.
 */
#define HIF_MAX_INTERFACES                  192

#define HIF_SOURCE_UDP_PORT_START           50000

#define HIF_AGENT_UDP_PORT_START            50000
#define HIF_AGENT_INTERFACE_INDEX           0
#define HIF_NUM_AGENT_INTERFACES            1

#define HIF_VHOST_UDP_PORT_START            50005
#define HIF_VHOST_INTERFACE_INDEX           5
#define HIF_NUM_VHOST_INTERFACES            1

#define HIF_PHYSICAL_UDP_PORT_START         50010
#define HIF_PHYSICAL_INTERFACE_INDEX        10
#define HIF_NUM_PHYSICAL_INTERFACES         1

#define HIF_VIRTUAL_UDP_PORT_START          50100
#define HIF_VIRTUAL_INTERFACE_INDEX_START   100
#define HIF_NUM_VIRTUAL_INTERFACES          32

#define HIF_DESTINATION_UDP_PORT_START      60000

#define HIF_TYPE_UDP                        1

struct vr_hpacket;
struct vr_hpacket_pool;
struct vr_interface;

struct vr_hinterface {
    int hif_index;
    int hif_users;
    unsigned int hif_type;
    unsigned int hif_vif_type;
    unsigned int hif_fd;
    struct vr_interface *hif_vif;
    struct vr_hpacket_pool *hif_pkt_pool;
    unsigned int (*hif_tx)(struct vr_hinterface *, struct vr_hpacket *);
    int (*hif_rx)(void *);
};

struct vr_hinterface *hif_table[HIF_MAX_INTERFACES];

struct vr_hinterface *vr_hinterface_create(unsigned int, unsigned int,
                unsigned int);
struct vr_hinterface *vr_hinterface_get(unsigned int);
void vr_hinterface_put(struct vr_hinterface *);
void vr_hinterface_delete(struct vr_hinterface *);




#endif /* __HOST_VR_HOST_INERFACE_H__ */
