/*
 * vhost.h -- definitions and other things that are useful for everybody ?
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VHOST_H__
#define __VHOST_H__
#ifdef __cplusplus
extern "C" {
#endif

#define VHOST_KIND  "vhost"
#define VHOST_IFNAME "vhost0"

#ifdef __KERNEL__

#define VHOST_MAX_INTERFACES 64

struct vhost_priv {
#if defined(__linux__)
    struct net_device *vp_dev;
#elif defined(__FreeBSD__)
    struct ifnet *vp_ifp;
    struct mtx vp_mtx;
#endif
    struct net_device *vp_phys_dev;
    struct vrouter *vp_router;
    struct vr_interface *vp_vifp;
    int vp_db_index;
    char vp_phys_name[VR_INTERFACE_NAME_LEN];
};

extern void vhost_detach_phys(struct net_device *);
extern void vhost_xconnect(void);
extern void vhost_remove_xconnect(void);
extern void vhost_attach_phys(struct net_device *);
extern struct net_device *vhost_get_vhost_for_phys(struct net_device *);

#endif /* __KERNEL__ */

#ifdef __cplusplus
}
#endif
#endif /* __VHOST_H__ */
