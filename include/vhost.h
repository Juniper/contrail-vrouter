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

#ifdef __KERNEL__
struct vhost_priv {
    struct net_device *vp_dev;
    struct vrouter *vp_router;
    struct vr_interface *vp_vifp;
};

#endif /* __KERNEL__ */

#ifdef __cplusplus
}
#endif
#endif /* __VHOST_H__ */
