/*
 * vr_dpdk_netlink.h - header for vrouter DPDK netlink infrastructure.
 *
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_DPDK_NETLINK_H__
#define __VR_DPDK_NETLINK_H__

int vr_netlink_uvhost_vif_add(unsigned char *vif_name, unsigned int vif_idx,
                              unsigned int vif_nrxqs, unsigned int vif_ntxqs);
int vr_netlink_uvhost_vif_del(unsigned int vif_idx);

#endif /* __VR_DPDK_NETLINK_H__ */
