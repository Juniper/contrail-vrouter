/*
 * vr_offloads.c -- register callbacks for hardware offload features
 *
 * Copyright (c) 2016 Netronome Systems, Inc. All rights reserved.
 */
#include "vr_offloads.h"

int
vr_offload_version(void)
{
    return VR_OFFLOAD_VER;
}
EXPORT_SYMBOL(vr_offload_version);

/*
 * Called by offload module to register itself with vrouter.
 */
int
vr_offload_register(int version, const struct vr_offload_ops *new_handler)
{

    struct vr_offload_ops *offload =
       rcu_dereference(offload_ops);

    if (version != VR_OFFLOAD_VER)
        return -EINVAL;

    if (offload)
        return -EBUSY;
    offload = kmalloc(sizeof(*offload), GFP_KERNEL);
    if (!offload)
        return -ENOMEM;
    *offload = *new_handler;

    rcu_assign_pointer(offload_ops, offload);
    return 0;
}
EXPORT_SYMBOL(vr_offload_register);

/*
 * Called by offload module to unregister itself with vrouter.
 */
int
vr_offload_unregister()
{
    struct vr_offload_ops *offload =
       rcu_dereference(offload_ops);

    if (offload) {
        rcu_assign_pointer(offload_ops, NULL);
        kfree(offload);
    }
    return 0;
}
EXPORT_SYMBOL(vr_offload_unregister);

/* Statistics update functions used by offload module */
EXPORT_SYMBOL(vr_flow_incr_stats);
EXPORT_SYMBOL(vr_nexthop_update_offload_vrfstats);
