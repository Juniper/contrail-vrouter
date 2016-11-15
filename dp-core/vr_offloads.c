/*
 * vr_offloads.c -- register callbacks for hardware offload features
 *
 * Copyright (c) 2016 Netronome Systems, Inc. All rights reserved.
 */
#include "vr_offloads.h"

struct vr_offload_ops *offload_ops;

int vr_offload_version(void)
{
    return VR_OFFLOAD_VER;
}
#if defined(__KERNEL__) && defined(__linux__)
EXPORT_SYMBOL(vr_offload_version);
#endif

int vr_offload_register(int version, const struct vr_offload_ops *new_handler)
{
#if defined(__KERNEL__) && defined(__linux__)

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
#endif
    return 0;
}
#if defined(__KERNEL__) && defined(__linux__)
EXPORT_SYMBOL(vr_offload_register);
#endif

int vr_offload_unregister()
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload =
       rcu_dereference(offload_ops);

    if (offload) {
        rcu_assign_pointer(offload_ops, NULL);
        kfree(offload);
    }
#endif
    return 0;
}
#if defined(__KERNEL__) && defined(__linux__)
EXPORT_SYMBOL(vr_offload_unregister);
#endif

int vr_offload_init_handler(void)
{
#if defined(__KERNEL__) && defined(__linux__)
    rcu_assign_pointer(offload_ops, NULL);
#endif
    return 0;
}

void vr_offload_cleanup_handler(void)
{
#if defined(__KERNEL__) && defined(__linux__)
    struct vr_offload_ops *offload =
       rcu_dereference(offload_ops);

    if (offload)
        kfree(offload);
    rcu_assign_pointer(offload_ops, NULL);
#endif
}
