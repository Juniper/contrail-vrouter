/*
 * Main code that inits the vnsw-dp module
 * This code should be made platorm independant at some
 * time
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/llc.h>
#include <net/llc.h>
#include <net/lacp.h>

#include "vnsw_private.h"


static const struct lacp_proto vnsw_lacp_proto = {
	.rcv	= vnsw_lacp_rcv,
};

static struct pernet_operations vnsw_net_ops = {
	.exit	= vnsw_net_exit,
};

static int __init vnsw_init(void)
{
	int err;

	err = lacp_proto_register(&vnsw_lacp_proto);
	if (err < 0) {
		pr_err("vnsw: can't register sap for LACP\n");
		return err;
	}
        /**
         * More proto register should come here
         */

	err = vnsw_mtrie_init();
	if (err)
		goto err_out;

	err = register_pernet_subsys(&vnsw_net_ops);
	if (err)
		goto err_out1;

	err = vnsw_policy_init();
	if (err)
		goto err_out2;

	err = vnsw_if_init();
	if (err)
		goto err_out3;

	err = register_netdevice_notifier(&vnsw_device_notifier);
	if (err)
		goto err_out4;

        /**
         * Should this move to linux directory
         */
	err = vnsw_netlink_init();
	if (err)
		goto err_out5;

        /**
         * Should this move to linux directory
         */
	brioctl_set(vnsw_ioctl_deviceless_stub);
        /**
         * Should this move to linux directory linux module init
         */
	br_handle_frame_hook = vnsw_handle_frame;


	return 0;
err_out5:
	unregister_netdevice_notifier(&vnsw_device_notifier);
err_out4:
        vnsw_if_fini();
err_out3:
	vnsw_policy_fini();
err_out2:
	unregister_pernet_subsys(&vnsw_net_ops);
err_out1:
	vnsw_mtrie_fini();
err_out:
	lacp_proto_unregister(&vnsw_lacp_proto);
	return err;
}

static void __exit vnsw_deinit(void)
{
	lacp_proto_unregister(&vnsw_lacp_proto);
        vnsw_if_fini();
	vnsw_netlink_fini();
	unregister_netdevice_notifier(&vnsw_device_notifier);
	brioctl_set(NULL);

	unregister_pernet_subsys(&vnsw_net_ops);

	rcu_barrier(); /* Wait for completion of call_rcu()'s */

	vnsw_policy_fini();

	vnsw_handle_frame_hook = NULL;
	vnsw_fdb_fini();
}

EXPORT_SYMBOL(vnsw_should_route_hook);

module_init(vnsw_init)
module_exit(vnsw_deinit)
MODULE_LICENSE("GPL");
MODULE_VERSION(BR_VERSION);
