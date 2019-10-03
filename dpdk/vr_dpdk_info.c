/*
 * vr_pkt_droplog.c -- Log drop packet information.
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_message.h"
#include "vr_btable.h"
#include "vr_dpdk.h"
//int vr_pkt_drop_log_init(struct vrouter *router);
//void vr_pkt_drop_log_exit(struct vrouter *router);
void
dpdk_info_get(char *buffer)
{
    //char buffer[1024];

    sprintf(buffer, "DPDK Version: %s", rte_version());
   rte_eth_bond_mode_get(); 
    //vr_printf("buffer: %s\n",response->vdu_proc_info);
    
    return;
}

