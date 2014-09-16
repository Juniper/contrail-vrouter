/*
 * Copyright (C) 2014 Semihalf.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * vr_port_bind.c -- DPDK runtime port bind/unbind
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>

#include "vr_os.h"
#include "vrouter.h"

#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_pci.h>
#include <rte_ethdev.h>

#include "vr_dpdk.h"

/* Please use an updated version of the script
 * which accepts -d and -e options.
 */
#define DPDK_BIND_SCRIPT "$RTE_SDK/tools/dpdk_nic_bind.py"

static int
dpdk_invoke(const char *cmd, char *buf, size_t size)
{
    FILE *pipein_fp = NULL;
    unsigned dev_id, func_id, svend_id, vend_id;
    int ret = 0;

    /* Create one way pipe line with call to popen() */
    if ((pipein_fp = popen(cmd, "r")) == NULL)
    {
        RTE_LOG(ERR, VROUTER, "Error invoking '%s': %s", cmd,
            strerror(errno));
        ret = -1;
        goto fail;
    }


    if (NULL == fgets(buf, size, pipein_fp)) {
        RTE_LOG(ERR, VROUTER, "Error reading pipe from '%s'\n", cmd);
        ret = -1;
        goto fail;
    }

fail:
    if (pipein_fp != NULL) {
        if (pclose(pipein_fp) == -1)
            RTE_LOG(ERR, VROUTER, "Error closing the pipe: %s",
                strerror(errno));
    }

    return ret;
}


int
vr_dpdk_port_bind(struct rte_pci_addr *pci, const char *ifname)
{
    char buf[100];
    char cmd[100];

    RTE_LOG(DEBUG, VROUTER, "RTE_SDK=%s\n", getenv("RTE_SDK"));

    sprintf(cmd, DPDK_BIND_SCRIPT " -d %s", ifname);

    if(dpdk_invoke(cmd, buf, sizeof(buf)-1)) {
        return -1;
    }

    if (sscanf(buf, "%hu:%hhu:%hhu.%hhu\n", &pci->domain, &pci->bus,
                    &pci->devid, &pci->function) != 4) {
        RTE_LOG(ERR, VROUTER, "Bad format: %s", buf);
        return -1;
    }

    return 0;
}

int
vr_dpdk_port_unbind(struct rte_pci_addr *pci)
{
    char cmd[100];
    char buf[100];

    sprintf(cmd, DPDK_BIND_SCRIPT " -e %04u:%02u:%02u.%01u 2>&1",
            pci->domain, pci->bus, pci->devid, pci->function);

    return dpdk_invoke(cmd, buf, sizeof(buf)-1);
}
