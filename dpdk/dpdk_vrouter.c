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
 * dpdk_vrouter.c -- DPDK vRouter application
 *
 */

#include <signal.h>

#include "vr_os.h"
#include "vr_dpdk.h"

/* Global vRouter/DPDK structure */
struct dpdk_global vr_dpdk;

/* TODO: default commandline params */
static char *dpdk_argv[] = {"dpdk", "-c", "0xf", "-n", "1" };
static int dpdk_argc = sizeof(dpdk_argv)/sizeof(*dpdk_argv);

/* Init DPDK EAL */
static int
dpdk_init(void)
{
    int i, ret, nb_sys_ports;
    unsigned lcore_id;

    ret = rte_eal_init(dpdk_argc, dpdk_argv);
    if (0 > ret) {
        RTE_LOG(CRIT, VROUTER, "Could not initialise EAL (%d)\n", ret);
        return ret;
    }

    /* Create the mbuf pool */
    vr_dpdk.pktmbuf_pool = rte_mempool_create("mbuf_pool", VR_DPDK_MPOOL_SZ,
            VR_DPDK_MBUF_SZ, VR_DPDK_MPOOL_CACHE_SZ,
            sizeof(struct rte_pktmbuf_pool_private),
            rte_pktmbuf_pool_init, NULL, vr_dpdk_pktmbuf_init, NULL,
            rte_socket_id(), 0);
    if (NULL == vr_dpdk.pktmbuf_pool) {
        RTE_LOG(CRIT, VROUTER, "Could not initialise mbuf pool\n");
        return -ENOMEM;
    }

    /* Scan PCI bus for recognised devices */
    ret = rte_eal_pci_probe();
    if (0 > ret) {
        RTE_LOG(CRIT, VROUTER, "Could not probe PCI (%d)\n", ret);
        return ret;
    }

    /* Get number of ports found in scan */
    nb_sys_ports = rte_eth_dev_count();
    RTE_LOG(INFO, VROUTER, "Found %d port(s)\n", nb_sys_ports);

    /* Enable all detected lcores */
    vr_dpdk.nb_lcores = rte_lcore_count();
    if (vr_dpdk.nb_lcores) {
        RTE_LOG(INFO, VROUTER, "Found %i lcore(s)\n", vr_dpdk.nb_lcores);
    } else {
        RTE_LOG(CRIT, VROUTER, "No lcores found. Please use -c option to enable more lcores.");
        return -ENODEV;
    }

    /* init timer subsystem */
    rte_timer_subsystem_init();

    return 0;
}

/* Shutdown DPDK EAL */
static void
dpdk_exit(void)
{
    unsigned port_id;
    /* loop eth dev pointer */
    struct rte_eth_dev *eth;
    /* loop vr_dpdk_port pointer */
    struct vif_port *port;

    RTE_LOG(INFO, VROUTER, "Closing %d ports...\n", (int)rte_eth_dev_count());
    for (port_id = 0; port_id < rte_eth_dev_count(); port_id++) {
        eth = &rte_eth_devices[port_id];
        /* unused ports marked with NULL data pointer */
        if (!eth->data)
            continue;

        port = &vr_dpdk.ports[port_id];

        /* check if port was added and assigned to a lcore */
        if (unlikely(NULL == port->vip_lcore_ctx))
            continue;

        RTE_LOG(DEBUG, VROUTER, "Closing port %s...\n", port->vip_name);

        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }
}

/* NetLink handling loop */
static void *
dpdk_netlink_loop(__attribute__((unused)) void *dummy)
{
    while(1) {
        /* vr_dpdk_netlink_handle would block waiting for a message
         * so we do not sleep in this loop */
        vr_dpdk_netlink_handle();

        /* check for the global stop flag */
        if (unlikely(rte_atomic32_read(&vr_dpdk.stop_flag)))
            break;
    };
    return NULL;
}

/* Timer handling loop */
static void *
dpdk_timer_loop(__attribute__((unused)) void *dummy)
{
    while(1) {
        rte_timer_manage();

        /* check for the global stop flag */
        if (unlikely(rte_atomic32_read(&vr_dpdk.stop_flag)))
            break;

        usleep(VR_DPDK_TIMER_US);
    };
    return NULL;
}

/* KNI handling loop */
static void *
dpdk_kni_loop(__attribute__((unused)) void *dummy)
{
    while(1) {
        vr_dpdk_all_knis_handle();

        /* check for the global stop flag */
        if (unlikely(rte_atomic32_read(&vr_dpdk.stop_flag)))
            break;

        usleep(VR_DPDK_KNI_US);
    };
    return NULL;
}

/* Lcore main loop */
static int
dpdk_lcore_loop(__attribute__((unused)) void *dummy)
{
    /* current lcore id */
    const unsigned lcore_id = rte_lcore_id();
    /* current lcore context */
    struct lcore_ctx * const lcore_ctx = &vr_dpdk.lcores[lcore_id];

    /* cycles counters */
    uint64_t cur_cycles = 0;
    uint64_t diff_cycles;
    uint64_t last_tx_cycles = 0;
#ifdef VR_DPDK_USE_TIMER
    /* calculate timeouts in CPU cycles */
    const uint64_t tx_drain_cycles = (rte_get_timer_hz() + US_PER_S - 1)
        * VR_DPDK_TX_DRAIN_US / US_PER_S;
#else
    const uint64_t tx_drain_cycles = VR_DPDK_TX_DRAIN_LOOPS;
#endif

    RTE_LOG(DEBUG, VROUTER, "Hello from lcore %u\n", lcore_id);

    while (1) {
        rte_prefetch0(lcore_ctx);

        /* update cycles counter */
#ifdef VR_DPDK_USE_TIMER
        cur_cycles = rte_get_timer_cycles();
#else
        cur_cycles++;
#endif

        /* Read bursts from all the ports assigned and
         * transmit those packets to VRouter
         */
        vr_dpdk_all_ports_poll(lcore_ctx);

        /* check if we need to drain TX queues */
        diff_cycles = cur_cycles - last_tx_cycles;
        if (unlikely(tx_drain_cycles < diff_cycles)) {
            /* update TX drain timer */
            last_tx_cycles = cur_cycles;

            vr_dpdk_all_ports_drain(lcore_ctx);

            /* check if any port attached */
            if (unlikely(0 == lcore_ctx->lcore_nb_rx_ports)) {
                /* no RX ports -> just sleep */
                usleep(VR_DPDK_NO_PORTS_US);
            }

            /* check for the global stop flag */
            if (unlikely(rte_atomic32_read(&vr_dpdk.stop_flag)))
                break;
        } /* drain TX queues */
    } /* lcore loop */

    RTE_LOG(DEBUG, VROUTER, "Bye-bye from lcore %u\n", lcore_id);

    return 0;
}

/* Custom handling of signals */
static void
dpdk_signal_handler(int signum)
{
    int lcore_id = rte_lcore_id();

    RTE_LOG(DEBUG, VROUTER, "Got signal %i on lcore %i\n",
            signum, lcore_id);

    /* stop processing on RTMIN or SIGINT signal */
    if (SIGTERM == signum || SIGINT == signum) {
        rte_atomic32_inc(&vr_dpdk.stop_flag);
    }
}

/* Setup signal handlers */
static int
dpdk_signals_init(void)
{
    struct sigaction act;

    memset(&act, 0 , sizeof(act));
    act.sa_handler = dpdk_signal_handler;

    if (sigaction(SIGTERM, &act, NULL) != 0) {
        RTE_LOG(CRIT, VROUTER, "Fail to register SIGTERM handler\n");
        return -1;
    }
    if (sigaction(SIGINT, &act, NULL) != 0) {
        RTE_LOG(CRIT, VROUTER, "Fail to register SIGINT handler\n");
        return -1;
    }
    return 0;
}

/* Cancel all threads */
static void
dpdk_threads_cancel(void)
{
    if (vr_dpdk.kni_thread)
        pthread_cancel(vr_dpdk.kni_thread);
    if (vr_dpdk.timer_thread)
        pthread_cancel(vr_dpdk.timer_thread);
    if (vr_dpdk.netlink_thread)
        pthread_cancel(vr_dpdk.netlink_thread);
}

/* Wait for other threads to join */
static void
dpdk_threads_join(void)
{
    if (vr_dpdk.kni_thread)
        pthread_join(vr_dpdk.kni_thread, NULL);
    if (vr_dpdk.timer_thread)
        pthread_join(vr_dpdk.timer_thread, NULL);
    if (vr_dpdk.netlink_thread)
        pthread_join(vr_dpdk.netlink_thread, NULL);
}


/* Create threads to handle KNI, timers, NetLink etc */
static int
dpdk_threads_create(void)
{
    int ret;

    /* thread to handle KNI requests */
    if (ret = pthread_create(&vr_dpdk.kni_thread, NULL,
        &dpdk_kni_loop, NULL)) {
        RTE_LOG(CRIT, VROUTER, "Error creating KNI thread (%d)\n",
            ret);
        return ret;
    }
    /* thread to handle timers */
    if (ret = pthread_create(&vr_dpdk.timer_thread, NULL,
        &dpdk_timer_loop, NULL)) {
        RTE_LOG(CRIT, VROUTER, "Error creating timer thread (%d)\n",
            ret);

        return ret;
    }

    /* thread to handle NetLink */
    if (ret = pthread_create(&vr_dpdk.netlink_thread, NULL,
        &dpdk_netlink_loop, NULL)) {
        RTE_LOG(CRIT, VROUTER, "Error creating NetLink thread (%d)\n",
            ret);

        return ret;
    }

    return 0;
}

int
main(int argc, const char *argv[])
{
    int ret;
    bool daemonize = true;

    /* daemonize... */
    if (argc >= 2 && strcmp(argv[1],"--no-daemon") == 0)
        daemonize = false;

    if (daemonize) {
        if (daemon(0, 0) < 0)
            return -1;
    }

    /* associate signal hanlder with signals */
    if (ret = dpdk_signals_init()) {
        return ret;
    }

    /* init DPDK first since vRouter uses DPDK mallocs */
    if (ret = dpdk_init()) {
        return ret;
    }

    /* init the vrouter */
    if (ret = vrouter_host_init()) {
        dpdk_exit();
        return ret;
    }

    /* init the communication socket with agent */
    if (ret = vr_dpdk_netlink_sock_init()) {
        vrouter_host_exit();
        dpdk_exit();
        return ret;
    }

    /* create threads to handle KNI, timers, NetLink etc */
    if (ret = dpdk_threads_create()) {
        dpdk_threads_cancel();
        dpdk_threads_join();
        vrouter_host_exit();
        dpdk_exit();
        return ret;
    }

    /* run lcore loops on all lcores */
    ret = rte_eal_mp_remote_launch(dpdk_lcore_loop,
        NULL, CALL_MASTER);

    /* set the stop flag */
    rte_atomic32_inc(&vr_dpdk.stop_flag);
    /* wait for other lcores to stop */
    rte_eal_mp_wait_lcore();

    /* cancel all threads*/
    dpdk_threads_cancel();
    /* wait for other threads to join */
    dpdk_threads_join();

    /* close the communication socket */
    vr_dpdk_netlink_sock_close();

    /* close DPDK ports first since we examine vif flags */
    dpdk_exit();
        /* close sandesh link and shutdown vrouter */
    vrouter_host_exit();

    return ret;
}
