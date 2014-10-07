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
 * dpdk_vrouter.c -- vRouter/DPDK application
 *
 */
#include <getopt.h>
#include <signal.h>

#include <rte_timer.h>

#include "vr_dpdk.h"

static int no_daemon_set;

extern int dpdk_netlink_core_id, dpdk_packet_core_id;
extern int vr_dpdk_flow_mem_init(void);

/* Global vRouter/DPDK structure */
struct vr_dpdk_global vr_dpdk;

/* TODO: default commandline params */
static char *dpdk_argv[] = {"dpdk",
    "-m", VR_DPDK_MAX_MEM,
    "-c", VR_DPDK_LCORE_MASK,
    "-n", "2" };
static int dpdk_argc = sizeof(dpdk_argv)/sizeof(*dpdk_argv);

/*
 * pktmbuf constructor with vr_packet support
 */
void
dpdk_pktmbuf_init(struct rte_mempool *mp,
         __attribute__((unused)) void *opaque_arg,
         void *_m,
         __attribute__((unused)) unsigned i)
{
    struct rte_mbuf *m = _m;
    struct vr_packet *pkt;
    rte_pktmbuf_init(mp, opaque_arg, _m, i);

    /* decrease rte packet size to fit vr_packet struct */
    m->buf_len -= sizeof(struct vr_packet);
    RTE_VERIFY(0 < m->buf_len);

    /* basic vr_packet initialization */
    pkt = vr_dpdk_mbuf_to_pkt(m);
    pkt->vp_head = (unsigned char *)m->buf_addr;
    pkt->vp_end = m->buf_len;
}

/* Init DPDK EAL */
static int
dpdk_init(void)
{
    int ret, nb_sys_ports;

    ret = vr_dpdk_flow_mem_init();
    if (ret < 0) {
        fprintf(stderr, "Error initializing flow table: %s (%d)\n",
            strerror(-ret), -ret);
        return ret;
    }

    ret = rte_eal_init(dpdk_argc, dpdk_argv);
    if (ret < 0) {
        fprintf(stderr, "Error initializing EAL\n");
        return ret;
    }

    /* Create the mbuf pool */
    vr_dpdk.pktmbuf_pool = rte_mempool_create("vrouter_mbuf_pool", VR_DPDK_MPOOL_SZ,
            VR_DPDK_MBUF_SZ, VR_DPDK_MPOOL_CACHE_SZ,
            sizeof(struct rte_pktmbuf_pool_private),
            rte_pktmbuf_pool_init, NULL, dpdk_pktmbuf_init, NULL,
            rte_socket_id(), 0);
    if (NULL == vr_dpdk.pktmbuf_pool) {
        RTE_LOG(CRIT, VROUTER, "Error initializing mbuf pool\n");
        return -ENOMEM;
    }

    /* Scan PCI bus for recognised devices */
    ret = rte_eal_pci_probe();
    if (ret < 0) {
        RTE_LOG(CRIT, VROUTER, "Error probing PCI: %s (%d)\n", strerror(-ret), -ret);
        return ret;
    }

    /* Get number of ports found in scan */
    nb_sys_ports = rte_eth_dev_count();
    RTE_LOG(INFO, VROUTER, "Found %d eth device(s)\n", nb_sys_ports);

    /* Enable all detected lcores */
    vr_dpdk.nb_lcores = rte_lcore_count();
    if (vr_dpdk.nb_lcores) {
        RTE_LOG(INFO, VROUTER, "Using %i forwarding lcore(s)\n", vr_dpdk.nb_lcores);
    } else {
        RTE_LOG(CRIT, VROUTER, "No forwarding lcores found. Please use -c option to"
            " enable more lcores.");
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
    int i;
    uint8_t port_id;

    RTE_LOG(INFO, VROUTER, "Releasing KNI devices...\n");
    for (i = 0; i < VR_MAX_INTERFACES; i++) {
        if (vr_dpdk.knis[i] != NULL) {
            rte_kni_release(vr_dpdk.knis[i]);
        }
    }

    RTE_LOG(INFO, VROUTER, "Closing eth devices...\n");
    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        if (vr_dpdk.eth_devs[i] != NULL) {
            port_id = vr_dpdk.eth_devs[i]->data->port_id;
            rte_eth_dev_stop(port_id);
            rte_eth_dev_close(port_id);
        }
    }
}

/* Timer handling loop */
static void *
dpdk_timer_loop(__attribute__((unused)) void *dummy)
{
    while (1) {
        rte_timer_manage();

        /* check for the global stop flag */
        if (unlikely(rte_atomic16_read(&vr_dpdk.stop_flag)))
            break;

        usleep(VR_DPDK_SLEEP_TIMER_US);
    };
    return NULL;
}

/* KNI handling loop */
static void *
dpdk_kni_loop(__attribute__((unused)) void *dummy)
{
    while (1) {
        vr_dpdk_knidev_all_handle();

        /* check for the global stop flag */
        if (unlikely(rte_atomic16_read(&vr_dpdk.stop_flag)))
            break;

        usleep(VR_DPDK_SLEEP_KNI_US);
    };
    return NULL;
}

/* Set stop flag for all lcores */
static void
dpdk_stop_flag_set(void) {
    unsigned lcore_id;
    struct vr_dpdk_lcore *lcore;

    /* check if the flag is already set */
    if (unlikely(rte_atomic16_read(&vr_dpdk.stop_flag)))
        return;

    RTE_LCORE_FOREACH(lcore_id) {
        lcore = vr_dpdk.lcores[lcore_id];
        rte_atomic16_inc(&lcore->lcore_stop_flag);
    }

    rte_atomic16_inc(&vr_dpdk.stop_flag);
}

/* Custom handling of signals */
static void
dpdk_signal_handler(int signum)
{
    RTE_LOG(DEBUG, VROUTER, "Got signal %i on lcore %u\n",
            signum, rte_lcore_id());

    dpdk_stop_flag_set();
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

    /* ignore sigpipes emanating from sockets that are closed */
    act.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &act, NULL) != 0) {
        RTE_LOG(CRIT, VROUTER, "Failed to ignore SIGPIPE\n");
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
}

/* Wait for other threads to join */
static void
dpdk_threads_join(void)
{
    if (vr_dpdk.kni_thread)
        pthread_join(vr_dpdk.kni_thread, NULL);
    if (vr_dpdk.timer_thread)
        pthread_join(vr_dpdk.timer_thread, NULL);
}


/* Create threads to handle KNI, timers, NetLink etc */
static int
dpdk_threads_create(void)
{
    int ret;

    /* thread to handle KNI requests */
    ret = pthread_create(&vr_dpdk.kni_thread, NULL,
            &dpdk_kni_loop, NULL);
    if (ret != 0) {
        RTE_LOG(CRIT, VROUTER, "Error creating KNI thread: %s (%d)\n",
            strerror(ret), ret);
        return ret;
    }
    /* thread to handle timers */
    ret = pthread_create(&vr_dpdk.timer_thread, NULL,
            &dpdk_timer_loop, NULL);
    if (ret != 0) {
        RTE_LOG(CRIT, VROUTER, "Error creating timer thread: %s (%d)\n",
            strerror(ret), ret);

        return ret;
    }

    return 0;
}

enum vr_opt_index {
    DAEMON_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [DAEMON_OPT_INDEX]              =   {"no-daemon",           no_argument,
                                                    &no_daemon_set,         1},
    [MAX_OPT_INDEX]                 =   {NULL,                  0,
                                                    NULL,                   0},
};

int
main(int argc, char *argv[])
{
    int ret, opt, option_index;

    while ((opt = getopt_long(argc, argv, "", long_options, &option_index))
            >= 0) {
        switch (opt) {
        case 0:
            break;

        case '?':
        default:
            fprintf(stderr, "Invalid option %s\n", argv[optind]);
            exit(-EINVAL);
            break;
        }
    }
    /* for other getopts in dpdk */
    optind = 0;

    if (!no_daemon_set) {
        if (daemon(0, 0) < 0)
            return -1;
    }

    /* init DPDK first since vRouter uses DPDK mallocs and logs */
    ret = dpdk_init();
    if (ret != 0) {
        return ret;
    }

    /* associate signal hanlder with signals */
    ret = dpdk_signals_init();
    if (ret != 0) {
        dpdk_exit();
        return ret;
    }

    /* init the vRouter */
    ret = vr_dpdk_host_init();
    if (ret != 0) {
        dpdk_exit();
        return ret;
    }

    /* init the communication socket with agent */
    ret = dpdk_netlink_init();
    if (ret != 0) {
        vr_dpdk_host_exit();
        dpdk_exit();
        return ret;
    }

    /* create threads to handle KNI, timers, NetLink etc */
    ret = dpdk_threads_create();
    if (ret != 0) {
        dpdk_threads_cancel();
        dpdk_threads_join();
        vr_dpdk_host_exit();
        dpdk_exit();
        return ret;
    }

    /* run loops on all forwarding lcores */
    ret = rte_eal_mp_remote_launch(vr_dpdk_lcore_loop, NULL, CALL_MASTER);

    rte_eal_mp_wait_lcore();
    dpdk_threads_cancel();
    dpdk_threads_join();
    dpdk_netlink_exit();
    vr_dpdk_host_exit();
    dpdk_exit();

    return ret;
}
