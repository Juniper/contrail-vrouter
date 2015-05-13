/*
 * Copyright (C) 2014 Semihalf.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * dpdk_vrouter.c -- vRouter/DPDK application
 *
 */
#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>

#include <getopt.h>
#include <signal.h>
#include <linux/vhost.h>

#include <rte_timer.h>
#include <rte_errno.h>

#include "vr_dpdk.h"
#include "vr_uvhost.h"
#include "vr_packet.h"
#include "qemu_uvhost.h"
#include "vr_dpdk_virtio.h"

static int no_daemon_set;
extern char *ContrailBuildInfo;

/* Global vRouter/DPDK structure */
struct vr_dpdk_global vr_dpdk;

/* TODO: default commandline params */
static char *dpdk_argv[] = {
    "dpdk",
    "-m", VR_DPDK_MAX_MEM,
    /* the argument will be updated in dpdk_init() */
    "--lcores", NULL,
    "-n", VR_DPDK_MAX_MEMCHANNELS
};
static int dpdk_argc = sizeof(dpdk_argv)/sizeof(*dpdk_argv);

/* Pktmbuf constructor with vr_packet support */
void
vr_dpdk_pktmbuf_init(struct rte_mempool *mp, void *opaque_arg, void *_m, unsigned i)
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

/* Create memory pools */
static int
dpdk_mempools_create(void)
{
    /* Create the mbuf pool used for receiving from VM virtio interfaces */
    vr_dpdk.virtio_mempool = rte_mempool_create("virtio_mempool",
                                 VR_DPDK_VIRTIO_MEMPOOL_SZ,
                                 VR_DPDK_MBUF_SZ,
                                 VR_DPDK_VIRTIO_MEMPOOL_CACHE_SZ,
                                 sizeof(struct rte_pktmbuf_pool_private),
                                 rte_pktmbuf_pool_init, NULL,
                                 vr_dpdk_pktmbuf_init, NULL,
                                 rte_socket_id(), 0);
    if (vr_dpdk.virtio_mempool == NULL) {
        RTE_LOG(CRIT, VROUTER, "Error creating virtio mempool: %s (%d)\n",
            rte_strerror(rte_errno), rte_errno);
        return -rte_errno;
    }

    /* Create the mbuf pool used for RSS */
    vr_dpdk.rss_mempool = rte_mempool_create("rss_mempool", VR_DPDK_RSS_MEMPOOL_SZ,
            VR_DPDK_MBUF_SZ, VR_DPDK_RSS_MEMPOOL_CACHE_SZ,
            sizeof(struct rte_pktmbuf_pool_private),
            rte_pktmbuf_pool_init, NULL, vr_dpdk_pktmbuf_init, NULL,
            rte_socket_id(), 0);
    if (vr_dpdk.rss_mempool == NULL) {
        RTE_LOG(CRIT, VROUTER, "Error creating RSS mempool: %s (%d)\n",
            rte_strerror(rte_errno), rte_errno);
        return -rte_errno;
    }

    int ret, i;
    char mempool_name[RTE_MEMPOOL_NAMESIZE];

    /* Create a list of free mempools */
    vr_dpdk.nb_free_mempools = 0;
    for (i = 0; i < VR_DPDK_MAX_VM_MEMPOOLS; i++) {
        ret = snprintf(mempool_name, sizeof(mempool_name), "vr_mempool_%d", i);
        if (ret >= sizeof(mempool_name)) {
            RTE_LOG(INFO, VROUTER, "Error creating VM mempool %d name\n", i);
            return -ENOMEM;
        }
        vr_dpdk.free_mempools[i] = rte_mempool_create(mempool_name,
                VR_DPDK_VM_MEMPOOL_SZ, VR_DPDK_MBUF_SZ, VR_DPDK_VM_MEMPOOL_CACHE_SZ,
                sizeof(struct rte_pktmbuf_pool_private),
                rte_pktmbuf_pool_init, NULL, vr_dpdk_pktmbuf_init, NULL,
                rte_socket_id(), 0);
        if (vr_dpdk.free_mempools[i] == NULL) {
            RTE_LOG(CRIT, VROUTER, "Error creating VM mempool %d: %s (%d)\n",
                i, rte_strerror(rte_errno), rte_errno);
            return -rte_errno;
        }
        vr_dpdk.nb_free_mempools++;
    }
    RTE_LOG(INFO, VROUTER, "Allocated %" PRIu16 " VM mempool(s)\n",
        vr_dpdk.nb_free_mempools);

    return 0;
}

/*
 * Figure out a number of CPU cores/threads and compute an affinity mask
 * which will be passed to EAL initialization in dpdk_init().
 *
 * Returns:
 *      new core mask on success
 *      VR_DPDK_DEF_LCORE_MASK on failure
 *      0 if the system does not have enough cores
 */
static uint64_t
dpdk_core_mask_get(void)
{
    cpu_set_t cs;
    uint64_t cpu_core_mask = 0;
    int i;
    long system_cpus_count, core_mask_count;

    if (sched_getaffinity(0, sizeof(cs), &cs) < 0)
        return VR_DPDK_DEF_LCORE_MASK;

    /*
     * Go through all the CPUs in the cpu_set_t structure to check
     * if they are available or not. Build an affinity mask based on that.
     * There is no official way to obtain the mask directly, as there is
     * no macro for this.
     *
     * Due to size of uint64_t, maximum number of supported CPUs is 64.
     */
    for (i = 0; i < RTE_MIN(CPU_SETSIZE, 64); i++) {
        if (CPU_ISSET(i, &cs))
            cpu_core_mask |= (uint64_t)1 << i;
    }

    if (!cpu_core_mask)
        return VR_DPDK_DEF_LCORE_MASK;

    /*
     * Do not allow to run vRouter on all the cores available, as some have
     * to be spared for virtual machines.
     */
    system_cpus_count = sysconf(_SC_NPROCESSORS_CONF);
    if (system_cpus_count == -1)
        return cpu_core_mask;

    core_mask_count
        = __builtin_popcountll((unsigned long long)cpu_core_mask);

    if (core_mask_count == system_cpus_count)
        return VR_DPDK_DEF_LCORE_MASK;

    return cpu_core_mask;
}

/* Stringify core mask, i.e. 0xf -> 5@0,6@1,7@2,8@3 */
static char *
dpdk_core_mask_stringify(uint64_t core_mask)
{
    int ret, lcore_id = 0, core_id = 0;
    static char core_mask_string[256];
    char *p = core_mask_string;
    bool first_lcore = true;

    while (core_mask) {
        if (core_mask & 1) {
            if (first_lcore)
                first_lcore = false;
            else
                *p++ = ',';

            ret = snprintf(p,
            sizeof(core_mask_string) - (p - core_mask_string),
                    "%d@%d", lcore_id + VR_DPDK_FWD_LCORE_ID, core_id);
            p += ret;

            if (p - core_mask_string >= sizeof(core_mask_string))
                return NULL;
            lcore_id++;
        }
        core_mask >>= 1;
        core_id++;
    }
    *p = '\0';
    return core_mask_string;
}

/* Updates parameters of EAL initialization in dpdk_argv[]. */
static int
dpdk_argv_update(void)
{
    long int system_cpus_count;
    int i;
    char *core_mask_str;
    static char lcores_string[512];

    /* get number of available CPUs */
    system_cpus_count = sysconf(_SC_NPROCESSORS_CONF);
    if (system_cpus_count == -1) {
        system_cpus_count = __builtin_popcountll(
                (unsigned long long)VR_DPDK_DEF_LCORE_MASK);
    }

    core_mask_str = dpdk_core_mask_stringify(dpdk_core_mask_get());

    /* sanity check */
    if (core_mask_str == NULL || system_cpus_count == 0)
        return -1;

    if (snprintf(lcores_string, sizeof(lcores_string), "(0-%d)@(0-%ld),%s",
        VR_DPDK_FWD_LCORE_ID - 1, system_cpus_count - 1, core_mask_str)
            == sizeof(lcores_string)) {
        return -1;
    }

    /* find and update the argument */
    for (i = 0; i < dpdk_argc; i++) {
        if (dpdk_argv[i] == NULL)
            dpdk_argv[i] = lcores_string;
    }

    printf("LCores configuration: %s\n", lcores_string);

    return 0;
}

/* Init DPDK EAL */
static int
dpdk_init(void)
{
    int ret, nb_sys_ports;

    ret = vr_dpdk_flow_mem_init();
    if (ret < 0) {
        fprintf(stderr, "Error initializing flow table: %s (%d)\n",
            rte_strerror(-ret), -ret);
        return ret;
    }

    if (dpdk_argv_update() == -1) {
        fprintf(stderr, "Error updating lcores arguments\n");
        return -1;
    }

    ret = rte_eal_init(dpdk_argc, dpdk_argv);
    if (ret < 0) {
        fprintf(stderr, "Error initializing EAL\n");
        return ret;
    }

    rte_kni_init(VR_DPDK_MAX_KNI_INTERFACES);

    ret = dpdk_mempools_create();
    if (ret < 0)
        return ret;

    /* Get number of ports found in scan */
    nb_sys_ports = rte_eth_dev_count();
    RTE_LOG(INFO, VROUTER, "Found %d eth device(s)\n", nb_sys_ports);

    vr_dpdk.nb_fwd_lcores = rte_lcore_count();
    vr_dpdk.nb_fwd_lcores -= VR_DPDK_FWD_LCORE_ID;
    RTE_LOG(INFO, VROUTER, "Using %d forwarding lcore(s)\n",
                            vr_dpdk.nb_fwd_lcores);
    RTE_LOG(INFO, VROUTER, "Using %d service lcore(s)\n",
                            VR_DPDK_FWD_LCORE_ID);

    /* init timer subsystem */
    rte_timer_subsystem_init();

    /* Init the interface configuration mutex
     * ATM we use it just to synchronize access between the NetLink interface
     * and kernel KNI events. The datapath is not affected. */
    return pthread_mutex_init(&vr_dpdk.if_lock, NULL);
}

/* Shutdown DPDK EAL */
static void
dpdk_exit(void)
{
    int i;

    vr_dpdk_if_lock();
    RTE_LOG(INFO, VROUTER, "Releasing KNI devices...\n");
    for (i = 0; i < VR_MAX_INTERFACES; i++) {
        if (vr_dpdk.knis[i] != NULL) {
            rte_kni_release(vr_dpdk.knis[i]);
            vr_dpdk.knis[i] = NULL;
        }
    }

    RTE_LOG(INFO, VROUTER, "Closing eth devices...\n");
    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        if (vr_dpdk.ethdevs[i].ethdev_ptr != NULL) {
            rte_eth_dev_stop(i);
            rte_eth_dev_close(i);
            vr_dpdk.ethdevs[i].ethdev_ptr = NULL;
        }
    }
    vr_dpdk_if_unlock();

    /* destroy interface lock */
    if (pthread_mutex_destroy(&vr_dpdk.if_lock)) {
        RTE_LOG(ERR, VROUTER, "Error destroying interface lock\n");
    }
}

/* Set stop flag for all lcores */
static void
dpdk_stop_flag_set(void)
{
    /* check if the flag is already set */
    if (unlikely(vr_dpdk_is_stop_flag_set()))
        return;

    vr_dpdk_lcore_cmd_post_all(VR_DPDK_LCORE_STOP_CMD, 0);
    rte_atomic16_inc(&vr_dpdk.stop_flag);

    /* wakeup UVHost server to shutdown */
    vr_uvhost_wakeup();
}

/* Check if the stop flag is set */
int
vr_dpdk_is_stop_flag_set(void)
{
    if (unlikely(rte_atomic16_read(&vr_dpdk.stop_flag)))
        return 1;

    return 0;
}

/* Custom handling of signals */
static void
dpdk_signal_handler(int signum)
{
    RTE_LOG(DEBUG, VROUTER, "Got signal %d on lcore %u\n",
            signum, rte_lcore_id());

    dpdk_stop_flag_set();
}

/* Setup signal handlers */
static int
dpdk_signals_init(void)
{
    struct sigaction act;
    sigset_t set;

    memset(&act, 0 , sizeof(act));
    act.sa_handler = dpdk_signal_handler;

    if (sigaction(SIGTERM, &act, NULL) != 0) {
        RTE_LOG(CRIT, VROUTER, "Error registering SIGTERM handler\n");
        return -1;
    }

    if (sigaction(SIGINT, &act, NULL) != 0) {
        RTE_LOG(CRIT, VROUTER, "Error registering SIGINT handler\n");
        return -1;
    }

    /* block (ignore) sigpipes for this and all the child threads */
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        RTE_LOG(CRIT, VROUTER, "Error setting signal mask\n");
        return -1;
    }

    return 0;
}

enum vr_opt_index {
    DAEMON_OPT_INDEX,
    VLAN_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [DAEMON_OPT_INDEX]              =   {"no-daemon",           no_argument,
                                                    &no_daemon_set,         1},
    [VLAN_OPT_INDEX]              =     {"vlan",                required_argument,
                                                    NULL,                 'v'},
    [MAX_OPT_INDEX]                 =   {NULL,                  0,
                                                    NULL,                   0},
};

/*
 * vr_dpdk_exit_trigger - function that is called by user space vhost server
 * to cause all DPDK threads to exit.
 *
 * Returns nothing.
 */
void
vr_dpdk_exit_trigger(void)
{
    dpdk_stop_flag_set();

    return;
}

int
main(int argc, char *argv[])
{
    int ret, opt, option_index;
    vr_dpdk.vlan_tag = VLAN_ID_INVALID;

    fprintf(stdout, "Starting vRouter/DPDK...\nBuild information: %s\n",
                ContrailBuildInfo);
    fflush(stdout);

    while ((opt = getopt_long(argc, argv, "", long_options, &option_index))
            >= 0) {
        switch (opt) {
        case 0:
            break;

        /* If VLAN tag is set, vRouter will expect tagged packets. The tag
         * will be stripped in dpdk_vroute() and injected in dpdk_if_tx().
         */
        case 'v':
            vr_dpdk.vlan_tag = (uint16_t)atoi(optarg);
            if (!vr_dpdk.vlan_tag)
                vr_dpdk.vlan_tag = VLAN_ID_INVALID;
            break;


        case '?':
        default:
            fprintf(stderr, "Invalid option %s\n", argv[optind - 1]);
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

    /* run all the lcores */
    ret = rte_eal_mp_remote_launch(vr_dpdk_lcore_launch, NULL, CALL_MASTER);

    rte_eal_mp_wait_lcore();
    dpdk_netlink_exit();
    vr_dpdk_host_exit();
    dpdk_exit();

    rte_exit(ret, "vRouter/DPDK is stopped.\n");
}
