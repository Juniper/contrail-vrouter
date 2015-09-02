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

/* For sched_getaffinity() */
#define _GNU_SOURCE

#include "vr_dpdk.h"
#include "vr_dpdk_virtio.h"
#include "vr_uvhost.h"
#include "vr_bridge.h"

#include <getopt.h>
#include <signal.h>
#include <sys/time.h>

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_timer.h>

#define LCORES_ARG "--lcores"

/* dp-core parameters */
extern unsigned int vr_bridge_entries;
extern unsigned int vr_bridge_oentries;
extern unsigned int vr_mpls_labels;
extern unsigned int vr_nexthops;
extern unsigned int vr_vrfs;

static int no_daemon_set;
extern char *ContrailBuildInfo;

/* Global vRouter/DPDK structure */
struct vr_dpdk_global vr_dpdk;

/* Arguments for EAL init */
static char *dpdk_argv[] = {
    "dpdk",
    /* the argument will be updated in dpdk_init() */
    LCORES_ARG, NULL,
    "-m", VR_DPDK_MAX_MEM,
    "-n", VR_DPDK_MAX_MEMCHANNELS,
    /* up to ten optional arguments (5 pairs of argument + option) */
    NULL, NULL,
    NULL, NULL,
    NULL, NULL,
    NULL, NULL,
    NULL, NULL
};
static int dpdk_argc = RTE_DIM(dpdk_argv) - 10;

/* Timestamp logger */
static FILE *timestamp_log_stream;

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

    /* start of buffer is just after vr_packet structure */
    m->buf_addr += sizeof(struct vr_packet);
    m->buf_physaddr += sizeof(struct vr_packet);

    /* basic vr_packet initialization */
    pkt = vr_dpdk_mbuf_to_pkt(m);
    pkt->vp_head = (unsigned char *)m->buf_addr;
    pkt->vp_end = m->buf_len;
}

/* Create memory pools */
static int
dpdk_mempools_create(void)
{
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

    /* Create the mbuf pool used for IP fragmentation (direct mbufs) */
    vr_dpdk.frag_direct_mempool = rte_mempool_create("frag_direct_mempool",
            VR_DPDK_FRAG_DIRECT_MEMPOOL_SZ, VR_DPDK_FRAG_DIRECT_MBUF_SZ,
            VR_DPDK_FRAG_DIRECT_MEMPOOL_CACHE_SZ,
            sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init,
            NULL, vr_dpdk_pktmbuf_init, NULL, rte_socket_id(), 0);
    if (vr_dpdk.frag_direct_mempool == NULL) {
        RTE_LOG(CRIT, VROUTER, "Error creating FRAG_DIRECT mempool: %s (%d)\n",
            rte_strerror(rte_errno), rte_errno);
        return -rte_errno;
    }

    /* Create the mbuf pool used for IP fragmentation (indirect mbufs) */
    vr_dpdk.frag_indirect_mempool = rte_mempool_create("frag_indirect_mempool",
            VR_DPDK_FRAG_INDIRECT_MEMPOOL_SZ, VR_DPDK_FRAG_INDIRECT_MBUF_SZ,
            VR_DPDK_FRAG_INDIRECT_MEMPOOL_CACHE_SZ, 0, NULL, NULL,
            rte_pktmbuf_init, NULL, rte_socket_id(), 0);
    if (vr_dpdk.frag_indirect_mempool == NULL) {
        RTE_LOG(CRIT, VROUTER, "Error creating FRAG_INDIRECT mempool: %s (%d)\n",
            rte_strerror(rte_errno), rte_errno);
        return -rte_errno;
    }

#if VR_DPDK_USE_HW_FILTERING
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
#endif

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
dpdk_core_mask_get(long system_cpus_count)
{
    cpu_set_t cs;
    uint64_t cpu_core_mask = 0;
    int i;
    long core_mask_count;

    if (sched_getaffinity(0, sizeof(cs), &cs) < 0) {
        RTE_LOG(ERR, VROUTER, "Error getting affinity."
            " Falling back do the default core mask 0x%" PRIx64 "\n",
                (uint64_t)(VR_DPDK_DEF_LCORE_MASK));
        return VR_DPDK_DEF_LCORE_MASK;
    }

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

    if (!cpu_core_mask) {
        RTE_LOG(ERR, VROUTER, "Error: core mask is zero."
            " Falling back do the default core mask 0x%" PRIx64 "\n",
                (uint64_t)(VR_DPDK_DEF_LCORE_MASK));
        return VR_DPDK_DEF_LCORE_MASK;
    }

    /*
     * Do not allow to run vRouter on all the cores available, as some have
     * to be spared for virtual machines.
     */
    core_mask_count = __builtin_popcountll((unsigned long long)cpu_core_mask);
    if (core_mask_count == system_cpus_count) {
        RTE_LOG(NOTICE, VROUTER, "Use taskset(1) to set the core mask."
            " Falling back do the default core mask 0x%" PRIx64 "\n",
                (uint64_t)(VR_DPDK_DEF_LCORE_MASK));
        return VR_DPDK_DEF_LCORE_MASK;
    }

    return cpu_core_mask;
}

/* Stringify shared IO core mask, i.e. 0xf -> 3@(0,1),4@(2,3) */
static char *
dpdk_shared_io_core_mask_stringify(uint64_t core_mask)
{
    int cpu_id = 0;
    int io_lcore_id = VR_DPDK_IO_LCORE_ID;
    static char core_mask_string[VR_DPDK_STR_BUF_SZ];
    static char io_cpus_string[VR_DPDK_STR_BUF_SZ];
    char *p = core_mask_string;
    char *iop = io_cpus_string;
    int nb_fwd_cores = 0;

    if (!VR_DPDK_USE_IO_LCORES || !VR_DPDK_SHARED_IO_LCORES)
        return "";

    while (core_mask) {
        if (core_mask & 1) {
            /* add CPU ID to IO lcore string */
            if (iop != io_cpus_string)
                *iop++ = ',';

            iop += snprintf(iop,
                    sizeof(io_cpus_string) - (iop - io_cpus_string),
                    "%d", cpu_id);
            if (iop - io_cpus_string >= sizeof(io_cpus_string)) {
                RTE_LOG(ERR, VROUTER, "Error stringifying IO CPU ID: buffer overflow\n");
                return NULL;
            }

            nb_fwd_cores++;
            if (nb_fwd_cores >= VR_DPDK_FWD_LCORES_PER_IO
                || (core_mask >> 1) == 0) {
                if (io_lcore_id > VR_DPDK_MAX_IO_LCORE_ID) {
                    RTE_LOG(ERR, VROUTER, "Error stringifying IO core mask: IO lcores limit exceeded\n");
                    return NULL;
                }

                p += snprintf(p,
                        sizeof(core_mask_string) - (p - core_mask_string),
                        "%d@(%s),", io_lcore_id, io_cpus_string);
                if (p - core_mask_string >= sizeof(core_mask_string)) {
                    RTE_LOG(ERR, VROUTER, "Error stringifying IO core mask: buffer overflow\n");
                    return NULL;
                }

                io_lcore_id++;
                iop = io_cpus_string;
                nb_fwd_cores = 0;
            }
        }
        core_mask >>= 1;
        cpu_id++;
    }
    *p = '\0';
    return core_mask_string;
}

/* Stringify forwarding and dedicated IO core mask, i.e. 0xf -> 7@0,8@1,9@2,10@3 */
static char *
dpdk_fwd_core_mask_stringify(uint64_t core_mask)
{
    int cpu_id = 0;
    int fwd_lcore_id = VR_DPDK_FWD_LCORE_ID;
    static char core_mask_string[VR_DPDK_STR_BUF_SZ];
    char *p = core_mask_string;
    int io_lcore_id = VR_DPDK_IO_LCORE_ID;
    int nb_fwd_cores = 0;

    while (core_mask) {
        if (core_mask & 1) {
            if (p != core_mask_string)
                *p++ = ',';

            if (VR_DPDK_USE_IO_LCORES && !VR_DPDK_SHARED_IO_LCORES
                    && nb_fwd_cores == 0) {
                /* first dedicated CPU is an IO lcore */
                if (io_lcore_id > VR_DPDK_MAX_IO_LCORE_ID) {
                    RTE_LOG(ERR, VROUTER, "Error stringifying IO core mask: IO lcores limit exceeded\n");
                    return NULL;
                }

                p += snprintf(p,
                        sizeof(core_mask_string) - (p - core_mask_string),
                        "%d@%d", io_lcore_id, cpu_id);
                if (p - core_mask_string >= sizeof(core_mask_string)) {
                    RTE_LOG(ERR, VROUTER, "Error stringifying IO core mask: buffer overflow\n");
                    return NULL;
                }
                io_lcore_id++;
            } else {
                /* forwarding lcore */
                p += snprintf(p,
                        sizeof(core_mask_string) - (p - core_mask_string),
                        "%d@%d", fwd_lcore_id, cpu_id);
                if (p - core_mask_string >= sizeof(core_mask_string)) {
                    RTE_LOG(ERR, VROUTER, "Error stringifying forwarding core mask: buffer overflow\n");
                    return NULL;
                }
                fwd_lcore_id++;
            }

            nb_fwd_cores++;
            if (nb_fwd_cores > VR_DPDK_FWD_LCORES_PER_IO)
                nb_fwd_cores = 0;

        }
        core_mask >>= 1;
        cpu_id++;
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
    uint64_t core_mask, mask_lm_bit;
    char *io_core_mask_str;
    char *fwd_core_mask_str;
    static char lcores_string[VR_DPDK_STR_BUF_SZ];

    /* get number of available CPUs */
    system_cpus_count = sysconf(_SC_NPROCESSORS_CONF);
    if (system_cpus_count == -1) {
        system_cpus_count = __builtin_popcountll(
                (unsigned long long)VR_DPDK_DEF_LCORE_MASK);
    }
    if (system_cpus_count == 0)
        return -1;

    core_mask = dpdk_core_mask_get(system_cpus_count);

    /* calculate number of forwarding and IO lcores */
    vr_dpdk.nb_fwd_lcores = __builtin_popcountll(core_mask);
    vr_dpdk.nb_io_lcores = 0;
    if (VR_DPDK_USE_IO_LCORES) {
        if (VR_DPDK_SHARED_IO_LCORES) {
            vr_dpdk.nb_io_lcores = (vr_dpdk.nb_fwd_lcores + VR_DPDK_FWD_LCORES_PER_IO - 1)
                                    /VR_DPDK_FWD_LCORES_PER_IO;
        } else {
            vr_dpdk.nb_io_lcores = (vr_dpdk.nb_fwd_lcores + VR_DPDK_FWD_LCORES_PER_IO)
                                    /(VR_DPDK_FWD_LCORES_PER_IO + 1);
            vr_dpdk.nb_fwd_lcores -= vr_dpdk.nb_io_lcores;
        }
    }

    /* sanity checks */
    if (vr_dpdk.nb_fwd_lcores == 0) {
        RTE_LOG(ERR, VROUTER, "Error configuring lcores: no forwarding lcores defined\n");
        return -1;
    }
    if (vr_dpdk.nb_io_lcores > 1
        && vr_dpdk.nb_fwd_lcores == VR_DPDK_FWD_LCORES_PER_IO*(vr_dpdk.nb_io_lcores - 1)) {
        /*
         * The last IO lcore has no forwarding lcores.
         * Decrease the number of IO lcores and continue.
         */
        RTE_LOG(INFO, VROUTER, "Adjusting number of IO lcores: %u -> %u\n",
            vr_dpdk.nb_io_lcores, vr_dpdk.nb_io_lcores - 1);
        vr_dpdk.nb_io_lcores--;
        /* remove the leftmost bit from the core mask */
        mask_lm_bit = core_mask;
        mask_lm_bit |= mask_lm_bit >> 32;
        mask_lm_bit |= mask_lm_bit >> 16;
        mask_lm_bit |= mask_lm_bit >> 8;
        mask_lm_bit |= mask_lm_bit >> 4;
        mask_lm_bit |= mask_lm_bit >> 2;
        mask_lm_bit |= mask_lm_bit >> 1;
        mask_lm_bit ^= mask_lm_bit >> 1;
        RTE_LOG(INFO, VROUTER, "Adjusting core mask: 0x%"PRIx64" -> 0x%"PRIx64"\n",
            core_mask, core_mask ^ mask_lm_bit);
        core_mask ^= mask_lm_bit;
    }

    io_core_mask_str = dpdk_shared_io_core_mask_stringify(core_mask);
    if (io_core_mask_str == NULL)
        return -1;

    fwd_core_mask_str = dpdk_fwd_core_mask_stringify(core_mask);
    if (fwd_core_mask_str == NULL)
        return -1;

    /* lcores order: service, IO, lcores with TX queues, forwaridng lcores */
    if (snprintf(lcores_string, sizeof(lcores_string),
        "(0-%d)@(0-%ld),%s(%d-%d)@(0-%ld),%s",
        VR_DPDK_IO_LCORE_ID - 1, system_cpus_count - 1,
        io_core_mask_str,
        VR_DPDK_PACKET_LCORE_ID, VR_DPDK_FWD_LCORE_ID - 1, system_cpus_count - 1,
        fwd_core_mask_str)
            == sizeof(lcores_string)) {
        return -1;
    }

    /* find and update the argument */
    for (i = 0; i < dpdk_argc; i++) {
        if (strncmp(LCORES_ARG, dpdk_argv[i], sizeof(LCORES_ARG)) == 0) {
            dpdk_argv[i + 1] = lcores_string;
            break;
        }
    }

    /* print out configuration */
    if (vr_dpdk.vlan_tag != VLAN_ID_INVALID) {
        RTE_LOG(INFO, VROUTER, "Using VLAN TCI: %" PRIu16 "\n", vr_dpdk.vlan_tag);
    }
    RTE_LOG(INFO, VROUTER, "Bridge Table limit:          %" PRIu32 "\n",
                vr_bridge_entries);
    RTE_LOG(INFO, VROUTER, "Bridge Table overflow limit: %" PRIu32 "\n",
                vr_bridge_oentries);
    RTE_LOG(INFO, VROUTER, "Flow Table limit:            %" PRIu32 "\n",
                vr_flow_entries);
    RTE_LOG(INFO, VROUTER, "Flow Table overflow limit:   %" PRIu32 "\n",
                vr_oflow_entries);
    RTE_LOG(INFO, VROUTER, "MPLS labels limit:           %" PRIu32 "\n",
                vr_mpls_labels);
    RTE_LOG(INFO, VROUTER, "Nexthops limit:              %" PRIu32 "\n",
                vr_nexthops);
    RTE_LOG(INFO, VROUTER, "VRF tables limit:            %" PRIu32 "\n",
                vr_vrfs);
    RTE_LOG(INFO, VROUTER, "EAL arguments:\n");
    for (i = 1; i < dpdk_argc - 1; i += 2) {
        RTE_LOG(INFO, VROUTER, " %12s  \"%s\"\n", dpdk_argv[i], dpdk_argv[i + 1]);
    }

    return 0;
}

static void
version_print(void)
{
    RTE_LOG(INFO, VROUTER, "vRouter/DPDK version: %s\n", ContrailBuildInfo);
}

/* Init DPDK EAL */
static int
dpdk_init(void)
{
    int ret, nb_sys_ports;

    version_print();

    ret = vr_dpdk_flow_mem_init();
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "Error initializing flow table: %s (%d)\n",
            rte_strerror(-ret), -ret);
        return ret;
    }

    if (dpdk_argv_update() == -1) {
        RTE_LOG(ERR, VROUTER, "Error updating lcores arguments\n");
        return -1;
    }

    ret = rte_eal_init(dpdk_argc, dpdk_argv);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "Error initializing EAL\n");
        return ret;
    }
    /* EAL resets the log stream */
    rte_openlog_stream(timestamp_log_stream);

    /* disable unwanted logtypes for debug purposes */
    rte_set_log_type(VR_DPDK_LOGTYPE_DISABLE, 0);

    /* set default log level to INFO */
    rte_set_log_level(RTE_LOG_INFO);

    ret = dpdk_mempools_create();
    if (ret < 0)
        return ret;

    /* get number of ports found in scan */
    nb_sys_ports = rte_eth_dev_count();
    RTE_LOG(INFO, VROUTER, "Found %d eth device(s)\n", nb_sys_ports);

    /* get number of cores */
    RTE_LOG(INFO, VROUTER, "Using %d forwarding lcore(s)\n",
                            vr_dpdk.nb_fwd_lcores);
    RTE_LOG(INFO, VROUTER, "Using %d IO lcore(s)\n",
                            vr_dpdk.nb_io_lcores);
    RTE_LOG(INFO, VROUTER, "Using %d service lcores\n",
                            rte_lcore_count() - vr_dpdk.nb_fwd_lcores
                            - vr_dpdk.nb_io_lcores);

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
    for (i = 0; i < VR_DPDK_MAX_KNI_INTERFACES; i++) {
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

    rte_atomic16_inc(&vr_dpdk.stop_flag);
    vr_dpdk_lcore_cmd_post_all(VR_DPDK_LCORE_STOP_CMD, 0);

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
dpdk_signal_handler_stop(int signum)
{
    RTE_LOG(INFO, VROUTER, "Got signal %d on lcore %u, stopping...\n",
            signum, rte_lcore_id());

    dpdk_stop_flag_set();
}
static void
dpdk_signal_handler_ignore(int signum)
{
    RTE_LOG(INFO, VROUTER, "Got signal %d on lcore %u, ignoring...\n",
            signum, rte_lcore_id());
}

/* Setup signal handlers */
static int
dpdk_signals_init(void)
{
    struct sigaction act;
    sigset_t set;

    memset(&act, 0 , sizeof(act));
    act.sa_handler = dpdk_signal_handler_stop;
    if (sigaction(SIGTERM, &act, NULL) != 0) {
        RTE_LOG(CRIT, VROUTER, "Error registering SIGTERM handler\n");
        return -1;
    }
    if (sigaction(SIGINT, &act, NULL) != 0) {
        RTE_LOG(CRIT, VROUTER, "Error registering SIGINT handler\n");
        return -1;
    }

    act.sa_handler = dpdk_signal_handler_ignore;
    if (sigaction(SIGPIPE, &act, NULL) != 0) {
        RTE_LOG(CRIT, VROUTER, "Error registering SIGPIPE handler\n");
        return -1;
    }

    /* Block (ignore) all the signals for this and all the child threads.
     * The signals will be unblocked for the master lcore later during
     * the lcore intialization.
     */
    sigfillset(&set);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        RTE_LOG(CRIT, VROUTER, "Error setting signal mask\n");
        return -1;
    }

    return 0;
}

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

enum vr_opt_index {
    NO_DAEMON_OPT_INDEX,
    HELP_OPT_INDEX,
    VERSION_OPT_INDEX,
    VLAN_TCI_OPT_INDEX,
    VLAN_NAME_OPT_INDEX,
    VDEV_OPT_INDEX,
    BRIDGE_ENTRIES_OPT_INDEX,
    BRIDGE_OENTRIES_OPT_INDEX,
    FLOW_ENTRIES_OPT_INDEX,
    OFLOW_ENTRIES_OPT_INDEX,
    MPLS_LABELS_OPT_INDEX,
    NEXTHOPS_OPT_INDEX,
    VRFS_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [NO_DAEMON_OPT_INDEX]           =   {"no-daemon",           no_argument,
                                                    &no_daemon_set,         1},
    [HELP_OPT_INDEX]                =   {"help",                no_argument,
                                                    NULL,                   0},
    [VERSION_OPT_INDEX]             =   {"version",             no_argument,
                                                    NULL,                   0},
    [VLAN_TCI_OPT_INDEX]            =   {"vlan_tci",            required_argument,
                                                    NULL,                   0},
    [VLAN_NAME_OPT_INDEX]           =   {"vlan_fwd_intf_name",  required_argument,
                                                    NULL,                   0},
    [VDEV_OPT_INDEX]                =   {"vdev",                required_argument,
                                                    NULL,                   0},
    [BRIDGE_ENTRIES_OPT_INDEX]      =   {"vr_bridge_entries",   required_argument,
                                                    NULL,                   0},
    [BRIDGE_OENTRIES_OPT_INDEX]     =   {"vr_bridge_oentries",  required_argument,
                                                    NULL,                   0},
    [FLOW_ENTRIES_OPT_INDEX]        =   {"vr_flow_entries",     required_argument,
                                                    NULL,                   0},
    [OFLOW_ENTRIES_OPT_INDEX]       =   {"vr_oflow_entries",    required_argument,
                                                    NULL,                   0},
    [MPLS_LABELS_OPT_INDEX]         =   {"vr_mpls_labels",      required_argument,
                                                    NULL,                   0},
    [NEXTHOPS_OPT_INDEX]            =   {"vr_nexthops",         required_argument,
                                                    NULL,                   0},
    [VRFS_OPT_INDEX]                =   {"vr_vrfs",             required_argument,
                                                    NULL,                   0},
    [MAX_OPT_INDEX]                 =   {NULL,                  0,
                                                    NULL,                   0},
};

static void
Usage(void)
{
    printf(
        "Usage:   contrail-vrouter-dpdk [--no-daemon] [--help] [--version]\n"
        "             [--vdev <config>]\n"
        "             [--vlan_tci <tci>] [--vlan_fwd_intf_name <name>]\n"
        "             [--vr_bridge_entries <number>] [--vr_bridge_oentries <number>]\n"
        "             [--vr_flow_entries <number>] [--vr_oflow_entries <number>]\n"
        "             [--vr_mpls_labels <number>] [--vr_nexthops <number>]\n"
        "             [--vr_vrfs <number>]\n"
        "\n"
        "--no-daemon  Do not demonize the vRouter\n"
        "--help       Prints this help message\n"
        "--version    Prints build information\n"
        "\n"
        "--vdev                 <config>    Virtual device configuration\n"
        "--vlan_tci             <tci>       VLAN tag control information\n"
        "--vlan_fwd_intf_name   <name>      VLAN forwarding interface name\n"
        "\n"
        "--vr_bridge_entries    <number>    Bridge Table limit\n"
        "--vr_bridge_oentries   <number>    Bridge Table overflow limit\n"
        "--vr_flow_entries      <number>    Flow Table limit\n"
        "--vr_oflow_entries     <number>    Flow Table overflow limit\n"
        "--vr_mpls_labels       <number>    MPLS labels limit\n"
        "--vr_nexthops          <number>    Nexthop limit\n"
        "--vr_vrfs              <number>    VRF tables limit\n"
        );

    exit(1);
}

static void
parse_long_opts(int opt_flow_index, char *opt_arg)
{
    int i;

    errno = 0;
    switch (opt_flow_index) {
    case NO_DAEMON_OPT_INDEX:
        break;

    case VERSION_OPT_INDEX:
        version_print();
        exit(0);
        break;

    /*
     * If VLAN tag is set, vRouter will expect tagged packets. The tag
     * will be stripped by NIC or in vr_dpdk_ethdev_rx_emulate() and
     * injected in dpdk_if_tx().
     *
     * Received packets with unmatching tag will be forwarded to the VLAN
     * forwarding interface, that is created in main(). Packets sent on that
     * interface will be immediately forwarded to the physical interface.
     *
     * See following funtions: dpdk_lcore_fwd_io(), vr_dpdk_ethdev_rx_emulate(),
     * vr_dpdk_lcore_vroute(), dpdk_vlan_forwarding_if_add().
     */
    case VLAN_TCI_OPT_INDEX:
        vr_dpdk.vlan_tag = (uint16_t)strtol(optarg, NULL, 0);
        if (errno != 0) {
            vr_dpdk.vlan_tag = VLAN_ID_INVALID;
        }
        break;

    /*
     * VLAN packets with unmatching tag will be forwarded to the kernel using
     * an interface with name defined here.
     */
    case VLAN_NAME_OPT_INDEX:
        strncpy(vr_dpdk.vlan_name, opt_arg, sizeof(vr_dpdk.vlan_name) - 1);
        break;


    case VDEV_OPT_INDEX:
        /* find a pair of free arguments */
        for (i = 0; i < RTE_DIM(dpdk_argv) - 1; i++) {
            if (dpdk_argv[i] == NULL && dpdk_argv[i + 1] == NULL) {
                dpdk_argv[i] = "--vdev";
                dpdk_argv[i + 1] = opt_arg;
                dpdk_argc += 2;
                break;
            }
        }
        break;

    case BRIDGE_ENTRIES_OPT_INDEX:
        vr_bridge_entries = (unsigned int)strtoul(optarg, NULL, 0);
        if (errno != 0) {
            vr_bridge_entries = VR_DEF_BRIDGE_ENTRIES;
        }
        break;

    case BRIDGE_OENTRIES_OPT_INDEX:
        vr_bridge_oentries = (unsigned int)strtoul(optarg, NULL, 0);
        if (errno != 0) {
            vr_bridge_oentries = VR_DEF_BRIDGE_OENTRIES;
        }
        break;

    case FLOW_ENTRIES_OPT_INDEX:
        vr_flow_entries = (unsigned int)strtoul(optarg, NULL, 0);
        if (errno != 0) {
            vr_flow_entries = VR_DEF_FLOW_ENTRIES;
        }
        break;

    case OFLOW_ENTRIES_OPT_INDEX:
        vr_oflow_entries = (unsigned int)strtoul(optarg, NULL, 0);
        if (errno != 0) {
            vr_oflow_entries = VR_DEF_OFLOW_ENTRIES;
        }
        break;

    case MPLS_LABELS_OPT_INDEX:
        vr_mpls_labels = (unsigned int)strtoul(optarg, NULL, 0);
        if (errno != 0) {
            vr_mpls_labels = VR_DEF_LABELS;
        }
        break;

    case NEXTHOPS_OPT_INDEX:
        vr_nexthops = (unsigned int)strtoul(optarg, NULL, 0);
        if (errno != 0) {
            vr_nexthops = VR_DEF_NEXTHOPS;
        }
        break;

    case VRFS_OPT_INDEX:
        vr_vrfs = (unsigned int)strtoul(optarg, NULL, 0);
        if (errno != 0) {
            vr_vrfs = VR_DEF_VRFS;
        }
        break;

    case HELP_OPT_INDEX:
    default:
        Usage();
    }
}

static ssize_t
timestamp_log_write(__attribute__((unused)) void *c, const char *buf, size_t size)
{
    ssize_t ret;
    struct timeval tv;
    struct tm *tm;
    char outbuf[VR_DPDK_STR_BUF_SZ];
    size_t len = 0;

    gettimeofday(&tv, NULL);
    if ((tm = localtime(&tv.tv_sec)) != NULL) {
        len += strftime(outbuf, sizeof(outbuf) - len, VR_DPDK_TIMESTAMP, tm);
        len += snprintf(outbuf + len, sizeof(outbuf) - len, ",%03lu ", tv.tv_usec/1000);
    }

    strncpy(outbuf + len, buf, sizeof(outbuf) - len);
    if (sizeof(outbuf) - len > size)
        len += size;
    else
        len = sizeof(outbuf);

    ret = fwrite(outbuf, len, 1, stdout);
    fflush(stdout);

    if (ret == 0)
        return -1;

    return ret;
}
static cookie_io_functions_t timestamp_log_func = {
    .write = timestamp_log_write,
};

int
main(int argc, char *argv[])
{
    int ret, opt, option_index;
    vr_dpdk.vlan_tag = VLAN_ID_INVALID;
    strncpy(vr_dpdk.vlan_name, VR_DPDK_VLAN_FWD_DEF_NAME,
        sizeof(vr_dpdk.vlan_name) - 1);

    /* init the timestamp log */
    timestamp_log_stream = fopencookie(NULL, "w+", timestamp_log_func);
    if (timestamp_log_stream == NULL) {
        printf("Error configuring log stream. Falling back to stdout.\n");
        timestamp_log_stream = stdout;
    }
    rte_openlog_stream(timestamp_log_stream);

    while ((opt = getopt_long(argc, argv, "", long_options, &option_index))
            >= 0) {
        switch (opt) {
        case 0:
            parse_long_opts(option_index, optarg);
            break;

        case '?':
        default:
            RTE_LOG(ERR, VROUTER, "Invalid option %s\n", argv[optind - 1]);
            Usage();
            break;
        }
    }
    /* for other getopts in DPDK */
    optind = 0;

    if (!no_daemon_set) {
        if (daemon(0, 0) < 0) {
            RTE_LOG(ERR, VROUTER, "Error daemonizing vRouter: %s (%d)\n",
                rte_strerror(errno), errno);
            return 1;
        }
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

    /* Init fragment assembler */
    ret = dpdk_fragment_assembler_init();
    if (ret != 0) {
        vr_dpdk_host_exit();
        dpdk_fragment_assembler_exit();
        dpdk_exit();
        return ret;
    }

    /* create VLAN forwarding interface if needed */
    if (vr_dpdk.vlan_tag != VLAN_ID_INVALID) {
        ret = dpdk_vlan_forwarding_if_add();
        if (ret != 0) {
            vr_dpdk_host_exit();
            dpdk_fragment_assembler_exit();
            dpdk_exit();
            return ret;
        }
    }

    /* run all the lcores */
    ret = rte_eal_mp_remote_launch(vr_dpdk_lcore_launch, NULL, CALL_MASTER);

    rte_eal_mp_wait_lcore();
    dpdk_fragment_assembler_exit();
    dpdk_netlink_exit();
    vr_dpdk_host_exit();
    dpdk_exit();

    rte_exit(ret, "vRouter/DPDK is stopped.\n");
}
