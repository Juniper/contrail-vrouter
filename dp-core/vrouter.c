/*
 * se ts=4;se expandtab
 *
 * vrouter.c -- virtual router
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#if defined(__linux__)
#include <linux/version.h>
#endif
#include "vr_types.h"
#include "vr_sandesh.h"
#include "vr_message.h"
#include <vr_packet.h>
#include <vr_interface.h>
#include <vr_nexthop.h>
#include <vr_route.h>
#include <vr_mpls.h>
#include <vr_flow.h>
#include <vr_bridge.h>
#include <vr_packet.h>
#include <vr_mirror.h>
#include <vr_vxlan.h>

static struct vrouter router;
struct host_os *vrouter_host;

extern struct host_os *vrouter_get_host(void);
extern int vr_stats_init(struct vrouter *);
extern void vr_stats_exit(struct vrouter *, bool);

extern unsigned int vr_flow_entries;
extern unsigned int vr_oflow_entries;
extern unsigned int vr_bridge_entries;
extern unsigned int vr_bridge_oentries;
extern const char *ContrailBuildInfo;

void vrouter_exit(bool);

volatile bool vr_not_ready = true;

struct vr_module {
    char *mod_name;
    int error;
    const char *error_func;
    int error_line;
    int error_data;
    int (*init)(struct vrouter *);
    void (*exit)(struct vrouter *, bool);
    void (*shut)(struct vrouter *);
};

struct vr_module *module_under_init;

static struct vr_module modules[] = {
    {
        .mod_name       =       "Stats",
        .init           =       vr_stats_init,
        .exit           =       vr_stats_exit,
    },
    {
        .mod_name       =       "Interface",
        .init           =       vr_interface_init,
        .exit           =       vr_interface_exit,
        .shut           =       vr_interface_shut,
    },
    {
        .mod_name       =       "Nexthop",
        .init           =       vr_nexthop_init,
        .exit           =       vr_nexthop_exit,
    },
    {
        .mod_name       =       "Fib",
        .init           =       vr_fib_init,
        .exit           =       vr_fib_exit,
    },
    {
        .mod_name       =       "Mpls",
        .init           =       vr_mpls_init,
        .exit           =       vr_mpls_exit,
    },
    {
        .mod_name       =       "Flow",
        .init           =       vr_flow_init,
        .exit           =       vr_flow_exit,
    },
    {
        .mod_name       =       "Mirror",
        .init           =       vr_mirror_init,
        .exit           =       vr_mirror_exit,
    },
    {
        .mod_name       =       "Vxlan",
        .init           =       vr_vxlan_init,
        .exit           =       vr_vxlan_exit,
    },

};


#define VR_NUM_MODULES  (sizeof(modules) / sizeof(modules[0]))
/*
 * TODO For BSD we turn off all performance tweaks for now, it will
 * be implemented later.
 */
/*
 * Enable changes for better performance
 */
#if defined(__linux__)
int vr_perfr = 1;    /* GRO */
int vr_perfs = 1;    /* segmentation in software */
#elif defined(__FreeBSD__)
int vr_perfr = 0;    /* GRO */
int vr_perfs = 0;    /* segmentation in software */
#endif

/*
 * Enable MPLS over UDP globally
 */
int vr_mudp = 0;

/*
 * TCP MSS adjust settings
 */
#if defined(__linux__)
int vr_from_vm_mss_adj = 1; /* adjust TCP MSS on packets from VM */
int vr_to_vm_mss_adj = 1;   /* adjust TCP MSS on packet sent to VM */
#elif defined(__FreeBSD__)
int vr_from_vm_mss_adj = 0; /* adjust TCP MSS on packets from VM */
int vr_to_vm_mss_adj = 0;   /* adjust TCP MSS on packet sent to VM */
#endif
/*
 * Following sysctls are to enable RPS. Based on empirical results,
 * performing RPS immediately after packets arrive on a physical interface
 * gives the best bidirectional throughput (as opposed to performing
 * RPS after pulling inner headers on the CPU core which received the
 * interrupt from the physical interface). This is probably because
 * more work can happen in parallel on multiple cores in the former case.
 * So, vr_perfr1 is set to 0 and vr_perfr3 is set to 1. vr_perfr2 is always
 * set as the vhost thread is usually scheduled on the CPU which received
 * the packet after GRO. Setting vr_perfr2 allows us to influence the
 * scheduling of the vhost thread to some extent (otherwise the scheduler
 * can sometimes make sub-optimal choices such as scheduling it on the CPU
 * which receives interrupts from the physical interface). vrouter ensures
 * that the receive processing happens on multiple cores which are in the
 * same NUMA node as the physical interface i.e. the CPU core which receives
 * packets from the physical interface is different from the CPU core which
 * does vrouter RX processing. A third CPU core does GRO processing (assuming
 * that enough cores are available). Also, hyper-thread siblings of the
 * above 3 cores are not used by vrouter for RX processing.
 */
#if defined(__linux__)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))

int vr_perfr1 = 0;   /* RPS after pulling inner headers */
int vr_perfr2 = 1;   /* RPS after GRO on pkt1 interface */
int vr_perfr3 = 1;   /* RPS from physical interface rx handler */
int vr_perfp = 1;    /* pull inner headers, faster version */

int vr_use_linux_br = 0; /* nop if netdev_rx_handler_register() is used */

#else

#if defined(RHEL_MAJOR) && defined(RHEL_MINOR) && \
           (RHEL_MAJOR == 6) && (RHEL_MINOR >= 4)

int vr_perfr1 = 0;
int vr_perfr2 = 1;
int vr_perfr3 = 1;
int vr_perfp = 1;
int vr_use_linux_br = 0; /* Centos 6.4 and higher */

#else

int vr_perfr1 = 0;
int vr_perfr2 = 0;
int vr_perfr3 = 0;
int vr_perfp = 0;
int vr_use_linux_br = 1; /* Xen */

#endif
#endif
#endif /* __linux__ */
#if defined(__FreeBSD__)
int vr_perfp = 0;
#endif
/*
 * Following sysctls can be set if vrouter shouldn't pick a CPU for RPS
 * core based on a hash of the received packet. Turned off by default.
 */
int vr_perfq1 = 0;   /* CPU to send packets to if vr_perfr1 is 1 */
int vr_perfq2 = 0;   /* CPU to send packets to if vr_perfr2 is 1 */
int vr_perfq3 = 0;   /* CPU to send packets to if vr_perfr3 is 1 */

/* Should NIC perform checksum offload for outer UDP header? */
int vr_udp_coff = 0;

int
vr_module_error(int error, const char *func,
        int line, int mod_specific)
{
    struct vr_module *module = module_under_init;

    /*
     * set the error only if it was not set earlier. sometimes, the module
     * init can call functions which fail and set the error. In those cases,
     * for the sake of consistency, the module init should also be able to
     * call this function without overwriting the set error data
     */
    if (module && !module->error) {
        module->error = error;
        module->error_func = func;
        module->error_line = line;
        module->error_data = mod_specific;
    }

    return error;
}

static void
vr_module_debug_dump(void)
{
    struct vr_module *module = module_under_init;

    if (!module)
        return;

    vr_printf("vrouter (%s): Init failed at %s:%d with return %d (data %d)\n",
            module->mod_name, module->error_func, module->error_line,
            module->error, module->error_data);

    /* reset error data */
    module->error = 0;
    module->error_func = NULL;
    module->error_line = -1;
    module->error_data = 0;

    return;
}

struct vrouter *
vrouter_get(unsigned int vr_id)
{
    return &router;
}

static void
vrouter_ops_destroy(vrouter_ops *req)
{
    if (!req)
        return;

    if (req->vo_build_info) {
        vr_free(req->vo_build_info);
        req->vo_build_info = NULL;
    }

    vr_free(req->vo_build_info);

    return;
}

static vrouter_ops *
vrouter_ops_get(void)
{
    vrouter_ops *req;

    req = vr_malloc(sizeof(*req));
    if (!req)
        return NULL;

    req->vo_build_info = vr_zalloc(strlen(ContrailBuildInfo));
    if (!req->vo_build_info) {
        vr_free(req);
        return NULL;
    }

    return req;
}

void
vrouter_ops_get_process(void *s_req)
{
    int ret = 0;
    struct vrouter *router;
    vrouter_ops *req = (vrouter_ops *)s_req;
    vrouter_ops *resp = NULL;

    if (req->h_op != SANDESH_OP_GET) {
        ret = -EOPNOTSUPP;
        goto generate_response;
    }

    router = vrouter_get(req->vo_rid);
    if (!router) {
        ret = -EINVAL;
        goto generate_response;
    }

    resp = vrouter_ops_get();
    if (!resp) {
        ret = -ENOMEM;
        goto generate_response;
    }

    resp->vo_interfaces = router->vr_max_interfaces;
    resp->vo_vrfs = router->vr_max_vrfs;
    resp->vo_mpls_labels = router->vr_max_labels;
    resp->vo_nexthops = router->vr_max_nexthops;
    resp->vo_bridge_entries = vr_bridge_entries;
    resp->vo_oflow_bridge_entries = vr_bridge_oentries;
    resp->vo_flow_entries = vr_flow_entries;
    resp->vo_oflow_entries = vr_oflow_entries;
    resp->vo_mirror_entries = router->vr_max_mirror_indices;
    strncpy(resp->vo_build_info, ContrailBuildInfo,
            strlen(ContrailBuildInfo));

    req = resp;
generate_response:
    if (ret)
        req = NULL;

    vr_message_response(VR_VROUTER_OPS_OBJECT_ID, req, ret);
    if (resp)
        vrouter_ops_destroy(resp);

    return;
}

void
vrouter_exit(bool soft_reset)
{
    int i;

    for (i = 0; i < (int)VR_NUM_MODULES; i++)
        if (modules[i].shut)
            modules[i].shut(&router);

    /* After all the modules are shut: Vrouter is really not ready */
    vr_not_ready = true;

    for (i = VR_NUM_MODULES - 1; i >= 0; --i) {
        modules[i].exit(&router, soft_reset);
    }

    return;
}

int
vrouter_init(void)
{
    unsigned int i;
    int ret;

    vrouter_host = vrouter_get_host();
    if (!vrouter_host && (ret = -ENOMEM))
        goto init_fail;

    for (i = 0; i < VR_NUM_MODULES; i++) {
        module_under_init = &modules[i];
        ret = modules[i].init(&router);
        if (ret) {
            vr_printf("vrouter module %u init error (%d)\n", i, ret);
            goto init_fail;
        }
    }

    module_under_init = NULL;
    vr_not_ready = false;
    return 0;

init_fail:
    vrouter_exit(false);
    vr_module_debug_dump();
    module_under_init = NULL;

    return ret;
}

static int
vrouter_soft_reset(void)
{
    vrouter_exit(true);
    return vrouter_init();
}

void
vrouter_ops_process(void *s_req)
{
    int ret;

    vrouter_ops *ops = (vrouter_ops *)s_req;

    switch (ops->h_op) {
    case SANDESH_OP_RESET:
        vr_printf("vrouter soft reset start\n");
        ret = vrouter_soft_reset();
        vr_printf("vrouter soft reset done (%d)\n", ret);
        break;

    case SANDESH_OP_GET:
        vrouter_ops_get_process(s_req);
        return;

    default:
        ret = -EOPNOTSUPP;
    }

    vr_send_response(ret);

    return;
}

