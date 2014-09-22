/*
 * vr_route.c -- route management
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include "vr_message.h"
#include "vr_sandesh.h"

static struct rtable_fspec rtable_families[];
extern int mtrie_algo_init(struct vr_rtable *, struct rtable_fspec *);
extern void mtrie_algo_deinit(struct vr_rtable *, struct rtable_fspec *, bool);
extern int mcast_algo_init(struct vr_rtable *, struct rtable_fspec *);
extern void mcast_algo_deinit(struct vr_rtable *, struct rtable_fspec *, bool);
extern int bridge_table_init(struct vr_rtable *, struct rtable_fspec *);
extern void bridge_table_deinit(struct vr_rtable *, struct rtable_fspec *, bool);


static struct rtable_fspec *
vr_get_family(unsigned int family)
{
    switch (family) {
    case AF_INET:
        return &rtable_families[0];
    case AF_BRIDGE:
        return &rtable_families[1];
    case AF_INET6:
        return &rtable_families[2];

    default:
        return NULL;
    }

    return NULL;
}

int
vr_route_delete(vr_route_req *req)
{
    struct rtable_fspec *fs;
    struct vr_route_req vr_req;
    int ret;
    uint32_t rt_prefix[4];

    fs = vr_get_family(req->rtr_family);
    if (!fs)
        ret = -ENOENT;
    else {
        vr_req.rtr_req = *req;

        if (req->rtr_family != AF_BRIDGE && !req->rtr_prefix_size) {
            ret = -EINVAL;
            goto error;
        }

        if (req ->rtr_family == AF_BRIDGE && 
                (!req->rtr_mac_size  || !req->rtr_mac)) {
            ret = -EINVAL;
            goto error;
        }

        if (req ->rtr_family != AF_BRIDGE) {
            vr_req.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
            memcpy(vr_req.rtr_req.rtr_prefix, req->rtr_prefix, RT_IP_ADDR_SIZE(req->rtr_family));
        }
        vr_req.rtr_req.rtr_src_size = vr_req.rtr_req.rtr_marker_size = 0;
        ret = fs->route_del(fs, &vr_req);
    }

error:
    vr_send_response(ret);

    return ret;
}

int
vr_route_add(vr_route_req *req)
{
    struct rtable_fspec *fs;
    struct vr_route_req vr_req;
    int ret;
    uint32_t rt_prefix[4];

    fs = vr_get_family(req->rtr_family);
    if (!fs) {
        ret = -ENOENT;
    } else {
        vr_req.rtr_req = *req;
        if (req->rtr_prefix_size) {
            vr_req.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
            memcpy(vr_req.rtr_req.rtr_prefix, req->rtr_prefix, RT_IP_ADDR_SIZE(req->rtr_family));
            vr_req.rtr_req.rtr_src_size = vr_req.rtr_req.rtr_marker_size = 0;
            vr_req.rtr_req.rtr_prefix_size = req->rtr_prefix_size;
        } else {
           vr_req.rtr_req.rtr_prefix = NULL;
        }

        ret = fs->route_add(fs, &vr_req);
    }

    vr_send_response(ret);

    return ret;
}

static struct vr_rtable *
vr_get_inet_table(struct vrouter *router, int id) 
{
    if (!router)
        return NULL;

    if (id == RT_UCAST) 
        return router->vr_inet_rtable;
    else if (id == RT_MCAST) 
        return router->vr_inet_mcast_rtable;
    
    return NULL;
}

static void
vr_put_inet_table(struct vrouter *router, int id, struct vr_rtable *table)
{
    if (!router)
        return;

    if (id == RT_UCAST)
        router->vr_inet_rtable = table;
    else if (id == RT_MCAST)
        router->vr_inet_mcast_rtable = table;

    return;
}


int
vr_route_get(vr_route_req *req)
{
    struct vr_route_req vr_req;
    struct vrouter *router;
    struct vr_rtable *rtable;
    int ret = 0;
    uint32_t rt_prefix[4], rt_src[4];
   
    vr_req.rtr_req = *req;

    vr_req.rtr_req.rtr_marker_size = 0;
    vr_req.rtr_req.rtr_prefix_size = req->rtr_prefix_size;
    if (req->rtr_prefix_size) {
        vr_req.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
        memcpy(vr_req.rtr_req.rtr_prefix, req->rtr_prefix, RT_IP_ADDR_SIZE(req->rtr_family));
    } else
        vr_req.rtr_req.rtr_prefix = NULL;

    vr_req.rtr_req.rtr_src_size = req->rtr_src_size;
    if (req->rtr_src_size) {
        vr_req.rtr_req.rtr_src = (uint8_t*)&rt_src;
        memcpy(vr_req.rtr_req.rtr_src, req->rtr_src, RT_IP_ADDR_SIZE(req->rtr_family));
    } else
        vr_req.rtr_req.rtr_src = NULL;

    router = vrouter_get(req->rtr_rid);
    if (!router) {
        ret = -ENOENT;
        goto generate_response;
    } else {

        rtable = vr_get_inet_table(router, req->rtr_rt_type);
        if (!rtable) {
            ret = -ENOENT;
            goto generate_response;
        }

        ret = rtable->algo_get(vr_req.rtr_req.rtr_vrf_id, &vr_req);
    }

generate_response:
    vr_message_response(VR_ROUTE_OBJECT_ID, ret ? NULL : &vr_req, ret);
    return ret;
}

int
vr_route_dump(vr_route_req *req)
{
    struct vr_route_req vr_req;
    struct vrouter *router;
    struct vr_rtable *rtable = NULL;
    int ret;
    uint32_t rt_prefix[4], rt_src[4], rt_marker[4];
   
    vr_req.rtr_req = *req;
    vr_req.rtr_req.rtr_prefix_size = req->rtr_prefix_size;
    if (req->rtr_prefix_size) {
        vr_req.rtr_req.rtr_prefix = (uint8_t*)&rt_prefix;
        memcpy(vr_req.rtr_req.rtr_prefix, req->rtr_prefix, RT_IP_ADDR_SIZE(req->rtr_family));
    } else {
        vr_req.rtr_req.rtr_prefix = NULL;
    }
        
    vr_req.rtr_req.rtr_marker_size = req->rtr_marker_size;
    vr_req.rtr_req.rtr_marker_plen = req->rtr_prefix_len;
    if (req->rtr_marker_size) {
        vr_req.rtr_req.rtr_marker = (uint8_t*)&rt_marker;
        memcpy(vr_req.rtr_req.rtr_marker, req->rtr_marker, RT_IP_ADDR_SIZE(req->rtr_family));
    } else {
        vr_req.rtr_req.rtr_marker = NULL;
    }
        
    vr_req.rtr_req.rtr_src_size = req->rtr_src_size;
    if (req->rtr_src_size) {
        vr_req.rtr_req.rtr_src = (uint8_t*)&rt_src;
        memcpy(vr_req.rtr_req.rtr_src, req->rtr_src, RT_IP_ADDR_SIZE(req->rtr_family));
    } else
        vr_req.rtr_req.rtr_src = NULL;

    router = vrouter_get(req->rtr_rid);
    if (!router) {
        ret = -ENOENT;
        goto generate_error;
    } else {

        if (req->rtr_family == AF_BRIDGE) {
            rtable = router->vr_bridge_rtable;
        } else  {
            rtable = vr_get_inet_table(router, req->rtr_rt_type);
        }

        if (!rtable) {
            ret = -ENOENT;
            goto generate_error;
        }

        ret = rtable->algo_dump(NULL, &vr_req);
    }
    return ret;

generate_error:
    vr_send_response(ret);

    return ret;
}

void
vr_route_req_process(void *s_req)
{
    vr_route_req *req = (vr_route_req *)s_req;

    switch (req->h_op) {
    case SANDESH_OP_ADD:
        vr_route_add(req);
        break;

    case SANDESH_OP_DELETE:
        vr_route_delete(req);
        break;

    case SANDESH_OP_GET:
        vr_route_get(req);
        break;

    case SANDESH_OP_DUMP:
        vr_route_dump(req);
        break;

    default:
        break;
    }

    return;
}

static void
vr_inet_vrf_stats_dump(struct vrouter *router, vr_vrf_stats_req *req)
{
    int ret = 0;
    struct vr_rtable *rtable;

    rtable = vr_get_inet_table(router, req->vsr_type);
    if (!rtable) {
        ret = -ENOENT;
        goto generate_error;
    }

    ret = rtable->algo_stats_dump(rtable, req);
    return;

generate_error:
    vr_send_response(ret);
    return; 
}

static void
vr_inet_vrf_stats_get(struct vrouter *router, vr_vrf_stats_req *req)
{
    int ret = 0;
    struct vr_rtable *rtable;
    vr_vrf_stats_req response;

    rtable = vr_get_inet_table(router, req->vsr_type);
    if (!rtable) {
        ret = -ENOENT;
        goto generate_error;
    }

    if (req->vsr_vrf >= 0 && 
            (unsigned int)req->vsr_vrf >= rtable->algo_max_vrfs) {
        ret = -EINVAL;
        goto generate_error;
    }

    ret = rtable->algo_stats_get(req, &response);
generate_error:
    vr_message_response(VR_VRF_STATS_OBJECT_ID, ret ? NULL : &response, ret);
    return;
}

static void
vr_inet_vrf_stats_op(struct vrouter *router, vr_vrf_stats_req *req)
{
    if (req->h_op == SANDESH_OP_GET)
        vr_inet_vrf_stats_get(router, req);
    else if (req->h_op == SANDESH_OP_DUMP)
        vr_inet_vrf_stats_dump(router, req);

    return;
}

static void
vr_vrf_stats_op(vr_vrf_stats_req *req)
{
    int ret = 0;
    struct vrouter *router;

    if (req->vsr_type == RT_MCAST) {
        ret = -EOPNOTSUPP;
        goto generate_error;
    }

    router = vrouter_get(req->vsr_rid);
    if (!router) {
        ret = -EINVAL;
        goto generate_error;
    }

    switch (req->vsr_family) {
    case AF_INET:
        vr_inet_vrf_stats_op(router, req);
        break;

    default:
        ret = -EINVAL;
        goto generate_error;
    }

    return; 

generate_error:
    vr_send_response(ret);
    return;
}

void
vr_vrf_stats_req_process(void *s_req)
{
    vr_vrf_stats_req *req = (vr_vrf_stats_req *)s_req;

    switch (req->h_op) {
    case SANDESH_OP_GET:
    case SANDESH_OP_DUMP:
        vr_vrf_stats_op(req);
        break;

    default:
        break;
    }

    return;
}

int
inet_route_add(struct rtable_fspec *fs, struct vr_route_req *req)
{
    int i;
    struct vr_rtable *rtable;
    struct vrouter *router;
    unsigned int pmask, pmask_byte;

    router = vrouter_get(req->rtr_req.rtr_rid);
    if (!router)
        return -EINVAL;

    rtable = vr_get_inet_table(router, req->rtr_req.rtr_rt_type);
    if (!rtable ||
            ((unsigned int)req->rtr_req.rtr_vrf_id > fs->rtb_max_vrfs) ||
            ((unsigned int)(req->rtr_req.rtr_prefix_len) > 
                            (RT_IP_ADDR_SIZE(req->rtr_req.rtr_family)*8)))
        return -EINVAL;

    if (req->rtr_req.rtr_prefix) {

        if (req->rtr_req.rtr_family == AF_INET)
            pmask = ~((1 << (32 - req->rtr_req.rtr_prefix_len)) - 1);
        else
            pmask = 0; //TBD: Assume V6 prefix length will be multiple of 8
            
        pmask_byte = req->rtr_req.rtr_prefix_len/8;
        if (pmask_byte < (RT_IP_ADDR_SIZE(req->rtr_req.rtr_family)-1)) {
            for (i=pmask_byte+1; i<RT_IP_ADDR_SIZE(req->rtr_req.rtr_family); i++) {
                req->rtr_req.rtr_prefix[i] = 0;
                pmask = pmask >> 8;
            }
            req->rtr_req.rtr_prefix[pmask_byte] = 
                         req->rtr_req.rtr_prefix[pmask_byte] & (pmask & 0xff);
        }
    } 

    if (rtable) {
        if (rtable->algo_add)
            return rtable->algo_add(rtable, req);
        else
            return -1;
        } else {
        return -1;
    }
}

int
inet_route_del(struct rtable_fspec *fs, struct vr_route_req *req)
{
    struct vr_rtable *rtable;
    struct vrouter *router;

    if (((unsigned int)(req->rtr_req.rtr_prefix_len) > 
                            (RT_IP_ADDR_SIZE(req->rtr_req.rtr_family)*8)) ||
            (unsigned int)(req->rtr_req.rtr_vrf_id) >= VR_MAX_VRFS)
        return -EINVAL;

    router = vrouter_get(req->rtr_req.rtr_rid);
    if (!router)
        return -EINVAL;

    rtable = vr_get_inet_table(router, req->rtr_req.rtr_rt_type);
    if (!rtable || req->rtr_req.rtr_vrf_id >= (int)fs->rtb_max_vrfs)
        return -EINVAL;

    return rtable->algo_del(rtable, req);
}

static void
inet_rtb_family_deinit(struct rtable_fspec *fs, struct vrouter *router, 
                                                        bool soft_reset)
{
	struct vr_rtable *rtable;
    int i;

    for (i = 0; i < RT_MAX; i++) {
        rtable = vr_get_inet_table(router, i);
        if (rtable) {
            fs->algo_deinit[i](rtable, fs, soft_reset);
            if (i == RT_UCAST) { 
                vr_free(rtable);
                vr_put_inet_table(router, i, NULL);
            }
            if ((i == RT_MCAST) && !soft_reset) {
                vr_free(rtable);
                vr_put_inet_table(router, i, NULL);
            }
        }
    }
   
    return;
}

static int
inet_rtb_family_init(struct rtable_fspec *fs, struct vrouter *router)
{
    int ret;
    struct vr_rtable *table = NULL;
    unsigned int i;

    for (i = 0; i < RT_MAX; i++) {

        if (!fs->algo_init[i])
            continue;

        if (vr_get_inet_table(router, i))
            continue;

        table = vr_zalloc(sizeof(struct vr_rtable));
        if (!table) 
            return vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, i);

        ret = fs->algo_init[i](table, fs);
        if (ret)
            return vr_module_error(ret, __FUNCTION__, __LINE__, i);

        vr_put_inet_table(router, i, table);
    }

    return 0;
}

int
bridge_entry_add(struct rtable_fspec *fs, struct vr_route_req *req)
{
    struct vrouter *router;

    router = vrouter_get(req->rtr_req.rtr_rid);
    if (!router)
        return -EINVAL;

    if (!router->vr_bridge_rtable ||
            ((unsigned int)req->rtr_req.rtr_vrf_id > fs->rtb_max_vrfs) ||
            ((unsigned int)(req->rtr_req.rtr_mac_size) != VR_ETHER_ALEN))
        return -EINVAL;

    return router->vr_bridge_rtable->algo_add(router->vr_bridge_rtable, req);
}

int
bridge_entry_del(struct rtable_fspec *fs, struct vr_route_req *req)
{
    struct vrouter *router;

    if ((unsigned int)(req->rtr_req.rtr_mac_size) > 6 ||
            (unsigned int)(req->rtr_req.rtr_vrf_id) >= VR_MAX_VRFS)
        return -EINVAL;

    router = vrouter_get(req->rtr_req.rtr_rid);
    if (!router)
        return -EINVAL;

    if (!router->vr_bridge_rtable || req->rtr_req.rtr_vrf_id >= (int)fs->rtb_max_vrfs)
        return -EINVAL;

    return router->vr_bridge_rtable->algo_del(router->vr_bridge_rtable, req);
}

static int
bridge_rtb_family_init(struct rtable_fspec *fs, struct vrouter *router)
{
    int ret;
    struct vr_rtable *table = NULL;
    
    if (router->vr_bridge_rtable)
        return 0;

    if (fs->algo_init[RT_UCAST]) {
        table = vr_zalloc(sizeof(struct vr_rtable));
        if (!table)
            return vr_module_error(-ENOMEM, __FUNCTION__, __LINE__,
                    RT_UCAST);

        ret = fs->algo_init[RT_UCAST](table, fs);
        if (ret)
            return vr_module_error(ret, __FUNCTION__, __LINE__, RT_UCAST);
    }

    router->vr_bridge_rtable = table;
    return 0;
}

static void
bridge_rtb_family_deinit(struct rtable_fspec *fs, struct vrouter *router, 
                                                            bool soft_reset)
{

    if (!router->vr_bridge_rtable) {
        return;
    }

    fs->algo_deinit[RT_UCAST](router->vr_bridge_rtable, fs, soft_reset);

    if (!soft_reset) {
        vr_free(router->vr_bridge_rtable);
        router->vr_bridge_rtable = NULL;
    }
}

/* hopefully we can afford a bit of bloat while loading ? */
static struct rtable_fspec rtable_families[] = {
    {
        .rtb_family                     =   AF_INET,
        .rtb_max_vrfs                   =   VR_MAX_VRFS,
        .rtb_family_init                =   inet_rtb_family_init,
        .rtb_family_deinit              =   inet_rtb_family_deinit,
        .route_add                      =   inet_route_add,
        .route_del                      =   inet_route_del,
        .algo_init[RT_UCAST]            =   mtrie_algo_init,
        .algo_deinit[RT_UCAST]          =   mtrie_algo_deinit,
        .algo_init[RT_MCAST]            =   mcast_algo_init,
        .algo_deinit[RT_MCAST]          =   mcast_algo_deinit,
    },
    {
        .rtb_family                     =   AF_BRIDGE,
        .rtb_max_vrfs                   =   VR_MAX_VRFS,
        .rtb_family_init                =   bridge_rtb_family_init,
        .rtb_family_deinit              =   bridge_rtb_family_deinit,
        .route_add                      =   bridge_entry_add,
        .route_del                      =   bridge_entry_del,
        .algo_init[RT_UCAST]            =   bridge_table_init,
        .algo_deinit[RT_UCAST]          =   bridge_table_deinit,
    },
    {
        .rtb_family                     =   AF_INET6,
        .rtb_max_vrfs                   =   VR_MAX_VRFS,
        .rtb_family_init                =   inet_rtb_family_init,
        .rtb_family_deinit              =   inet_rtb_family_deinit,
        .route_add                      =   inet_route_add,
        .route_del                      =   inet_route_del,
        .algo_init[RT_UCAST]            =   mtrie_algo_init,
        .algo_deinit[RT_UCAST]          =   mtrie_algo_deinit,
        .algo_init[RT_MCAST]            =   mcast_algo_init,
        .algo_deinit[RT_MCAST]          =   mcast_algo_deinit,
    }
};

void
vr_fib_exit(struct vrouter *router, bool soft_reset)
{
    unsigned int i;
    struct rtable_fspec *fs;

    for (i = 0; i < ARRAYSIZE(rtable_families); i++) {
        fs = &rtable_families[i];
        fs->rtb_family_deinit(fs, router, soft_reset);
    }

    return;
}

int 
vr_fib_init(struct vrouter *router)
{
    int i;
    int ret;
    int size;
    struct rtable_fspec *fs;

    size = (int)ARRAYSIZE(rtable_families);
    for (i = 0; i < size; i++) {
        fs = &rtable_families[i];
        ret = fs->rtb_family_init(fs, router);
        if (ret) {
            vr_module_error(ret, __FUNCTION__, __LINE__, i);
            goto exit_init;
        }
    }

    return 0;

exit_init:
    if (!i)
        return ret;

    for (--i, --fs; i >= 0; i--) {
        fs->rtb_family_deinit(fs, router, false);
    }

    return ret;
}

