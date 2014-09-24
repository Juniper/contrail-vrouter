/*
 *  vrouter_host_mod.c -- 'vrouter' library init
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_os.h"
#include "vr_packet.h"
#include "vr_proto.h"
#include "vrouter.h"
#include <sys/time.h>
#include "vr_message.h"
#include "vr_sandesh.h"
#include "host/vr_host_packet.h"
#include "ulinux.h"

#define PAGE_SIZE    4096
unsigned int vr_num_cpus = 1;

static bool vr_host_inited = false;
static unsigned int vr_message_proto;

extern int vr_flow_entries;
extern int vr_oflow_entries;

extern void vr_diet_message_proto_exit(void);
extern int vr_diet_message_proto_init(void);

static int
vr_lib_create_timer(struct vr_timer *vtimer)
{
    struct dummy_timer_list *timer;

    timer = vr_zalloc(sizeof(*timer));
    if (!timer)
        return -1;
    init_timer(timer);

    vtimer->vt_os_arg = (void *)timer;
    timer->data = (unsigned long)vtimer;
    timer->function = ulinux_timer;
    timer->expires = get_time() + vtimer->vt_msecs;
    add_timer(timer);

    return 0;
}

static void
vr_lib_delete_timer(struct vr_timer *vtimer)
{
	vr_free(vtimer->vt_os_arg);
}

static void *
vr_lib_page_alloc(unsigned int size)
{
	return malloc(PAGE_SIZE);
}

static void
vr_lib_page_free(void *address, unsigned int size)
{
	if (address)
		free(address);
}

static void *
vr_lib_malloc(unsigned int size)
{
    return malloc(size);
}

static void *
vr_lib_zalloc(unsigned int size)
{
    return calloc(size, 1);
}

static void
vr_lib_free(void *mem)
{
    if (mem)
        free(mem);
    return;
}

static struct vr_packet *
vr_lib_get_packet(struct vr_hpacket *hpkt, struct vr_interface *vif)
{
    struct vr_packet *pkt;

    pkt = &hpkt->hp_packet;
    pkt->vp_head = hpkt->hp_head;
    pkt->vp_data = hpkt->hp_data;
    pkt->vp_tail = hpkt->hp_tail;
    pkt->vp_end = hpkt->hp_end;
    pkt->vp_len = hpkt_head_len(hpkt);
    pkt->vp_if = vif;

    return pkt;
}

static struct vr_packet *
vr_lib_palloc(unsigned int size)
{
    struct vr_hpacket *hpkt;
    
    hpkt = vr_hpacket_alloc(size);
    if (!hpkt)
        return NULL;

    return vr_lib_get_packet(hpkt, NULL);
}

static struct vr_packet *
vr_lib_palloc_head(struct vr_packet *pkt, unsigned int size)
{
    struct vr_hpacket *hpkt_head, *hpkt;

    hpkt_head = vr_hpacket_alloc(size);
    if (!hpkt_head)
        return NULL;

    hpkt = VR_PACKET_TO_HPACKET(pkt);
    hpkt_head->hp_len = hpkt->hp_len;
    hpkt_head->hp_next = hpkt;

    return &hpkt_head->hp_packet;
}

static struct vr_packet *
vr_lib_pclone(struct vr_packet *pkt)
{
    struct vr_hpacket *hpkt, *hpkt_c;

    hpkt = VR_PACKET_TO_HPACKET(pkt);
    hpkt_c = vr_hpacket_clone(hpkt);
    if (!hpkt_c)
        return NULL;

    return &hpkt_c->hp_packet;
}

static void
vr_lib_preset(struct vr_packet *pkt)
{
    struct vr_hpacket *hpkt;

    hpkt = VR_PACKET_TO_HPACKET(pkt);

    pkt->vp_data = hpkt->hp_data;
    pkt->vp_tail = hpkt->hp_tail;
    pkt->vp_len = pkt->vp_tail - pkt->vp_data + 1;

    return;
}

static void
vr_lib_pfree(struct vr_packet *pkt, unsigned short reason)
{
    struct vr_hpacket *hpkt;

    hpkt = VR_PACKET_TO_HPACKET(pkt);
    vr_hpacket_free(hpkt);
    return;
}

static int
vr_lib_pcopy(unsigned char *dst, struct vr_packet *p_src,
        unsigned int offset, unsigned int len)
{
    struct vr_hpacket *src_hpkt = VR_PACKET_TO_HPACKET(p_src);

    return vr_hpacket_copy(dst, src_hpkt, offset, len);
}


static unsigned short
vr_lib_pfrag_len(struct vr_packet *pkt)
{
    struct vr_hpacket *hpkt;

    hpkt = VR_PACKET_TO_HPACKET(pkt);
    if (!hpkt->hp_next)
        return 0;

    return hpkt->hp_next->hp_len;
}

static void
vr_lib_get_time(unsigned int *sec, unsigned int *nsec)
{
    struct timeval tv;

    *sec = *nsec = 0;
    if (gettimeofday(&tv, NULL) < 0)
        return;

    *sec = tv.tv_sec;
    *nsec = tv.tv_usec * 1000;

    return;
}

static unsigned int
vr_lib_get_cpu(void)
{
    return 0;
}

static void
vr_lib_schedule_work(unsigned int cpu, void (*fn)(void *), void *arg)
{
    return;
}

static void
vr_lib_delay_op(void)
{
    return;
}

struct host_os vr_lib_host = {
    .hos_malloc             =       vr_lib_malloc,
    .hos_zalloc             =       vr_lib_zalloc,
    .hos_free               =       vr_lib_free,

    .hos_palloc             =       vr_lib_palloc,
    .hos_palloc_head        =       vr_lib_palloc_head,
    .hos_pfree              =       vr_lib_pfree,
    .hos_preset             =       vr_lib_preset,
    .hos_pclone             =       vr_lib_pclone,
    .hos_pcopy              =       vr_lib_pcopy,
    .hos_pfrag_len          =       vr_lib_pfrag_len,

    .hos_get_cpu            =       vr_lib_get_cpu,
    .hos_schedule_work      =       vr_lib_schedule_work,
    .hos_delay_op           =       vr_lib_delay_op,
    .hos_get_time           =       vr_lib_get_time,
	.hos_page_alloc			=		vr_lib_page_alloc,
	.hos_page_free			=		vr_lib_page_free,
	.hos_create_timer		=		vr_lib_create_timer,
	.hos_delete_timer		=		vr_lib_delete_timer,
};

struct host_os *
vrouter_get_host(void)
{
    return &vr_lib_host;
}

static void
vr_message_exit(void)
{
    switch (vr_message_proto) {
    case VR_MPROTO_DIET:
        vr_diet_message_proto_exit();
        break;

    case VR_MPROTO_SANDESH:
        vr_sandesh_exit();
        break;

    default:
        break;
    }

    vr_message_proto = 0;

    return;
}

static int
vr_message_init(unsigned int message_proto)
{
    int ret = 0;

    switch (message_proto) {
    case VR_MPROTO_DIET:
        ret = vr_diet_message_proto_init();
        break;

    case VR_MPROTO_SANDESH:
        ret = vr_sandesh_init();
        break;

    default:
        ret = -EINVAL;
    }

    if (!ret)
        vr_message_proto = message_proto;

    return ret;
}

void
vrouter_host_exit(void)
{
    vr_message_exit();
    vrouter_exit(false);

    return;
}

int
vrouter_host_init(unsigned int message_proto)
{
    int ret;

    if (vr_host_inited)
        return 0;

    ret = vrouter_init();
    if (ret)
        return ret;

    ret = vr_message_init(message_proto);
    if (ret)
        goto init_fail;

    vr_host_inited = true;

    return 0;

init_fail:
    vrouter_host_exit();
    return ret;
}
