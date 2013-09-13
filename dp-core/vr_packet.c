/*
 * vr_packet.c -- packet handling helpers
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>

void
pkt_reset(struct vr_packet *pkt)
{
    vr_preset(pkt);

    pkt->vp_tail = pkt->vp_data;
    pkt->vp_len = 0;
    pkt->vp_network_h = pkt->vp_data;

    return;
}

struct vr_packet *
pkt_copy(struct vr_packet *pkt, unsigned short off, unsigned short len)
{
    struct vr_packet *pkt_c;
    unsigned short head_space;

    head_space = sizeof(struct vr_eth) + sizeof(struct agent_hdr);
    pkt_c = vr_palloc(head_space + len);
    if (!pkt_c)
        return pkt_c;

    pkt_c->vp_data += head_space;
    pkt_c->vp_tail += head_space;
    if (vr_pcopy(pkt_data(pkt_c), pkt, off, len) < 0) {
        vr_pfree(pkt_c, VP_DROP_MISC);
        return NULL;
    }
    pkt_pull_tail(pkt_c, len);

    pkt_c->vp_if = pkt->vp_if;
    pkt_c->vp_flags = pkt->vp_flags;
    pkt_c->vp_cpu = pkt->vp_cpu;
    pkt_c->vp_network_h = 0;

    return pkt_c;
}

