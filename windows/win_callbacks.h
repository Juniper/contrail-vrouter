/*
 * win_callbacks.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_CALLBACKS_H__
#define __WIN_CALLBACKS_H__

struct vr_packet;

extern void *win_data_at_offset(struct vr_packet *vrPkt, unsigned short offset);
extern struct vr_packet *win_pclone(struct vr_packet *vrPkt);
extern void win_pfree(struct vr_packet *vrPkt, unsigned short reason);

#endif
