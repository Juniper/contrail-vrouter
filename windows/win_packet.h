/*
 * win_packet.h -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_PACKET_H__
#define __WIN_PACKET_H__

struct _NET_BUFFER_LIST;
typedef struct _NET_BUFFER_LIST *PNET_BUFFER_LIST;

typedef struct _NET_BUFFER_LIST   WIN_PACKET;
typedef struct _NET_BUFFER_LIST *PWIN_PACKET;

#endif /* __WIN_PACKET_H__ */
