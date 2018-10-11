/*
 * win_packet_splitting.h -- IP fragmentation and TCP segmentation functions
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_PACKET_SPLITTING_H__
#define __WIN_PACKET_SPLITTING_H__

#include "vr_packet.h"

PWIN_MULTI_PACKET split_packet_if_needed(struct vr_packet *pkt);

#endif //__WIN_PACKET_SPLITTING_H__
