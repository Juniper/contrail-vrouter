/*
 * windows_nbl.h -- definitions used in operations on NBLs
 *
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WINDOWS_NBL_H__
#define __WINDOWS_NBL_H__

#include "vr_interface.h"
#include "vr_packet.h"
#include "vr_windows.h"

#define IS_NBL_OWNED(nbl) ((nbl)->NdisPoolHandle == VrNBLPool)
#define IS_NBL_CLONE(nbl) ((nbl)->ParentNetBufferList != NULL)

#define VP_DEFAULT_INITIAL_TTL 64

/* Functions for NBL handling are located in windows/vr_nbl.c */
extern FILTER_SEND_NET_BUFFER_LISTS FilterSendNetBufferLists;
extern FILTER_SEND_NET_BUFFER_LISTS_COMPLETE FilterSendNetBufferListsComplete;

extern PNET_BUFFER_LIST CreateNetBufferList(unsigned int bytesCount);
extern PNET_BUFFER_LIST CloneNetBufferList(PNET_BUFFER_LIST originalNbl);
extern VOID FreeNetBufferList(PNET_BUFFER_LIST nbl);
extern VOID FreeCreatedNetBufferList(PNET_BUFFER_LIST nbl);
extern VOID FreeClonedNetBufferListRecursive(PNET_BUFFER_LIST nbl);
extern VOID FreeClonedNetBufferListPreservingParent(PNET_BUFFER_LIST nbl);
PNET_BUFFER_LIST SplitMultiNetBufferNetBufferList(PNET_BUFFER_LIST origNbl);

extern struct vr_packet *win_get_packet(PNET_BUFFER_LIST nbl, struct vr_interface *vif);
extern void win_packet_map_from_mdl(struct vr_packet *pkt, PMDL mdl, ULONG mdl_offset, ULONG data_length);
extern struct vr_packet *win_allocate_packet(void *buffer, unsigned int size);
extern void win_free_packet(struct vr_packet *pkt);

#endif /* __WINDOWS_NBL_H__ */
