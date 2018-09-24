/*
 * win_interface.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_INTERFACE_H__
#define __WIN_INTERFACE_H__


#include <vr_interface.h>

struct vr_interface *GetVrInterfaceByGuid(GUID if_guid);
struct vr_interface *GetVrInterfaceByPortAndNic(NDIS_SWITCH_PORT_ID vifPort, NDIS_SWITCH_NIC_INDEX vifNic);


#endif //__WIN_INTERFACE_H__
