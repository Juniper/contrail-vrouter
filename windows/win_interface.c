/*
 * win_interface.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_interface.h"

#include <vrouter.h>

struct vr_interface *
GetVrInterfaceByGuid(GUID if_guid)
{
    struct vrouter *vrouter = vrouter_get(0);
    ASSERT(vrouter != NULL);

    for (int i = 0; i < vrouter->vr_max_interfaces; i++) {
        struct vr_interface* vif = vrouter->vr_interfaces[i];

        if (vif == NULL)
            continue;

        if (IsEqualGUID(&vif->vif_guid, &if_guid))
            return vif;
    }

    return NULL;
}

struct vr_interface *
GetVrInterfaceByPortAndNic(NDIS_SWITCH_PORT_ID vifPort, NDIS_SWITCH_NIC_INDEX vifNic)
{
    struct vrouter *vrouter = vrouter_get(0);
    ASSERT(vrouter != NULL);

    for (int i = 0; i < vrouter->vr_max_interfaces; i++) {
        struct vr_interface* vif = vrouter->vr_interfaces[i];

        if (vif == NULL)
            continue;

        if (vif->vif_port == vifPort && vif->vif_nic == vifNic)
            return vif;
    }

    return NULL;
}
