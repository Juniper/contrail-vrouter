/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <vrouter.h>

unsigned int vr_num_cpus = 1;
const ULONG VrAllocationTag = 'TSET';
PSWITCH_OBJECT VrSwitchObject = NULL;
NDIS_HANDLE VrNBLPool = "definitely not null";

void get_random_bytes(void *buf, int nbytes) {
}

int pkt0_if_tx(struct vr_interface *vif, struct vr_packet *pkt) {
    return 0;
}
