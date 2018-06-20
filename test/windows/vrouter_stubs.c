/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <vrouter.h>

unsigned int vr_num_cpus = 1;
const ULONG VrAllocationTag = 'TSET';
PSWITCH_OBJECT VrSwitchObject = NULL;

void get_random_bytes(void *buf, int nbytes) {
}

struct host_os * vrouter_get_host(void) {
    return NULL;
}

// Needed because we don't compile vr_nbl.c in tests yet.
void win_free_packet(struct vr_packet *pkt) {
}

int pkt0_if_tx(struct vr_interface *vif, struct vr_packet *pkt) {
    return 0;
}
