/*
 * vr_llocal.h
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */
#ifndef _VR_LLOCAL_H_
#define _VR_LLOCAL_H_

#ifdef __cplusplus
extern "C" {
#endif

bool vr_valid_link_local_port(struct vrouter *,int,int,int);
void vr_clear_link_local_port(struct vrouter *, int, int, int);
void vr_set_link_local_port(struct vrouter *, int , int , int);
void vr_link_local_ports_reset(struct vrouter *);
void vr_link_local_ports_exit(struct vrouter *);
int vr_link_local_ports_init(struct vrouter *);

#ifdef __cplusplus
}
#endif

#endif /* _VR_LLOCAL_H_ */

