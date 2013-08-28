/*
 * vr_host.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_HOST_H__
#define __VR_HOST_H__

int vr_send(unsigned int, void *, unsigned int);
void *vr_recv(void);
void vr_free_req(void *);
void vr_host_io_unregister(unsigned int);
void vr_host_io_init(void);
int vr_host_io_register(unsigned int, int (*)(void *), void *);
int vr_host_io(void);

#endif /* __VR_HOST_H__ */
