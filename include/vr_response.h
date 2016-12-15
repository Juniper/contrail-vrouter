/*
 * vr_response.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_RESPONSE_H__
#define __VR_RESPONSE_H__

#include <vr_types.h>

extern int vr_send_response(int);
extern int vr_send_broadcast(unsigned int, void *, unsigned int, int);
extern int vr_generate_response(vr_response *, int, unsigned char *, int);

#endif /* __VR_RESPONSE_H__ */
