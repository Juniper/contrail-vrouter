/*
 * util.h
 * Copyright (c) 2016 Juniper Networks, Inc. All rights reserved.
 */
#ifndef UTIL_H
#define UTIL_H

#include <sys/time.h>
#include <stdlib.h>
#include <stdint.h>
#include <linux/un.h>

#define VHOST_USER_HDR_SIZE (sizeof(struct virtio_net_hdr))
#define VHOST_MEMORY_MAX_NREGIONS    8

#define VHOST_CLIENT_PAGE_SIZE \
        ALIGN(sizeof(struct uvhost_virtq) + VIRTQ_DESC_BUFF_SIZE * VIRTQ_DESC_MAX_SIZE, 1024 * 1024)

#define ALIGN(v,b)   (((long int)v + (long int)b - 1)&(-(long int)b))


#endif

