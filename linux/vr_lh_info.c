/*
 * vr_lh_info.c - vRouter kernel specific callback functions for vr_info.
 *
 * Copyright (c) 2020 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_message.h"
#include "vr_btable.h"
#include "vrouter.h"

extern const char *ContrailBuildInfo;

/* NOTE: Callback API's need to be registered in vrouter/include/vr_info.h
 * under VR_INFO_REG(X) macro.
 * All callback API's should start with "lh_<fn.name>"
 * Register Format: X(MSG, <fn.name>) \
 *                  eg: X(INFO_VER, info_get_version)
 */

/* Kernel based callback functions */
int
lh_info_get_version(VR_INFO_ARGS)
{
    VR_INFO_BUF_INIT();
    VI_PRINTF("Kernel version: %s\n", ContrailBuildInfo);
    return 0;
}

