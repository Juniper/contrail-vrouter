/*
 * vr_packetdump.h
 *
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_PACKETDUMP_H__
#define __VR_PACKETDUMP_H__

#include <vr_packet.h>

#define TEMP_BUFFER_SIZE 512
#define OUTPUT_BUFFER_SIZE 10240

void
WriteVrPacketToFile(struct vr_packet *packet, char tag[]);

void
DontWriteVrPacketToFile(struct vr_packet *packet, char tag[]);

typedef void (*PWRITEVRPACKETTOFILEFUNCTION)(struct vr_packet *packet, char tag[]);

#endif // __VR_PACKETDUMP_H__
