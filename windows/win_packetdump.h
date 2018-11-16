/*
 * win_packetdump.h
 *
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WIN_PACKETDUMP_H__
#define __WIN_PACKETDUMP_H__

#include <vr_packet.h>

void
EnablePacketDumping();

void
DisablePacketDumping();

bool
IsPacketDumpingEnabled();

void
InitPacketDumping();

typedef void (*PWRITEVRPACKETTOFILEFUNCTION)(struct vr_packet *packet, char tag[]);

extern PWRITEVRPACKETTOFILEFUNCTION PacketToFileWriter;

#endif // __WIN_PACKETDUMP_H__
