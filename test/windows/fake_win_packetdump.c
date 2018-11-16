#include <vr_packet.h>

void
DontWriteVrPacketToFile(struct vr_packet *packet, char tag[]) {}

typedef void (*PWRITEVRPACKETTOFILEFUNCTION)(struct vr_packet *packet, char tag[]);
extern PWRITEVRPACKETTOFILEFUNCTION PacketToFileWriter = DontWriteVrPacketToFile;
