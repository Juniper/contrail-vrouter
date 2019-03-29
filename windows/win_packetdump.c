#include "win_packetdump.h"
#include <Ntstrsafe.h>
#include "win_memory.h"
#include "win_packet_raw.h"
#include "win_packet.h"
#include "win_packet_impl.h"
#include "win_assert.h"
#include "vr_windows.h"

#define TEMP_BUFFER_SIZE 512
#define OUTPUT_BUFFER_SIZE 10240

static NDIS_IO_WORKITEM_FUNCTION WritePacketToFileWork;
static NDIS_MUTEX packetWriterMutex;

static VOID
WritePacketToFileWork(PVOID work_item_context, NDIS_HANDLE work_item_handle)
{
    char* outputBuffer = (char*)(work_item_context);

    UNICODE_STRING     uniName;
    OBJECT_ATTRIBUTES  objAttr;

    RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\packetsdump.txt");
    InitializeObjectAttributes(&objAttr, &uniName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    HANDLE   handle;
    NTSTATUS ntstatus;
    IO_STATUS_BLOCK ioStatusBlock;
    NDIS_WAIT_FOR_MUTEX(&packetWriterMutex);
    ntstatus = ZwCreateFile(&handle,
                            FILE_APPEND_DATA | SYNCHRONIZE,
                            &objAttr, &ioStatusBlock, NULL,
                            FILE_ATTRIBUTE_NORMAL,
                            0,
                            FILE_OPEN_IF,
                            FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL, 0);

    if (NT_SUCCESS(ntstatus)) {
        LARGE_INTEGER byteOffset;
        byteOffset.LowPart = FILE_USE_FILE_POINTER_POSITION;
        byteOffset.HighPart = -1;
        size_t cb;
        ntstatus = RtlStringCbLengthA(outputBuffer, OUTPUT_BUFFER_SIZE, &cb);
        if (NT_SUCCESS(ntstatus)) {
            ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock,
            outputBuffer, cb, &byteOffset, NULL);
        }
        ZwClose(handle);
    }
    NDIS_RELEASE_MUTEX(&packetWriterMutex);

    NdisFreeIoWorkItem(work_item_handle);
    WinRawFree(outputBuffer);
}

static NTSTATUS
AddVrPacketJSONInformation(struct vr_packet *packet, char* outputBuffer, size_t outputBufferSize)
{
    static const char vrPacketJsonFormat[] = ",\"vrpacket\":{"
        "\"vp_data\":%d,"
        "\"vp_tail\":%d,"
        "\"vp_len\":%d,"
        "\"vp_end\":%d,"
        "\"vp_network_h\":%d,"
        "\"vp_flags\":%d,"
        "\"vp_inner_network_h\":%d,"
        "\"vp_cpu\":%d,"
        "\"vp_type\":%d,"
        "\"vp_ttl\":%d,"
        "\"vp_queue\":%d,"
        "\"vp_priority\":%d,"
        "\"vp_if->vif_mtu\":%d"
        "}";

    char tempBuffer[TEMP_BUFFER_SIZE];
    NTSTATUS ntstatus;
    ntstatus = RtlStringCbPrintfA(tempBuffer, TEMP_BUFFER_SIZE, vrPacketJsonFormat,
                                    (unsigned long)packet->vp_data,
                                    (unsigned long)packet->vp_tail,
                                    (unsigned long)packet->vp_len,
                                    (unsigned long)packet->vp_end,
                                    (unsigned long)packet->vp_network_h,
                                    (unsigned long)packet->vp_flags,
                                    (unsigned long)packet->vp_inner_network_h,
                                    (unsigned long)packet->vp_cpu,
                                    (unsigned long)packet->vp_type,
                                    (unsigned long)packet->vp_ttl,
                                    (unsigned long)packet->vp_queue,
                                    (unsigned long)packet->vp_priority,
                                    (unsigned long)packet->vp_if->vif_mtu);
    if (!NT_SUCCESS(ntstatus)) {
        return ntstatus;
    }

    ntstatus = RtlStringCbCatA(outputBuffer, outputBufferSize, tempBuffer);

    return ntstatus;
}

static NTSTATUS
AddPacketMetaDataJSONInformation(struct vr_packet *packet, char* outputBuffer, size_t outputBufferSize)
{
    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(packet);
    PWIN_PACKET_RAW winPacketRaw = WinPacketToRawPacket(winPacket);
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(winPacketRaw);

    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO lso_info;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO settings;

    lso_info.Value = NET_BUFFER_LIST_INFO(nbl, TcpLargeSendNetBufferListInfo);
    settings.Value = NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);

    static const char metaDataJsonFormat[] = ",\"metaData\":{"
        "\"MSS\":%d,"
        "\"IsIPv4\":%d,"
        "\"IsIPv6\":%d,"
        "\"TcpChecksum\":%d,"
        "\"UdpChecksum\":%d,"
        "\"IpHeaderChecksum\":%d,"
        "\"TcpHeaderOffset\":%d"
        "}";

    char tempBuffer[TEMP_BUFFER_SIZE];
    NTSTATUS ntstatus;
    ntstatus = RtlStringCbPrintfA(tempBuffer, TEMP_BUFFER_SIZE, metaDataJsonFormat,
                                    (unsigned long)lso_info.LsoV2Transmit.MSS,
                                    (unsigned long)settings.Transmit.IsIPv4,
                                    (unsigned long)settings.Transmit.IsIPv6,
                                    (unsigned long)settings.Transmit.TcpChecksum,
                                    (unsigned long)settings.Transmit.UdpChecksum,
                                    (unsigned long)settings.Transmit.IpHeaderChecksum,
                                    (unsigned long)settings.Transmit.TcpHeaderOffset);

    if (!NT_SUCCESS(ntstatus)) {
        return ntstatus;
    }

    ntstatus = RtlStringCbCatA(outputBuffer, outputBufferSize, tempBuffer);

    return ntstatus;
}

static inline char
NibbleToHex(uint8_t value)
{
    static const char * const nibbles = "0123456789ABCDEF";

    WinAssert(value < 16);

    return nibbles[value];
}

static void
DumpBufferToHex(uint8_t* buffer, size_t bufferSize, char* outputBuffer, size_t outputBufferSize)
{
    for (int i = 0; i < bufferSize; i++) {
        *outputBuffer++ = NibbleToHex((buffer[i] >> 4) & 0x0F);
        *outputBuffer++ = NibbleToHex(buffer[i] & 0x0F);
        *outputBuffer++ = ' ';
    }

    *outputBuffer = 0;
}

static NTSTATUS
AddBytesJSONInformation(struct vr_packet *packet, char* outputBuffer, size_t outputBufferSize)
{
    ULONG packetBufferSize = pkt_len(packet);
    uint8_t* packetBuffer = (uint8_t*)WinRawAllocate(packetBufferSize);

    // 2 letters and space for each byte in hex
    // plus 0 at the end of the string
    size_t packetBytesAsCharBufferSize = packetBufferSize*3 + 1;
    char* packetBytesAsCharBuffer = (char*)WinRawAllocate(packetBytesAsCharBufferSize);

    char* tempBuffer = (char*)WinRawAllocate(OUTPUT_BUFFER_SIZE);

    if (packetBuffer == NULL || packetBytesAsCharBuffer == NULL || tempBuffer == NULL) {
        if (packetBuffer != NULL) {
            WinRawFree(packetBuffer);
        }
        if (packetBytesAsCharBuffer != NULL) {
            WinRawFree(packetBytesAsCharBuffer);
        }
        if (tempBuffer != NULL) {
            WinRawFree(tempBuffer);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    vr_pcopy(packetBuffer, packet, packet->vp_data, packetBufferSize);

    DumpBufferToHex(packetBuffer, packetBufferSize, packetBytesAsCharBuffer, packetBytesAsCharBufferSize);
    NTSTATUS ntstatus = RtlStringCbPrintfA(tempBuffer, OUTPUT_BUFFER_SIZE, ",\"bytes\":\"%s\"", packetBytesAsCharBuffer);
    if (NT_SUCCESS(ntstatus)) {
        ntstatus = RtlStringCbCatA(outputBuffer, outputBufferSize, tempBuffer);
    }

    WinRawFree(packetBuffer);
    WinRawFree(packetBytesAsCharBuffer);
    WinRawFree(tempBuffer);

    return ntstatus;
}

static void
WriteVrPacketToFile(struct vr_packet *packet, char tag[])
{
    static volatile int lastPacketNumber = 0;
    int packetNumber = InterlockedIncrement(&lastPacketNumber);

    // Needs initialization before first 'goto clean'
    NDIS_HANDLE workItem = NULL;

    char* outputBuffer = (char*)WinRawAllocate(OUTPUT_BUFFER_SIZE);

    if (outputBuffer == NULL) {
        return;
    }

    if (!NT_SUCCESS(RtlStringCbPrintfA(outputBuffer, OUTPUT_BUFFER_SIZE, "{\"number\":%d,\"tag\":\"%s\"", packetNumber, tag))) {
        goto clean;
    }

    if (!NT_SUCCESS(AddVrPacketJSONInformation(packet, outputBuffer, OUTPUT_BUFFER_SIZE))) {
        goto clean;
    }

    if (!NT_SUCCESS(AddPacketMetaDataJSONInformation(packet, outputBuffer, OUTPUT_BUFFER_SIZE))) {
        goto clean;
    }

    if (!NT_SUCCESS(AddBytesJSONInformation(packet, outputBuffer, OUTPUT_BUFFER_SIZE))) {
        goto clean;
    }

    if (!NT_SUCCESS(RtlStringCbCatA(outputBuffer, OUTPUT_BUFFER_SIZE, "},\n"))) {
        goto clean;
    }

    workItem = NdisAllocateIoWorkItem(VrDriverHandle);
    if (workItem) {
        NdisQueueIoWorkItem(workItem, WritePacketToFileWork, (PVOID)(outputBuffer));
    }

clean:
    if (outputBuffer != NULL && workItem == NULL) {
        WinRawFree(outputBuffer);
    }
}

static void
DontWriteVrPacketToFile(struct vr_packet *packet, char tag[]) {}

PWRITEVRPACKETTOFILEFUNCTION PacketToFileWriter = DontWriteVrPacketToFile;

void
EnablePacketDumping()
{
    PacketToFileWriter = WriteVrPacketToFile;
}

void
DisablePacketDumping()
{
    PacketToFileWriter = DontWriteVrPacketToFile;
}

bool
IsPacketDumpingEnabled()
{
    return PacketToFileWriter == WriteVrPacketToFile;
}

void
InitPacketDumping()
{
    NDIS_INIT_MUTEX(&packetWriterMutex);
}
