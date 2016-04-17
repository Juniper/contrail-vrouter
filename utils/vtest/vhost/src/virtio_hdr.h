
#ifndef VIRT_HDR_H
#define VIRT_HDR_H


struct virtio_net_hdr {

#define VIRTIO_NET_HDR_F_NEEDS_CSUM    1
#define VIRTIO_NED_HDR_F_DATA_VALID    2
    uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE        0
#define VIRTIO_NET_HDR_GSO_TCPV4       1
#define VIRTIO_NET_HDR_GSO_UDP         3
#define VIRTIO_NET_HDR_GSO_TCPV6       4
#define VIRTIO_NET_HDR_GSO_ECN      0x80
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
};
#endif

