# Variables
SANDESH_ROOT := ${.CURDIR}/../../tools/sandesh
BUILD_DIR := ../../build/debug

# Additional sources paths
.PATH: ${.CURDIR}/../dp-core
.PATH: ${.CURDIR}/../../build/debug/vrouter/sandesh/gen-c
.PATH: ${.CURDIR}/../../build/kbuild/sandesh/library/c
.PATH: ${.CURDIR}/../../build/kbuild/sandesh/library/c/protocol
.PATH: ${.CURDIR}/../../build/kbuild/sandesh/library/c/transport

# Name of module
KMOD = vrouter

# BSD module sources
SRCS =	vrouter_mod.c \
	vhost_dev.c \
	vr_host_interface.c \
	vr_mem.c \
	vr_socket.c \
	vr_bsd_transport.c

# Sandesh bin sources
SRCS += vr_types.c

# Sandesh lib sources
SRCS += sandesh.c \
	thrift_protocol.c \
	thrift_binary_protocol.c \
	thrift_transport.c \
	thrift_memory_buffer.c \
	thrift_fake_transport.c

SRCS += vr_message.c \
       vr_sandesh.c \
       vr_queue.c \
       vr_index_table.c \
       vr_ip_mtrie.c \
       vrouter.c \
       vr_route.c \
       vr_nexthop.c \
       vr_datapath.c \
       vr_interface.c \
       vr_packet.c \
       vr_proto_ip.c \
       vr_mpls.c \
       vr_response.c \
       vr_flow.c \
       vr_mirror.c \
       vr_vrf_assign.c \
       vr_stats.c \
       vr_btable.c \
       vr_bridge.c \
       vr_vif_bridge.c \
       vr_htable.c \
       vr_vxlan.c \
       vr_fragment.c

CFLAGS += -I${.CURDIR}/../include
CFLAGS += -I$(BUILD_DIR)/vrouter/sandesh/gen-c
CFLAGS += -I$(.CURDIR)/../../tools
CFLAGS += -I$(SANDESH_ROOT)/library/c
CFLAGS += -g
CFLAGS += -D__KERNEL__

clean:
	rm -f export_syms
	rm -f *.o *.kld *.ko
	rm -f @ machine x86

.include <bsd.kmod.mk>

CFLAGS += -Wno-error=missing-prototypes
