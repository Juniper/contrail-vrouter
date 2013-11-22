#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

ifneq ($(KERNELRELEASE), )
SANDESH_ROOT := $(M)/../tools/sandesh
MOD_OUTPUT_DIR = ../build/linux-$(KERNELRELEASE)

PREFIX=../build/kbuild
SANDESH_BINS := $(PREFIX)/sandesh/gen-c/vr_types.o

SANDESH_LIB_BINS := $(PREFIX)/sandesh/library/c/sandesh.o 
SANDESH_LIB_BINS += $(PREFIX)/sandesh/library/c/protocol/thrift_protocol.o 
SANDESH_LIB_BINS += $(PREFIX)/sandesh/library/c/protocol/thrift_binary_protocol.o
SANDESH_LIB_BINS += $(PREFIX)/sandesh/library/c/transport/thrift_transport.o
SANDESH_LIB_BINS += $(PREFIX)/sandesh/library/c/transport/thrift_memory_buffer.o
SANDESH_LIB_BINS += $(PREFIX)/sandesh/library/c/transport/thrift_fake_transport.o

	obj-m := vrouter.o
	vrouter-y += $(SANDESH_BINS)
	vrouter-y += $(SANDESH_LIB_BINS)

	vrouter-y += linux/vrouter_mod.o linux/vhost_dev.o
	vrouter-y += linux/vr_host_interface.o linux/vr_genetlink.o
	vrouter-y += linux/vr_mem.o

	vrouter-y += dp-core/vr_message.o dp-core/vr_sandesh.o
	vrouter-y += dp-core/vr_queue.o dp-core/vr_index_table.o
	vrouter-y += dp-core/vrouter.o dp-core/vr_route.o dp-core/vr_nexthop.o
	vrouter-y += dp-core/vr_datapath.o dp-core/vr_interface.o
	vrouter-y += dp-core/vr_packet.o dp-core/vr_proto_ip.o
	vrouter-y += dp-core/vr_mpls.o dp-core/vnsw_ip4_mtrie.o
	vrouter-y += dp-core/vr_response.o dp-core/vr_flow.o 
	vrouter-y += dp-core/vr_mirror.o dp-core/vr_vrf_assign.o
	vrouter-y += dp-core/vr_index_table.o dp-core/vr_mcast.o
	vrouter-y += dp-core/vr_stats.o dp-core/vr_btable.o
	vrouter-y += dp-core/vr_bridge.o dp-core/vr_htable.o
	vrouter-y += dp-core/vr_vxlan.o dp-core/vr_fragment.o

	ccflags-y += -I$(src)/include -I$(BUILD_DIR)/vrouter/sandesh/gen-c -I$(src)/../tools -I$(SANDESH_ROOT)/library/c -g
	ccflags-y += -I$(src)/sandesh/gen-c/ -Wall 
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) BUILD_DIR=$(BUILD_DIR) modules

clean:
	$(RM) $(SANDESH_BINS) $(SANDESH_LIB_BINS)
	$(RM) cscope* tags
	$(MAKE) --quiet -C sandesh/ clean
	$(MAKE) --quiet -C $(KERNELDIR) M=$(PWD) clean

cscope:
	find -L . -name "*.[cChHyYSsmM]" > cscope.files
	cscope -b -qi cscope.files
	ctags -R --extra=+f .

endif
