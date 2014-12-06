#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

#
# This Makefile is used in a couple of contexts. One context is is obviously
# when you compile the vrouter module from the repository. Another context
# is when the sources get distributed as a package (for e.g.: dkms).
#
# In the second context, all sandesh source files needed for compilation will
# be under the sandesh/ directory.
#
# 'SANDESH_SRC_ROOT' points to where the make can find the sandesh files
# needed for compiling the module. If not set by command line, path will be
# relative.
#
# 'SANDESH_HEADER_PATH' will point to a place where we can find most of the
# header files needed for compilation of sandesh sources whereas
#
# 'SANDESH_EXTRA_HEADER_PATH' points to a place where additional header files
# can be found
#
# When the sources are ditributed, the sandesh compiler will not be present
# and hence the generated files (vr_types.c,h) will be packaged rather than
# the vr.sandesh file. Hence, the makefile in the sandesh directory is not
# packaged
#
# Since we want standalone make to work when the source is distributed, default
# values will point to the vrouter source root and when invoked from 'scons',
# the parent 'SConscript' will provide the paths through command line arguments
#
# Also, please note that if you add more source files, you will also need to
# add those files in RPM spec file and the rules file in the dkms package
#

SANDESH_HEADER_PATH ?= $(src)/
SANDESH_EXTRA_HEADER_PATH ?= $(src)/

SANDESH_BINS := $(SANDESH_SRC_ROOT)/sandesh/gen-c/vr_types.o

SANDESH_LIB_BINS := $(SANDESH_SRC_ROOT)sandesh/library/c/sandesh.o
SANDESH_LIB_BINS += $(SANDESH_SRC_ROOT)sandesh/library/c/protocol/thrift_protocol.o
SANDESH_LIB_BINS += $(SANDESH_SRC_ROOT)sandesh/library/c/protocol/thrift_binary_protocol.o
SANDESH_LIB_BINS += $(SANDESH_SRC_ROOT)sandesh/library/c/transport/thrift_transport.o
SANDESH_LIB_BINS += $(SANDESH_SRC_ROOT)sandesh/library/c/transport/thrift_memory_buffer.o
SANDESH_LIB_BINS += $(SANDESH_SRC_ROOT)sandesh/library/c/transport/thrift_fake_transport.o

ifneq ($(KERNELRELEASE), )
	obj-m := vrouter.o

	vrouter-y += $(SANDESH_BINS)
	vrouter-y += $(SANDESH_LIB_BINS)

	vrouter-y += linux/vrouter_mod.o linux/vhost_dev.o
	vrouter-y += linux/vr_host_interface.o linux/vr_genetlink.o
	vrouter-y += linux/vr_mem.o

	vrouter-y += dp-core/vr_message.o dp-core/vr_sandesh.o
	vrouter-y += dp-core/vr_queue.o dp-core/vr_index_table.o
	vrouter-y += dp-core/vrouter.o dp-core/vr_route.o
	vrouter-y += dp-core/vr_nexthop.o dp-core/vr_vif_bridge.o
	vrouter-y += dp-core/vr_datapath.o dp-core/vr_interface.o
	vrouter-y += dp-core/vr_packet.o dp-core/vr_proto_ip.o
	vrouter-y += dp-core/vr_mpls.o dp-core/vr_ip_mtrie.o
	vrouter-y += dp-core/vr_response.o dp-core/vr_flow.o
	vrouter-y += dp-core/vr_mirror.o dp-core/vr_vrf_assign.o
	vrouter-y += dp-core/vr_index_table.o
	vrouter-y += dp-core/vr_stats.o dp-core/vr_btable.o
	vrouter-y += dp-core/vr_bridge.o dp-core/vr_htable.o
	vrouter-y += dp-core/vr_vxlan.o dp-core/vr_fragment.o

	ccflags-y += -I$(src)/include -I$(SANDESH_HEADER_PATH)/sandesh/gen-c
	ccflags-y += -I$(SANDESH_EXTRA_HEADER_PATH)
	ccflags-y += -I$(SANDESH_EXTRA_HEADER_PATH)/sandesh/library/c
	ccflags-y += -g -Wall

	ifeq ($(shell uname -r | grep 2.6.32|grep -c openstack),1)
		ccflags-y += -DISRHOSKERNEL
	endif
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
ifneq ($(wildcard sandesh/Makefile), )
	$(MAKE) --quiet -C sandesh/ clean
endif
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
ifneq ($(SANDESH_SRC_ROOT),)
	$(RM) $(SANDESH_BINS) $(SANDESH_LIB_BINS)
endif

cscope:
	find -L . -name "*.[cChHyYSsmM]" > cscope.files
	cscope -b -qi cscope.files
	ctags -R --extra=+f .

endif
