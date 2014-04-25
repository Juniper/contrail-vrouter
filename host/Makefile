#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#
SRC_ROOT ?= ..

HOST_OS = $(shell uname -s)
DP_CORE = $(SRC_ROOT)/dp-core
CFLAGS += -I$(SRC_ROOT)/include -I$(SRC_ROOT)/sandesh/gen-c/
CFLAGS += -I$(SRC_ROOT)/../../ -I$(SRC_ROOT)/../../sandesh/library/c/
CFLAGS += -g -Wall
LIB_NAME = libvrouter
LIB_MAJOR_VERSION = 1
LIB_MINOR_VERSION = 0.1
SRC_SANDESH = ../../../sandesh/library/c

ifeq ($(HOST_OS), Darwin)
SONAME = install_name
else
SONAME = soname
endif

LIB_FLAGS = -shared -Wl,-$(SONAME),$@.so.$(LIB_MAJOR_VERSION)\
		-o $@.so.$(LIB_MAJOR_VERSION).$(LIB_MINOR_VERSION) -lc\
		-L$(SRC_ROOT)/../../../build/debug/sandesh/library/c/ -lsandesh-c

LIBOBJS = vrouter_host_mod.lo
LIBOBJS += vr_host_mtransport.lo vr_host_message.lo
LIBOBJS += vr_host_interface.lo vr_host_packet.lo ulinux.lo
LIBOBJS += $(DP_CORE)/vr_message.lo
LIBOBJS += $(DP_CORE)/vr_queue.lo
LIBOBJS += $(DP_CORE)/vrouter.lo $(DP_CORE)/vr_route.lo $(DP_CORE)/vr_nexthop.lo
LIBOBJS += $(DP_CORE)/vr_datapath.lo $(DP_CORE)/vr_interface.lo
LIBOBJS += $(DP_CORE)/vr_packet.lo $(DP_CORE)/vr_proto_ip.lo
LIBOBJS += $(DP_CORE)/vr_mpls.lo $(DP_CORE)/vr_ip4_mtrie.lo
LIBOBJS += $(DP_CORE)/vr_flow.lo $(DP_CORE)/vr_mirror.lo
LIBOBJS += $(DP_CORE)/vr_mcast.lo $(DP_CORE)/vr_index_table.lo

%.lo: %.c
	$(CC) -c $(CFLAGS) -fPIC -o $@ $^ $(BIN_FLAGS)

all: vr_types $(LIB_NAME)

vr_types:
	$(MAKE) -C $(SRC_ROOT)/sandesh

$(LIB_NAME): $(LIBOBJS)
	$(RM) $(LIB_NAME).so*
	$(CC) $(LIB_FLAGS) $^
	ln -s $(LIB_NAME).so.$(LIB_MAJOR_VERSION).$(LIB_MINOR_VERSION) $(LIB_NAME).so.$(LIB_MAJOR_VERSION)
	ln -s $(LIB_NAME).so.$(LIB_MAJOR_VERSION).$(LIB_MINOR_VERSION) $(LIB_NAME).so

clean:
	$(RM) ../sandesh/gen-c/vr_types.o $(LIBOBJS)
	$(RM) $(LIB_NAME).so*
