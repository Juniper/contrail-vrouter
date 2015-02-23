#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

SRC_ROOT ?= ..

ifeq ($(ARCH),i686)
    CFLAGS += -march=$(ARCH)
endif

CFLAGS += -I$(SRC_ROOT)/include -I$(SRC_ROOT)/sandesh/gen-c
CFLAGS += -I$(SRC_ROOT)/../../ -I$(SRC_ROOT)/../../sandesh/library/c -g
CFLAGS += -Wall -Werror

BUILD_DIR = ../../../../build/lib
BIN_FLAGS = -L$(BUILD_DIR) -L$(SRC_ROOT)/../../../build/debug/sandesh/library/c/
BIN_FLAGS += -L .
BIN_FLAGS += -lsandesh-c -lvrutil

LIB_NAME = libvrutil.a
LIBOBJS = nl_util.lo

VIF = vif
NH = nh
RT = rt
MPLS = mpls
FLOW = flow
MIRROR = mirror
VRFSTATS = vrfstats
DROPSTATS = dropstats
VXLAN = vxlan

SANDESH_OBJS = $(SRC_ROOT)/sandesh/gen-c/vr_types.o

%.lo: %.c
	$(CC) -c $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $^

all: $(VIF) $(NH) $(RT) $(MPLS) $(FLOW) $(MIRROR) $(VRFSTATS) $(DROPSTATS) $(VXLAN)

$(SANDESH_OBJS:%.o=%.c):
	$(MAKE) -C $(SRC_ROOT)/sandesh

$(VIF): $(VIF).c $(SANDESH_OBJS) $(LIB_NAME)
	$(CC) $< $(SANDESH_OBJS) $(CFLAGS) $(BIN_FLAGS) -o $@

$(NH): $(NH).c $(SANDESH_OBJS) $(LIB_NAME)
	$(CC) $< $(SANDESH_OBJS)  $(CFLAGS) $(BIN_FLAGS) -o $@

$(RT): $(RT).c $(SANDESH_OBJS) $(LIB_NAME)
	$(CC) $< $(SANDESH_OBJS) $(CFLAGS) $(BIN_FLAGS) -o $@

$(MPLS): $(MPLS).c $(SANDESH_OBJS) $(LIB_NAME)
	$(CC) $< $(SANDESH_OBJS) $(CFLAGS) $(BIN_FLAGS) -o $@

$(FLOW): $(FLOW).c $(SANDESH_OBJS) $(LIB_NAME)
	$(CC) $< $(SANDESH_OBJS) $(CFLAGS) $(BIN_FLAGS) -o $@

$(MIRROR): $(MIRROR).c $(SANDESH_OBJS) $(LIB_NAME)
	$(CC) $< $(SANDESH_OBJS) $(CFLAGS) $(BIN_FLAGS) -o $@

$(VRFSTATS): $(VRFSTATS).c $(SANDESH_OBJS) $(LIB_NAME)
	$(CC) $< $(SANDESH_OBJS) $(CFLAGS) $(BIN_FLAGS) -o $@

$(DROPSTATS): $(DROPSTATS).c $(SANDESH_OBJS) $(LIB_NAME)
	$(CC) $< $(SANDESH_OBJS) $(CFLAGS) $(BIN_FLAGS) -o $@

$(VXLAN): $(VXLAN).c $(SANDESH_OBJS) $(LIB_NAME)
	$(CC) $< $(SANDESH_OBJS) $(CFLAGS) $(BIN_FLAGS) -o $@

$(LIB_NAME): $(LIBOBJS)
	$(AR) rcs $@ $^

clean:
	$(MAKE) -C $(SRC_ROOT)/sandesh clean
	$(RM) *.o *.lo $(LIB_NAME)
	$(RM) $(VIF)  $(MPLS) $(NH) $(RT) $(FLOW) $(MIRROR) $(VRFSTATS) $(DROPSTATS) $(VXLAN)
