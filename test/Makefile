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

SOFTRESET=soft_reset
VR_TESTs=vr_tests

SANDESH_OBJS = $(SRC_ROOT)/sandesh/gen-c/vr_types.o

%.lo: %.c
	$(CC) -c $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $^

all:  $(SOFTRESET)  

$(SANDESH_OBJS:%.o=%.c):
	$(MAKE) -C $(SRC_ROOT)/sandesh



$(SOFTRESET): $(SOFTRESET).c $(SANDESH_OBJS) $(LIB_NAME)
        $(CC) $< $(SANDESH_OBJS) $(CFLAGS) $(BIN_FLAGS) -o $@

$(LIB_NAME): $(LIBOBJS)
	$(AR) rcs $@ $^

clean:
	$(MAKE) -C $(SRC_ROOT)/sandesh clean
	$(RM) *.o *.lo $(LIB_NAME)
	$(RM) $(SOFTRESET)
