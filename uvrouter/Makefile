#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

SRC_ROOT ?= ..

CFLAGS += -I$(SRC_ROOT)/include -I$(SRC_ROOT)/sandesh/gen-c/
CFLAGS += -I$(SRC_ROOT)/../../ -I$(SRC_ROOT)/../../sandesh/library/c/
CFLAGS += -I$(SRC_ROOT)/include 
CFLAGS += -g -Wall

BIN_FLAGS = -L$(SRC_ROOT)/host -lvrouter
BIN_FLAGS += -L$(SRC_ROOT)/../../../build/debug/sandesh/library/c/
BIN_FLAGS += -lsandesh-c

UVROUTER = uvrouter
UVROUTER_OBJS = uvrouter.o

%.o: %.c
	$(CC) -c -Wall -Werror $(CFLAGS) -o $@ $^


all:vrouter uvrouter

vrouter:
	$(MAKE) -C $(SRC_ROOT)/host

uvrouter: $(UVROUTER_OBJS)
	$(CC) $^ $(BIN_FLAGS) -o $(UVROUTER)

clean:
	$(MAKE) -C $(SRC_ROOT)/host clean
	$(RM) $(UVROUTER_OBJS)
