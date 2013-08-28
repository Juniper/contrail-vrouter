#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

PWD := $(shell pwd)
TREE_ROOT := $(PWD)/../..

SANDESH := $(TREE_ROOT)/build/bin/sandesh
SANDESH_FLAGS := --gen c -o .

SANDESH_SRC := vr.sandesh

default:
	$(SANDESH) $(SANDESH_FLAGS) $(SANDESH_SRC)

clean:
	$(RM) -rf gen-c
