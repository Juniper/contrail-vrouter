#!/bin/bash
##
## Compile vRouter/DPDK Script
## Copyright (c) 2014 Semihalf. All rights reserved.
##

. 00.config.sh

(cd ${CONTRAIL_DIR} && scons vrouter --optimization=${OPTIMIZATION})
