#!/bin/bash
##
## Start vRouter
## Copyright (c) 2014 Semihalf. All rights reserved.
##

. 00.config.sh

export RTE_SDK="${DPDK_DIR}"
sudo service supervisor-vrouter stop
sudo -E ${VROUTER} --no-daemon
