#!/bin/bash
##
## Bind Interfaces on VROUTER1
## Copyright (c) 2014 Semihalf. All rights reserved.
##

. 00.config.sh

#################################################################
## Shutdown Linux Interfaces
sudo ifconfig ${VROUTER1_1_IF} down

#################################################################
## Load Kernel Modules
sudo modprobe uio
sudo insmod ${DPDK_DIR}/build/kmod/rte_kni.ko
sudo insmod ${DPDK_DIR}/build/kmod/igb_uio.ko

#################################################################
## Re-bind NICs to DPDK Drivers
sudo -E ${BIND} -b igb_uio ${VROUTER1_1_PCI}
sudo -E ${BIND} --status
