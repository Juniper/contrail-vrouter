#!/bin/bash
##
## Bind Interfaces on VM2
## Copyright (c) 2014 Semihalf. All rights reserved.
##

. 00.config.sh

#################################################################
## Shutdown Linux Interface
sudo ifconfig ${VM2_IF} down

#################################################################
## Load Kernel Modules
sudo modprobe uio
sudo insmod ${PKTGEN_SDK}/${PKTGEN_TARGET}/kmod/rte_kni.ko
sudo insmod ${PKTGEN_SDK}/${PKTGEN_TARGET}/kmod/igb_uio.ko

#################################################################
## Re-bind NIC to DPDK Drivers
sudo -E ${BIND} -b igb_uio ${VM2_PCI}
sudo -E ${BIND} --status
