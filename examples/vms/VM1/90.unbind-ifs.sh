#!/bin/bash
##
## Unbind Interfaces on VM1
## Copyright (c) 2014 Semihalf. All rights reserved.
##

. 00.config.sh

#################################################################
## Re-bind Interface to Linux Driver
sudo -E ${BIND} -b ${VM1_DRV} ${VM1_PCI}
sudo -E ${BIND} --status

#################################################################
## Remove Kernel Modules
sudo rmmod rte_kni.ko
sudo rmmod igb_uio.ko

#################################################################
## Configure Linux Interface
sudo ifconfig ${VM1_IF} ${VM1_DEF_IP} netmask 255.255.255.0 up
sudo ifconfig ${VM1_IF}
