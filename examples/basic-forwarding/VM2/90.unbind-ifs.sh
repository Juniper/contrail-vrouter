#!/bin/bash
##
## Unbind Interfaces on VM2
## Copyright (c) 2014 Semihalf. All rights reserved.
##

. 00.config.sh

#################################################################
## Re-bind Interface to Linux Driver
sudo -E ${BIND} -b ${VM2_DRV} ${VM2_PCI}

sudo -E ${BIND} --status

#################################################################
## Remove Kernel Modules
sudo rmmod rte_kni.ko
sudo rmmod igb_uio.ko

#################################################################
## Configure Linux Interface
sudo ifconfig ${VM2_IF} ${VM2_DEF_IP} netmask 255.255.255.0 up

sudo ifconfig ${VM2_IF}
