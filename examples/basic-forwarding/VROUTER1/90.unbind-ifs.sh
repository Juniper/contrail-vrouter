#!/bin/bash
##
## Unbind Interfaces on vRouter 1
## Copyright (c) 2014 Semihalf. All rights reserved.
##

. 00.config.sh

#################################################################
## Re-bind Interfaces to Linux Driver
sudo -E ${BIND} -b ${VROUTER1_1_DRV} ${VROUTER1_1_PCI}
sudo -E ${BIND} -b ${VROUTER1_2_DRV} ${VROUTER1_2_PCI}

sudo -E ${BIND} --status

#################################################################
## Remove Kernel Modules
sudo rmmod rte_kni.ko
sudo rmmod igb_uio.ko
# remove tap interface for the agent
sudo ip tuntap del ${VROUTER2_AGENT_TAP} mode tap

#################################################################
## Configure Linux Interfaces
sudo ifconfig ${VROUTER1_1_IF} ${VROUTER1_1_DEF_IP} netmask 255.255.255.0 up
sudo ifconfig ${VROUTER1_2_IF} ${VROUTER1_2_DEF_IP} netmask 255.255.255.0 up

sudo ifconfig ${VROUTER1_1_IF}
sudo ifconfig ${VROUTER1_2_IF}
