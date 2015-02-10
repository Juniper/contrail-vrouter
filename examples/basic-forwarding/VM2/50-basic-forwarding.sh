#!/bin/bash
##
## Basic VM-to-VM IP Forwarding Scenario for VM2
## Copyright (c) 2014 Semihalf. All rights reserved.
##
## In this example vRouter acts as a transparent proxy between
## two VMs.
##
## VM may be a virtual machine with tap or another host.
##
## VM1_IP and VM2_IP must be in the same class C (/24) network.
##
## VM1 -------- vRouter/DPDK -------- VM2
## VM1_IP                          VM2_IP
## VM1_MAC                        VM2_MAC
##

. 00.config.sh

#################################################################
## Add Interfaces
sudo ifconfig ${VM2_IF} ${VM2_IP} netmask 255.255.255.0 up

sudo ifconfig ${VM2_IF}
