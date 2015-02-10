#!/bin/bash
##
## MPLSoUDP Scenario for vRouter 2
## Copyright (c) 2014 Semihalf. All rights reserved.
##
## In this example two vRouters act as a tunnel source/destination.
##
## VM1_IP and VM2_IP must be in the same class C (/24) network.
##
## VM1 -------- VROUTER1 --- <MPLSoUDP> --- VROUTER2 -------- VM2
## VM1_IP                                                  VM2_IP
## VM1_MAC                                                VM2_MAC
##

. 00.config.sh

#################################################################
## Add Interfaces
sudo ${VIF} --add ${VROUTER2_1_PORT} --mac ${VROUTER2_1_MAC} \
    --type physical --pmd --vrf 0 --id 2
sudo ${VIF} --add ${VROUTER2_2_PORT} --mac ${VROUTER2_2_MAC} \
    --type physical --pmd --vrf 0 --id 0
# add vhost after the vrouter2_1 port since we use it for xconnect
sudo ${VIF} --add ${VROUTER2_VHOST} --mac ${VROUTER2_1_MAC} \
    --type vhost --xconnect ${VROUTER2_1_PORT} --pmd --vrf 0 --id 1
# add agent interface to disable xconnect mode
sudo ${VIF} --add ${VROUTER2_1_PORT} --mac ${VROUTER2_1_MAC} \
    --type agent --pmd --vrf 0 --id 3

sudo ${VIF} --list

sudo ifconfig ${VROUTER2_VHOST} ${VROUTER2_VHOST_IP} up

#################################################################
## Create Next Hops
sudo ${NH} --create 1 --oif 1 --type 1
sudo ${NH} --create 2 --oif 0 --type 2 \
    --smac ${VROUTER2_2_MAC} --dmac ${VM2_MAC}
sudo ${NH} --create 3 --oif 2 --type 3 \
    --smac ${VROUTER2_1_MAC} --dmac ${VROUTER1_2_MAC} \
    --sip ${VROUTER2_VHOST_IP} --dip ${VROUTER1_VHOST_IP} \
    --udp
sudo ${NH} --list


#################################################################
## Create Routes
sudo ${RT} -c -n 1 -p ${VROUTER2_VHOST_IP} -l 32 -f 0 -P -v 0
sudo ${RT} -c -n 3 -p ${VM1_IP} -l 25 -f 0 -P -v 0 -t ${MPLS_LABEL}

sudo ${MPLS} --create ${MPLS_LABEL} --nh 2
sudo ${MPLS} --dump
