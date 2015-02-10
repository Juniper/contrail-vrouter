#!/bin/bash
##
## MPLSoGRE Configuration for vRouter 1
## Copyright (c) 2014 Semihalf. All rights reserved.
##
## In this example two vRouters act as a tunnel source/destination.
##
## VM1_IP and VM2_IP must be in the same class C (/24) network.
##
## VM1 -------- VROUTER1 --- <MPLSoGRE> --- VROUTER2 -------- VM2
## VM1_IP                                                  VM2_IP
## VM1_MAC                                                VM2_MAC
##

. 00.config.sh

#################################################################
## Add Interfaces
sudo ${VIF} --add ${VROUTER1_1_PORT} --mac ${VROUTER1_1_MAC} \
    --type physical --pmd --vrf 0 --id 0
sudo ${VIF} --add ${VROUTER1_2_PORT} --mac ${VROUTER1_2_MAC} \
    --type physical --pmd --vrf 0 --id 2
# add vhost after the vrouter1_2 port since we use it for xconnect
sudo ${VIF} --add ${VROUTER1_VHOST} --mac ${VROUTER1_2_MAC} \
    --type vhost --xconnect ${VROUTER1_2_PORT} --pmd --vrf 0 --id 1
# add an agent interface to disable xconnect mode
sudo ${VIF} --add ${VROUTER1_2_PORT} --mac ${VROUTER1_2_MAC} \
    --type agent --pmd --vrf 0 --id 3

sudo ${VIF} --list

sudo ifconfig ${VROUTER1_VHOST} ${VROUTER1_VHOST_IP} up

#################################################################
## Create Next Hops
sudo ${NH} --create 1 --oif 1 --type 1
sudo ${NH} --create 2 --oif 0 --type 2 \
    --smac ${VROUTER1_1_MAC} --dmac ${VM1_MAC}
sudo ${NH} --create 3 --oif 2 --type 3 \
    --smac ${VROUTER1_2_MAC} --dmac ${VROUTER2_1_MAC} \
    --sip ${VROUTER1_VHOST_IP} --dip ${VROUTER2_VHOST_IP}
sudo ${NH} --list


#################################################################
## Create Routes
sudo ${RT} -c -n 1 -p ${VROUTER1_VHOST_IP} -l 32 -f 0 -P -v 0
sudo ${RT} -c -n 3 -p ${VM2_IP} -l 25 -f 0 -P -v 0 -t ${MPLS_LABEL}

sudo ${MPLS} --create ${MPLS_LABEL} --nh 2
sudo ${MPLS} --dump
