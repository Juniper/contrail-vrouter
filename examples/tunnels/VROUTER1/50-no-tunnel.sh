#!/bin/bash
##
## No tunnel (basic forwarding) Configuration for vRouter 1
## Copyright (c) 2014 Semihalf. All rights reserved.
##
## In this example two vRouters act as a transparent proxy.
##
## VM1_IP and VM2_IP must be in the same class C (/24) network.
##
## VM1 -------- VROUTER1 ------ VROUTER2 -------- VM2
## VM1_IP                                      VM2_IP
## VM1_MAC                                    VM2_MAC
##

. 00.config.sh

#################################################################
## Add Interfaces
sudo ${VIF} --add ${VROUTER1_1_PORT} --mac ${VROUTER1_1_MAC} \
    --type physical --pmd --vrf 0 --id 1
sudo ${VIF} --add ${VROUTER1_2_PORT} --mac ${VROUTER1_2_MAC} \
    --type physical --pmd --vrf 0 --id 2
sudo ${VIF} --list

#################################################################
## Create Next Hops
sudo ${NH} --create 1 --oif 1 --type 2 \
    --smac ${VROUTER1_1_MAC} --dmac ${VM1_MAC}
sudo ${NH} --create 2 --oif 2 --type 2 \
    --smac ${VROUTER1_2_MAC} --dmac ${VROUTER2_1_MAC}
sudo ${NH} --list


#################################################################
## Create Routes
sudo ${RT} -c -n 1 -p ${VM1_IP} -l 25 -f 0 -P -v 0
sudo ${RT} -c -n 2 -p ${VM2_IP} -l 25 -f 0 -P -v 0
