#!/bin/bash
##
## MPLSoUDP Scenario for vRouter 1
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
sudo ${VIF} --add vm1 --mac ${VM1_MAC} --type virtual --vrf 0 --id 0
sudo ${VIF} --add ${VROUTER1_2_PCI_DBDF} --mac ${VROUTER1_2_MAC} \
    --type physical --vrf 0 --id 1 --pci
sudo ${VIF} --list

#################################################################
## Create Next Hops
# 1 - rcv, 2 - encap, 3 - tunnel, 4 - resolve, 5 - discard, 6 - Composite, 7 - Vxlan VRF
sudo ${NH} --create 1 --oif 1 --type 1
sudo ${NH} --create 2 --oif 0 --type 2 \
    --smac ${VROUTER1_2_MAC} --dmac ${VM1_MAC}
sudo ${NH} --create 3 --oif 1 --type 3 \
    --smac ${VROUTER1_2_MAC} --dmac ${VROUTER2_1_MAC} \
    --sip ${VROUTER1_VHOST_IP} --dip ${VROUTER2_VHOST_IP} \
    --udp
sudo ${NH} --list


#################################################################
## Create Routes
sudo ${RT} -c -n 1 -p ${VROUTER1_VHOST_IP} -l 32 -f 0 -P -v 0
sudo ${RT} -c -n 3 -p ${VM2_IP} -l 25 -f 0 -P -v 0 -t ${MPLS_LABEL}

sudo ${MPLS} --create ${MPLS_LABEL} --nh 2
sudo ${MPLS} --dump
