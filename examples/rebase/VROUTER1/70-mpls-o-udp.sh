#!/bin/bash
##
## MPLSoUDP Scenario Test (Sending Part)
## Copyright (c) 2015 Semihalf. All rights reserved.
##

. 00.config.sh

#################################################################
## Add Interfaces
sudo ${VIF} --add vm2 --mac ${VM_MAC} --type virtual --vrf 0 --id 0
sudo ${VIF} --add ${VROUTER1_1_PCI_DBDF} --mac ${VROUTER1_1_MAC} \
    --type physical --vrf 0 --id 1 --pci
sudo ${VIF} --list

#################################################################
## Create Next Hops
# 1 - rcv, 2 - encap, 3 - tunnel, 4 - resolve, 5 - discard, 6 - Composite, 7 - Vxlan VRF
sudo ${NH} --create 1 --oif 1 --type 1
sudo ${NH} --create 3 --oif 1 --type 3 \
    --smac ${VROUTER1_1_MAC} --dmac ${LINUX_MAC} \
    --sip ${VROUTER1_VHOST_IP} --dip ${LINUX_IP} \
    --udp
sudo ${NH} --list


#################################################################
## Create Routes
#sudo ${RT} -c -n 1 -p ${VROUTER1_VHOST_IP} -l 32 -f 0 -P -v 0
sudo ${RT} -c -n 3 -e ${LINUX_MAC} -f 1 -v 0 -t ${MPLS_LABEL_L2}
sudo ${RT} -c -n 3 -p ${LINUX_IP} -l 25 -f 0 -e ${LINUX_MAC} -P -v 0 \
    -t ${MPLS_LABEL}
