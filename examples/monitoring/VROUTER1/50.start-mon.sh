#!/bin/bash
##
## Start Monitoring Script
##

. 00.config.sh

#################################################################
## Add Interfaces
#sudo ${VIF} --add vm1 --mac ${VM1_MAC} --type virtual --vrf 0 --id 0
sudo ${VIF} --add ${VROUTER1_1_PCI_DBDF} --mac ${VROUTER1_1_MAC} \
    --type physical --vrf 0 --id 1 --pci

#################################################################
## Start interface monitoring two times
vifdump -i 1 -nvv
vifdump -i 1 -nvv

#################################################################
## Check if any artifacts left
sudo ${VIF} --list

ifconfig
