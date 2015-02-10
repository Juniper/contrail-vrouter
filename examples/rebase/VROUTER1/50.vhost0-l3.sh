#!/bin/bash
##
## Configure vhost0 routing
##

. 00.config.sh

#################################################################
## Add Interfaces
sudo ${VIF} --add ${VROUTER1_1_PORT} --mac ${VROUTER1_1_MAC} \
    --type physical --pmd --vrf 0 --id 1
sudo ${VIF} --add ${VROUTER1_VHOST} --mac ${VROUTER1_1_MAC} \
    --type vhost --xconnect ${VROUTER1_1_PORT} --pmd --vrf 0 --id 2
# add agent interface to disable xconnect mode
sudo ${VIF} --add ${VROUTER1_1_PORT} --mac ${VROUTER1_1_MAC} \
    --type agent --pmd --vrf 0 --id 3
sudo ${VIF} --list

sudo ifconfig ${VROUTER1_VHOST} ${VROUTER1_VHOST_IP} up

sudo arp -s ${LINUX_IP} ${LINUX_MAC}

#################################################################
## Create Next Hops
sudo ${NH} --create 1 --oif 2 --type 2 \
    --dmac ${VROUTER1_1_MAC} --smac ${LINUX_MAC}
sudo ${NH} --create 2 --oif 1 --type 2 \
    --dmac ${LINUX_MAC} --smac ${VROUTER1_1_MAC}
sudo ${NH} --list


#################################################################
## Create Routes
sudo ${RT} -c -n 2 -p ${LINUX_IP} -l 32 -f 0 -P -v 0
sudo ${RT} -c -n 1 -p ${VROUTER1_VHOST_IP} -l 32 -f 0 -P -v 0
