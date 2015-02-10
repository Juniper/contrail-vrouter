##
## vRouter/DPDK Configuration File
## Copyright (c) 2014 Semihalf. All rights reserved.
##
## MPLS tunnels scenarios:
##
##   VM1 -- VROUTER1 -- <MPLS tunnel> -- VROUTER2 -- VM2
##
## This is the VROUTER1 configuration
##

# Compile optimization method
OPTIMIZATION="production"

#################################################################
## DIRECTORIES
# Contrail project base directory
CONTRAIL_DIR="${HOME}/contrail"
# HugeTLBfs mount point
TLBFS_DIR="/mnt/huge"
# DPDK base directory
DPDK_DIR="${CONTRAIL_DIR}/third_party/dpdk"

#################################################################
## INTERFACES
# NIC PCI addresses
VROUTER1_1_PCI="04:00.0"
VROUTER1_2_PCI="04:00.1"
# NIC Linux interfaces to bind
VROUTER1_1_IF="eth2"
VROUTER1_2_IF="eth3"
# DPDK ports
VROUTER1_1_PORT="0"
VROUTER1_2_PORT="1"
# NIC Linux drivers (for the unbind)
VROUTER1_1_DRV="ixgbe"
VROUTER1_2_DRV="ixgbe"
# default IP addresses (for the unbind)
VROUTER1_1_DEF_IP="172.16.1.100"
VROUTER1_2_DEF_IP="172.16.2.100"
# MAC addresses
VM1_MAC="90:e2:ba:3f:cb:78"
VROUTER1_1_MAC="90:e2:ba:3f:c7:68"
VROUTER1_2_MAC="90:e2:ba:3f:c7:69"
VROUTER2_1_MAC="90:e2:ba:3f:c5:e8"
# vHost interface
VROUTER1_VHOST="vhost0"
# Fake Agent interface to disable xconnect mode
VROUTER1_AGENT_IF="tap100"
# IPs
VM1_IP="172.16.1.1"
VM2_IP="172.16.1.129"
VROUTER1_VHOST_IP="172.16.1.101"
VROUTER2_VHOST_IP="172.16.1.102"


#################################################################
## OTHER
# MPLS label to use
MPLS_LABEL=22

# Number of HugePages
NB_HUGEPAGES=512

# vRouter Utils
MPLS="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/mpls"
NH="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/nh"
RT="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/rt"
VIF="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/vif"
VROUTER="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/dpdk/contrail-vrouter-dpdk"

# Bind Tool
BIND="${DPDK_DIR}/tools/dpdk_nic_bind.py"
