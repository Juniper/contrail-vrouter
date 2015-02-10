##
## vRouter/DPDK Configuration File
## Copyright (c) 2014 Semihalf. All rights reserved.
##
## MPLS tunnels scenarios:
##
##   VM1 -- VROUTER1 -- <MPLS tunnel> -- VROUTER2 -- VM2
##
## This is the VROUTER2 configuration
##

# Compile optimization method
OPTIMIZATION="production"

#################################################################
## DIRECTORIES
# Pktgen-DPDK base directory
PKTGEN_DIR="${HOME}/Pktgen-DPDK"
# Contrail project base directory
CONTRAIL_DIR="${HOME}/contrail"
# HugeTLBfs mount point
TLBFS_DIR="/mnt/huge"
# DPDK base directory
DPDK_DIR="${CONTRAIL_DIR}/third_party/dpdk"
# QEMU 2.1.0 directory
QEMU_DIR="${HOME}/qemu/qemu-2.1.0/build/native"
# User space vHost prefix
UVH_PREFIX="/var/tmp/uvh_vif"

#################################################################
## INTERFACES
# NIC PCI addresses
VROUTER2_1_PCI="04:00.0"
VROUTER2_1_PCI_DBDF="0x400"
VROUTER2_2_PCI="04:00.1"
VROUTER2_2_PCI_DBDF="0x401"
# NIC Linux interfaces to bind
VROUTER2_1_IF="eth2"
VROUTER2_2_IF="eth3"
# DPDK ports
VROUTER2_1_PORT="0"
VROUTER2_2_PORT="1"
# NIC Linux drivers (for the unbind)
VROUTER2_1_DRV="ixgbe"
VROUTER2_2_DRV="ixgbe"
# default IP addresses (for the unbind)
VROUTER2_1_DEF_IP="172.16.1.100"
VROUTER2_2_DEF_IP="172.16.2.100"
# MAC addresses
VM1_MAC="90:e2:ba:3f:c7:60"
VROUTER1_2_MAC="90:e2:ba:3f:c7:69"
VROUTER2_1_MAC="90:e2:ba:3f:c5:e8"
VROUTER2_2_MAC="90:e2:ba:3f:c5:e9"
VM2_MAC="90:e2:ba:3f:c7:60"
# vHost interface
VROUTER2_VHOST="vhost0"
# Fake Agent interface to disable xconnect mode
VROUTER2_AGENT_IF="tap100"
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
NB_HUGEPAGES=1024

# vRouter Utils
MPLS="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/mpls"
NH="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/nh"
RT="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/rt"
VIF="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/vif"
VROUTER="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/dpdk/contrail-vrouter-dpdk"

# Pktgen Vars
PKTGEN_SDK="${PKTGEN_DIR}/dpdk"
PKTGEN_TARGET="x86_64-pktgen-linuxapp-gcc"
PKTGEN="${PKTGEN_SDK}/examples/pktgen/app/pktgen"

# Bind Tool
BIND="${DPDK_DIR}/tools/dpdk_nic_bind.py"
