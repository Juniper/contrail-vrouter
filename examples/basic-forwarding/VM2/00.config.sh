##
## vRouter/DPDK Configuration File
## Copyright (c) 2014 Semihalf. All rights reserved.
##
## Basic forwarding scenario:
##
##   VM1 -- VROUTER1 -- VM2
##
## This is the VM2 configuration
##

#################################################################
## DIRECTORIES
# Pktgen-DPDK base directory
PKTGEN_DIR="${HOME}/Pktgen-DPDK"
# HugeTLBfs mount point
TLBFS_DIR="/mnt/huge"

#################################################################
## INTERFACES
# NIC PCI addresses
VM2_PCI="00:06.0"
# NIC Linux interfaces to bind
VM2_IF="eth3"
# DPDK ports
VM2_PORT="0"
# NIC Linux drivers (for the unbind)
VM2_DRV="ixgbe"
# default IP addresses (for the unbind)
VM2_DEF_IP="172.16.2.2"
# MAC addresses
VROUTER1_2_MAC="90:e2:ba:3f:c7:69"
VM2_MAC="90:e2:ba:3f:c7:61"
# IPs
VM1_IP="172.16.1.1"
VM1_IP_MAX="172.16.1.126"
VM2_IP="172.16.1.129"

#################################################################
## OTHER
# Number of HugePages
NB_HUGEPAGES=512

# Pktgen Vars
PKTGEN_SDK="${PKTGEN_DIR}/dpdk"
PKTGEN_TARGET="x86_64-pktgen-linuxapp-gcc"
PKTGEN="${PKTGEN_SDK}/examples/pktgen/app/pktgen"

# Bind Tool
BIND="${PKTGEN_SDK}/tools/dpdk_nic_bind.py"
