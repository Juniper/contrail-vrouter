##
## vRouter/DPDK Configuration File
## Copyright (c) 2014 Semihalf. All rights reserved.
##
## MPLS over UDP forwarding scenario:
##
##   VM1 -- VROUTER1 -- <MPLSoUDP> -- VROUTER2 -- VM2
##
## This is the VM1 configuration
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
VM1_PCI="00:03.0"
# NIC Linux interfaces to bind
VM1_IF="eth0"
# DPDK ports
VM1_PORT="0"
# NIC Linux drivers (for the unbind)
VM1_DRV="virtio-pci"
# default IP addresses (for the unbind)
VM1_DEF_IP="172.16.1.1"
# MAC addresses
VROUTER1_1_MAC="90:e2:ba:3f:c7:68"
VM1_MAC="02:cd:0:0:0:1"
# IPs
VM1_IP="172.16.1.1"
VM2_IP="172.16.1.129"
VM2_IP_MAX="172.16.1.254"

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
