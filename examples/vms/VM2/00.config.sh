##
## vRouter/DPDK Configuration File
## Copyright (c) 2014 Semihalf. All rights reserved.
##
## MPLS over UDP forwarding scenario:
##
##   VM1 -- VROUTER1 -- <MPLSoUDP> -- VROUTER2 -- VM2
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
VM2_PCI="00:03.0"
# NIC Linux interfaces to bind
VM2_IF="eth0"
# DPDK ports
VM2_PORT="0"
# NIC Linux drivers (for the unbind)
VM2_DRV="virtio-pci"
# default IP addresses (for the unbind)
VM2_DEF_IP="172.16.1.129"
# MAC addresses
VROUTER2_1_MAC="90:e2:ba:3f:c7:68"
VM2_MAC="90:1:2:3:4:5"
# IPs
VM1_IP="172.16.1.1"
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
