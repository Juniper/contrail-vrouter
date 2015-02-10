##
## vRouter/DPDK Configuration File
## Copyright (c) 2014 Semihalf. All rights reserved.
##
## TODO: unfinished
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
TLBFS_DIR="/hugepages"
# DPDK base directory
DPDK_DIR="${CONTRAIL_DIR}/third_party/dpdk"


#################################################################
## OTHER
# Number of HugePages
NB_HUGEPAGES=2048

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
