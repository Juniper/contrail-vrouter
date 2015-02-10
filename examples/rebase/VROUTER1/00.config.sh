##
## vRouter/DPDK Configuration File
## Copyright (c) 2015 Semihalf. All rights reserved.
##
## Post-rebase testing script:
##
##   172.16.1.100/24 (vhost0) VROUTER1 (eth1) --<1Gbps>-- 172.16.1.1/24 (eth1) LINUX
##

# Compile optimization method
OPTIMIZATION="production"

#################################################################
## DIRECTORIES
# Contrail project base directory
CONTRAIL_DIR="${HOME}/contrail-rebase"
# HugeTLBfs mount point
TLBFS_DIR="/hugepages"
# DPDK base directory
DPDK_DIR="${CONTRAIL_DIR}/third_party/dpdk"
# User space vHost prefix
UVH_PREFIX="/var/tmp/uvh_vif"

#################################################################
## INTERFACES
# NIC PCI addresses
VROUTER1_1_PCI="06:00.1"
VROUTER1_1_PCI_DBDF="0x601"
# NIC Linux interfaces to bind
VROUTER1_1_IF="eth1"
# DPDK ports
VROUTER1_1_PORT="0"
# NIC Linux drivers (for the unbind)
VROUTER1_1_DRV="igb"
# default IP addresses (for the unbind)
VROUTER1_1_DEF_IP="172.16.1.100"
# MAC addresses
VROUTER1_1_MAC="0c:c4:7a:16:33:9f"
LINUX_MAC="00:25:90:c5:68:7d"
VM_MAC="0c:c4:7a:16:33:a0"
# Vhost interfaces
VROUTER1_VHOST="vhost0"
# IPs
VROUTER1_VHOST_IP="172.16.1.100"
LINUX_IP="172.16.1.1"


#################################################################
## OTHER
# MPLS label to use
MPLS_LABEL=22
MPLS_LABEL_L2=23

# Number of HugePages
NB_HUGEPAGES=2048

# vRouter Utils
DROPSTATS="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/dropstats"
MPLS="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/mpls"
NH="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/nh"
RT="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/rt"
VIF="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/utils/vif"
VROUTER="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vrouter/dpdk/contrail-vrouter-dpdk"
AGENT="${CONTRAIL_DIR}/build/${OPTIMIZATION}/vnsw/agent/contrail/contrail-vrouter-agent"

# Bind Tool
BIND="${DPDK_DIR}/tools/dpdk_nic_bind.py"
