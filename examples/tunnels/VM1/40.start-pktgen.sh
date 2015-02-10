#!/bin/bash
##
## Start Pktgen-DPDK on VM1
## Copyright (c) 2014 Semihalf. All rights reserved.
##

. 00.config.sh


LUA="/tmp/pktgen.$$.lua"

# Clear huge tables
sudo rm -f "${TLBFS_DIR}/pgmap*"

# Generate Lua script
cat template.lua \
    | sed -e "s/\${SRC_IP}/${VM1_IP}/" \
    | sed -e "s/\${SRC_MAC}/${VM1_MAC}/" \
    | sed -e "s/\${DST_IP}/${VM2_IP}/" \
    | sed -e "s/\${DST_IP_MAX}/${VM2_IP_MAX}/" \
    | sed -e "s/\${DST_MAC}/${VROUTER1_1_MAC}/" \
    > ${LUA}

# Start Pktgen-DPDK
(cd ${PKTGEN_SDK}/examples/pktgen; \
    sudo ${PKTGEN} -c 7 -n 4 --file-prefix pg \
    -- -T -p 7 -P -m "[1:2].0" -f ${LUA})

# Remove temporary Lua script
rm -f ${LUA}
