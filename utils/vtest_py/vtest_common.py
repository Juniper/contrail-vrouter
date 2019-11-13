#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os
import socket

# Add all utility functions here like vt_ipv4, vt_encap etc.
class VTestCommon(VTestBase):

    def htonll(val):
        return (socket.htonl(val & 0xFFFFFFFF) << 32) + (socket.htonl(val >> 32))

    def ntohll(val):
        return (socket.ntohl(val & 0xFFFFFFFF) << 32) + (socket.ntohl(val >> 32))

