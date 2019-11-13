#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os

class Vif(vr_interface_req, VtestObjectBase):
    # Index to allocate in case of auto index allocation
    _auto_alloc_idx = 0

    # Add setup/teardown methods

    # name is mandatory
    def __init__(self, name=None, *args, **kwargs):
        self.vifr_name = name
        pass

    # Display basic details of the Vif
    def __repr__(self):
        return "Vif"

    def __str__(self):
        return "Vif"

    def send_packet(self, packet):
        # Add code here to send packet
        pass

    def send_and_receive_packet(self, packet, receive_vif):
        # Add code here to send packet
        # and receive it on receive_vif
        pass

    def send_and_compare_received_packet(self, packet_to_send,
                                         receive_vif, packet_to_compare):
        return True

class VirtualVif(Vif):

    def __init__(self, name=None, ipv4_str=None, mac_str=None,
                 mtu=1514, *args, **kwargs):
        self.vifr_type = vtconst.VIF_TYPE_VIRTUAL
        self.vifr_transport = vtconst.VIF_TRANSPORT_PMD
        self.vifr_mtu = mtu
        self.vifr_ip = vt_ipv4(ipv4_str)
        super(self, VirtualVif).__init__(self, name, args, **kwars) 

    def set_nh(self, nh_id):
        self.vifr_nh_id = nh_id

    def set_vrf_idx(self, vrf_idx):
        self.vifr_vrf = vrf_idx

class AgentVif(Vif):

    def __init__(self):
        self.vifr_type = vtconst.VIF_TYPE_AGENT
        self.vifr_transport = vtconst.VIF_TRANSPORT_SOCKET
        self.vifr_vrf = 65535
        self.vifr_mcast_vrf = 65535
        self.vifr_mac = vt_mac("00:00:5e:00:01:00")
        self.vifr_mtu = 1514
        self.vifr_flags = vtconst.VIF_FLAG_L3_ENABLED
        super(self, AgentVif).__init__(self, name='unix', args, **kwargs)

# Add methods for vhost0
class VhostVif(Vif):

    def __init__(self):
        pass

# Add methods for fabric
class FabricVif(Vif):

    def __init__(self):
        pass
