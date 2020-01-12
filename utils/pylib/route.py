#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os
from object_base import *
from vr_py_sandesh.vr_py.ttypes import *


class Route(ObjectBase, vr_route_req):
    """Base class for creating routes"""

    def __init__(self, family, vrf, prefix=None, prefix_len=None, mac=None,
                 nh_id=None, rtr_label_flags=None, **kwargs):
        super(Route, self).__init__()
        vr_route_req.__init__(self)
        self.h_op = constants.SANDESH_OPER_ADD
        self.rtr_family = family
        self.rtr_vrf_id = vrf
        if mac is not None:
            self.rtr_mac = self.vt_mac(mac)
        if prefix is not None:
            self.rtr_prefix = self.vt_ipv4_bytes(prefix)
        self.rtr_prefix_len = prefix_len
        self.rtr_nh_id = nh_id
        self.rtr_label_flags = rtr_label_flags
        self.sreq_class = vr_route_req.__name__

    # Display basic details of the route
    def __repr__(self):
        return "Route(Prefix:{} mac:{})".format(self.rtr_prefix, self.rtr_mac)

    def __str__(self):
        return "Route(Prefix:{} mac:{})".format(self.rtr_prefix, self.rtr_mac)

    def get(self, key):
        """Parses the key field from the response xml file"""
        self.h_op = constants.SANDESH_OPER_GET
        return super(Route, self).get(key)

    def rtr_nh_id(self):
        return self.rtr_nh_id

    def get_rtr_nh_id(self):
        """Parses the key 'rtr_nh_id' from the response xml file"""
        return int(self.get('rtr_nh_id'))

class BridgeRoute(Route):
    """
    BridgeRoute class to create bridge route

    Mandatory Parameters:
    --------------------
    vrf : int
        Vrf index
    mac_str: str
        MAC address
    nh_id : int
        Nexthop id
    """

    def __init__(self, vrf, mac_str, nh_id, **kwargs):
        super(BridgeRoute, self).__init__(constants.AF_BRIDGE, vrf, None, None,
                                          mac_str, nh_id, **kwargs)


class InetRoute(Route):
    """
    InetRoute class to create inet route

    Mandatory Parameters:
    --------------------
    vrf : int
        Vrf index
    prefix : str
        IP prefix
    nh_id : int
        Nexthop id

    Optional Parameters:
    -------------------
    prefix_len : int
        Prefix length
    """

    def __init__(self, vrf, prefix, nh_id, prefix_len=32, **kwargs):
        super(InetRoute, self).__init__(
            constants.AF_INET,
            vrf,
            prefix,
            prefix_len,
            None,
            nh_id,
            **kwargs)


class Inet6Route(Route):
    """
    Inet6Route class to create inet6 route

    Mandatory Parameters:
    --------------------
    vrf : int
        Vrf index
    prefix : str
        IP prefix
    prefix_len : int
        Nexthop id
    nh_id : int
        Nexthop id
    """

    def __init__(self, vrf, prefix, prefix_len, nh_id, **kwargs):
        super(Inet6Route, self).__init__(
            constants.AF_INET6,
            vrf,
            prefix,
            prefix_len,
            None,
            nh_id,
            **kwargs)
