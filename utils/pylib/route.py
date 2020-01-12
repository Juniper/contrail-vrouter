#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os
from vtest_object_base import *
from vr_py_sandesh.vr_py.ttypes import *


class Route(VTestObjectBase, vr_route_req):

    def __init__(self, family, vrf, prefix=None, prefix_len=None, mac=None,
                 nh_id=None, rtr_label_flags=None, **kwargs):
        super(Route, self).__init__()
        vr_route_req.__init__(self)
        self.h_op = vtconst.SANDESH_OPER_ADD
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
        self.h_op = vtconst.SANDESH_OPER_GET
        return super(Route, self).get(key)

    def rtr_nh_id(self):
        return self.rtr_nh_id

    def get_rtr_nh_id(self):
        return int(self.get('rtr_nh_id'))

class BridgeRoute(Route):

    def __init__(self, vrf, mac_str, nh_id, **kwargs):
        super(BridgeRoute, self).__init__(vtconst.AF_BRIDGE, vrf, None, None,
                                          mac_str, nh_id, **kwargs)


class InetRoute(Route):

    def __init__(self, vrf, prefix, nh_id, prefix_len=32, **kwargs):
        super(InetRoute, self).__init__(
            vtconst.AF_INET,
            vrf,
            prefix,
            prefix_len,
            None,
            nh_id,
            **kwargs)


class Inet6Route(Route):

    def __init__(self, vrf, prefix, prefix_len, nh_id, **kwargs):
        super(Inet6Route, self).__init__(
            vtconst.AF_INET6,
            vrf,
            prefix,
            prefix_len,
            None,
            nh_id,
            **kwargs)
