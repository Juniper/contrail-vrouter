#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os
from vtest_object_base import *
from vtest_common import *
from vr_py_sandesh.vr_py.ttypes import *


class Route(vr_route_req, VTestObjectBase, VTestCommon):

    def __init__(self, family, vrf, prefix=None, prefix_len=None, mac=None,
                 nh_id=None, **kwargs):
        super(Route, self).__init__()
        VTestObjectBase.__init__(self)
        self.h_op = vtconst.SANDESH_OPER_ADD
        self.rtr_family = family
        self.rtr_vrf_id = vrf
        if mac is not None:
            self.rtr_mac = self.vt_mac(mac)
        if prefix is not None:
            self.rtr_prefix = self.vt_ipv4_bytes(prefix)
        self.rtr_prefix_len = prefix_len
        self.rtr_nh_id = nh_id
        self.sreq_class = vr_route_req.__name__

    def get(self, key):
        self.h_op = vtconst.SANDESH_OPER_GET
        return super(Route, self).get(key)

    def get_rtr_nh_id(self):
        return int(self.get('rtr_nh_id'))

    def set_label_flags(self, flags):
        self.rtr_label_flags = vtconst.VR_RT_ARP_TRAP_FLAG


class BridgeRoute(Route):

    def __init__(self, vrf, mac, nh_id, **kwargs):
        super(BridgeRoute, self).__init__(vtconst.AF_BRIDGE, vrf, None, None,
                                          mac, nh_id, **kwargs)


class InetRoute(Route):

    def __init__(self, vrf, prefix, prefix_len, nh_id, **kwargs):
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
            nh_idi,
            **kwargs)
