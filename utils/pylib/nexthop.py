#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os
from vtest_object_base import *
from vtest_common import *

from vr_py_sandesh.vr_py.ttypes import *


class NextHop(vr_nexthop_req, VTestObjectBase, VTestCommon):
    # Index to allocate in case of auto index allocation
    _auto_alloc_nh_id = 0

    def __init__(self, nh_type, nh_id, nh_family, nh_vrf, nh_flags,
                 encap_oif_id, encap, encap_family, *args, **kwargs):
        super(NextHop, self).__init__()
        VTestObjectBase.__init__(self)
        self.h_op = vtconst.SANDESH_OPER_ADD
        if VTestCommon.nh_auto_alloc is True:
            NextHop._auto_alloc_nh_id += 1
            self.nhr_id = NextHop._auto_alloc_nh_id
        else:
            self.nhr_id = nh_id
        self.nhr_family = nh_family
        self.nhr_type = nh_type
        self.nhr_vrf = nh_vrf
        self.nhr_flags = nh_flags
        self.nhr_encap_oif_id = encap_oif_id
        if encap is not None:
            self.nhr_encap = self.vt_encap(encap)
        self.nhr_encap_family = encap_family
        self.sreq_class = vr_nexthop_req.__name__

    def get(self, key):
        self.h_op = vtconst.SANDESH_OPER_GET
        return super(NextHop, self).get(key)

    def id(self):
        return self.nhr_id

    def get_nh_id(self):
        return int(self.get('nhr_id'))

    def get_nh_tun_sip(self):
        return int(self.get('nhr_tun_sip'))

    def get_nh_tun_dip(self):
        return int(self.get('nhr_tun_dip'))


class EncapNextHop(NextHop):

    def __init__(self, encap_oif_id, encap, nh_id=1,
                 nh_family=vtconst.AF_INET, nh_vrf=0,
                 nh_flags=vtconst.NH_FLAG_VALID,
                 encap_family=None, **kwargs):
        super(EncapNextHop, self).__init__(
            vtconst.NH_TYPE_ENCAP,
            nh_id,
            nh_family,
            nh_vrf,
            nh_flags,
            encap_oif_id,
            encap,
            encap_family,
            **kwargs)


class TunnelNextHopV4(NextHop):

    def __init__(self, encap_oif_id, encap, tun_sip, tun_dip,
                 nh_id=1, nh_family=vtconst.AF_INET, nh_vrf=0,
                 nh_flags=vtconst.NH_FLAG_VALID, encap_family=None,
                 **kwargs):
        super(TunnelNextHopV4, self).__init__(
            vtconst.NH_TYPE_TUNNEL,
            nh_id,
            nh_family,
            nh_vrf,
            nh_flags,
            encap_oif_id,
            encap,
            encap_family,
            **kwargs)
        self.nhr_tun_sip = self.vt_ipv4(tun_sip)
        self.nhr_tun_dip = self.vt_ipv4(tun_dip)


class TunnelNextHopV6(NextHop):

    def __init__(self, encap_oif_id, encap, tun_sip6, tun_dip6, nh_id=1,
                 **kwargs):
        super(TunnelNextHopV6, self).__init__(
            vtconst.NH_TYPE_TUNNEL,
            vtconst.AF_INET6,
            encap_oif,
            encap,
            **kwargs)
        self.nhr_tun_sip6 = tun_sip6
        self.nhr_tun_dip6 = tun_dip6


class CompositeNextHop(vr_nexthop_req, VTestObjectBase):
    def __init__():
        pass

    # Add a nexthop to this composite nexthop
    def add_nexthop(nexthop):
        pass

class ReceiveL2NextHop(NextHop):

    def __init__(self, nh_id, nh_family=vtconst.AF_INET, nh_vrf=0,
                 nh_flags=vtconst.NH_FLAG_VALID, **kwargs):
        super(ReceiveL2NextHop, self).__init__(
            vtconst.NH_TYPE_L2_RCV,
            nh_id,
            nh_family,
            nh_vrf,
            nh_flags,
            encap_oif_id=None,
            encap=None,
            encap_family=None)

class ReceiveNextHop(NextHop):

    def __init__(self, encap_oif_id, nh_id=1, nh_family=vtconst.AF_INET, nh_vrf=0,
                 nh_flags=vtconst.NH_FLAG_VALID, encap=None, encap_family=None,
                 **kwargs):
        super(ReceiveNextHop, self).__init__(
            vtconst.NH_TYPE_RCV,
            nh_id,
            nh_family,
            nh_vrf,
            nh_flags,
            encap_oif_id,
            encap,
            encap_family)
