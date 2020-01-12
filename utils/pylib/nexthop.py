#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os
from object_base import *
from vr_py_sandesh.vr_py.ttypes import *


class NextHop(ObjectBase, vr_nexthop_req):
    """Base class to create nexthop"""
    # Index to allocate in case of auto index allocation
    _auto_alloc_nh_id = 0

    def __init__(self, nh_type, nh_id, nh_family, nh_vrf, nh_flags,
                 encap_oif_id, encap, encap_family, *args, **kwargs):
        super(NextHop, self).__init__()
        vr_nexthop_req.__init__(self)
        self.h_op = constants.SANDESH_OPER_ADD
        if ObjectBase.auto_nh_id_alloc is True:
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

    # Display basic details of the nexthop
    def __repr__(self):
        return "NextHop(idx:{})".format(self.nhr_id)

    def __str__(self):
        return "NextHop(idx:{})".format(self.nhr_id)

    def get(self, key):
        """Parses the key field from the xml response file"""
        self.h_op = constants.SANDESH_OPER_GET
        return super(NextHop, self).get(key)

    def idx(self):

        return self.nhr_id

    def get_nh_id(self):
        """Parses the key nhr_id from the xml response file"""
        return int(self.get('nhr_id'))

    def get_nh_tun_sip(self):
        """Parses the key nhr_tun_sip from the xml response file"""
        return int(self.get('nhr_tun_sip'))

    def get_nh_tun_dip(self):
        """Parses the key nhr_tun_dip from the xml response file"""
        return int(self.get('nhr_tun_dip'))


class EncapNextHop(NextHop):
    """
    EncapNextHop class to create encap nexthops

    Mandatory Parameters:
    --------------------
    encap_oif_id : int
        Encap outer interface id
    encap : str
        Encap data

    Optional Parameters:
    -------------------
    nh_id : int
        Nexthop id
    nh_family : int
        Nexthop family
    nh_vrf : int
        Nexthop vrf id
    nh_flags : int
        Nexthop flags
    encap_family : int
        Encap family
    """

    def __init__(self, encap_oif_id, encap, nh_id=1,
                 nh_family=constants.AF_INET, nh_vrf=0,
                 nh_flags=constants.NH_FLAG_VALID,
                 encap_family=None, **kwargs):
        super(EncapNextHop, self).__init__(
            constants.NH_TYPE_ENCAP,
            nh_id,
            nh_family,
            nh_vrf,
            nh_flags,
            encap_oif_id,
            encap,
            encap_family,
            **kwargs)


class TunnelNextHopV4(NextHop):
    """
    TunnelNextHopV4 class to create v4 tunnel nexthops

    Mandatory Parameters:
    --------------------
    encap_oif_id : int
        Encap outer interface id
    encap : str
        Encap data
    tun_sip : str
        Tunnel source ip
    tun_dip : str
        Tunnel destination ip

    Optional Parameters:
    -------------------
    nh_id : int
        Nexthop id
    nh_vrf : int
        Nexthop vrf id
    nh_flags : int
        Nexthop flags
    encap_family : int
        Encap family
    """
    def __init__(self, encap_oif_id, encap, tun_sip, tun_dip,
                 nh_id=1, nh_vrf=0, nh_flags=constants.NH_FLAG_VALID,
                 encap_family=None, **kwargs):
        super(TunnelNextHopV4, self).__init__(
            constants.NH_TYPE_TUNNEL,
            nh_id,
            constants.AF_INET,
            nh_vrf,
            nh_flags,
            encap_oif_id,
            encap,
            encap_family,
            **kwargs)
        self.nhr_tun_sip = self.vt_ipv4(tun_sip)
        self.nhr_tun_dip = self.vt_ipv4(tun_dip)


class TunnelNextHopV6(NextHop):
    """
    TunnelNextHopV6 class to create v6 tunnel nexthops

    Mandatory Parameters:
    --------------------
    encap_oif_id : int
        Encap outer interface id
    encap : str
        Encap data
    tun_sip6 : str
        Tunnel source ipv6 address
    tun_dip6 : str
        Tunnel destination ipv6 address

    Optional Parameters:
    -------------------
    nh_id : int
        Nexthop id
    """

    def __init__(self, encap_oif_id, encap, tun_sip6, tun_dip6, nh_id=1,
                 **kwargs):
        super(TunnelNextHopV6, self).__init__(
            constants.NH_TYPE_TUNNEL,
            constants.AF_INET6,
            encap_oif,
            encap,
            **kwargs)
        self.nhr_tun_sip6 = tun_sip6
        self.nhr_tun_dip6 = tun_dip6


class CompositeNextHop(vr_nexthop_req, ObjectBase):
    def __init__():
        # TODO
        pass

    # Add a nexthop to this composite nexthop
    def add_nexthop(nexthop):
        # TODO
        pass

class ReceiveL2NextHop(NextHop):
    """
    ReceiveL2NextHop class to create receive l2 nexthops

    Mandatory Parameters:
    --------------------
    nh_id : int
        Nexthop id

    Optional Parameters:
    -------------------
    nh_family : int
        Nexthop family
    nh_vrf : int
        Nexthop vrf id
    nh_flags : int
        Nexthop flags
    """

    def __init__(self, nh_id, nh_family=constants.AF_INET, nh_vrf=0,
                 nh_flags=constants.NH_FLAG_VALID, **kwargs):
        super(ReceiveL2NextHop, self).__init__(
            constants.NH_TYPE_L2_RCV,
            nh_id,
            nh_family,
            nh_vrf,
            nh_flags,
            encap_oif_id=None,
            encap=None,
            encap_family=None)

class ReceiveNextHop(NextHop):
    """
    ReceiveNextHop class to create receive nexthops

    Mandatory Parameters:
    --------------------
    encap_oif_id : int
        Encap outer interface id

    Optional Parameters:
    -------------------
    nh_id : int
        Nexthop id
    nh_family : int
        Nexthop family
    nh_vrf : int
        Nexthop vrf id
    nh_flags : int
        Nexthop flags
    encap : str
        Encap data
    encap_family : int
        Encap family
    """

    def __init__(self, encap_oif_id, nh_id=1, nh_family=constants.AF_INET, nh_vrf=0,
                 nh_flags=constants.NH_FLAG_VALID, encap=None, encap_family=None,
                 **kwargs):
        super(ReceiveNextHop, self).__init__(
            constants.NH_TYPE_RCV,
            nh_id,
            nh_family,
            nh_vrf,
            nh_flags,
            encap_oif_id,
            encap,
            encap_family)
