#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os
from object_base import *
from vr_py_sandesh.vr_py.ttypes import *


class NextHop(ObjectBase, vr_nexthop_req):
    """Base class to create nexthop"""
    # Index to allocate in case of auto index allocation
    _auto_alloc_nh_idx = 0

    def __init__(self, nh_type, nh_idx, nh_family, nh_vrf, nh_flags,
                 encap_oif_id, encap, encap_family, *args, **kwargs):
        super(NextHop, self).__init__()
        vr_nexthop_req.__init__(self)
        self.h_op = constants.SANDESH_OPER_ADD
        if ObjectBase.auto_nh_id_alloc is True:
            NextHop._auto_alloc_nh_idx += 1
            self.nhr_id = NextHop._auto_alloc_nh_idx
        else:
            self.nhr_id = nh_idx
        self.nhr_family = nh_family
        self.nhr_type = nh_type
        self.nhr_vrf = nh_vrf
        self.nhr_flags = constants.NH_FLAG_VALID | nh_flags
        self.nhr_encap_oif_id = encap_oif_id
        if encap is not None:
            self.nhr_encap = self.vt_encap(encap)
        self.nhr_encap_family = encap_family
        self.sreq_class = vr_nexthop_req.__name__

    def __repr__(self):
        """Display basic details of the NextHop"""
        return "NextHop(idx:{})".format(self.nhr_id)

    def __str__(self):
        """Display basic details of the NextHop"""
        return "NextHop(idx:{})".format(self.nhr_id)

    def get(self, key):
        """
        Queries vrouter and returns the key field from the xml response file
        """
        self.h_op = constants.SANDESH_OPER_GET
        return super(NextHop, self).get(key)

    def idx(self):
        """Returns nexthop index"""
        return self.nhr_id

    def get_nh_idx(self):
        """
        Queries vrouter and gets nhr_id value from the xml response file
        """
        return int(self.get('nhr_id'))

    def get_nh_tun_sip(self):
        """
        Queries vrouter and gets nhr_tun_sip valuefrom the xml response file
        """
        return int(self.get('nhr_tun_sip'))

    def get_nh_tun_dip(self):
        """
        Queries vrouter and gets nhr_tun_dip value from the xml response file
        """
        return int(self.get('nhr_tun_dip'))

    def get_nh_family(self):
        """
        Queries vrouter and gets nhr_family value from the xml response file
        """
        return int(self.get('nhr_family'))

    def get_nh_type(self):
        """
        Queries vrouter and gets nhr_type value from the xml response file
        """
        return int(self.get('nhr_type'))

    def set_nh_flags(self, nh_flags):
        """
        Sets the value of nhr_flags
        """
        self.nhr_flags = constants.NH_FLAG_VALID |\
            constants.NH_FLAG_ETREE_ROOT |\
            nh_flags


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
    nh_idx : int
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

    def __init__(self, encap_oif_id, encap, nh_idx=1,
                 nh_family=constants.AF_INET, nh_vrf=0,
                 nh_flags=constants.NH_FLAG_VALID,
                 encap_family=None, **kwargs):
        super(EncapNextHop, self).__init__(
            constants.NH_TYPE_ENCAP,
            nh_idx,
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
    nh_idx : int
        Nexthop id
    nh_vrf : int
        Nexthop vrf id
    nh_flags : int
        Nexthop flags
    encap_family : int
        Encap family
    nh_family : int
        Nexthop family
    """

    def __init__(self, encap_oif_id, encap, tun_sip, tun_dip,
                 tun_sport=None, tun_dport=None, nh_idx=1, nh_vrf=0,
                 nh_flags=constants.NH_FLAG_VALID, encap_family=None,
                 nh_family=constants.AF_INET, **kwargs):
        super(TunnelNextHopV4, self).__init__(
            constants.NH_TYPE_TUNNEL,
            nh_idx,
            nh_family,
            nh_vrf,
            nh_flags,
            encap_oif_id,
            encap,
            encap_family,
            **kwargs)
        self.nhr_tun_sip = self.vt_ipv4(tun_sip)
        self.nhr_tun_dip = self.vt_ipv4(tun_dip)
        self.nhr_tun_sport = tun_sport
        self.nhr_tun_dport = tun_dport


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
    nh_idx : int
        Nexthop id
    """

    def __init__(self, encap_oif_id, encap, tun_sip6, tun_dip6, nh_idx=1,
                 **kwargs):
        super(TunnelNextHopV6, self).__init__(
            constants.NH_TYPE_TUNNEL,
            constants.AF_INET6,
            encap_oif,
            encap,
            **kwargs)
        self.nhr_tun_sip6 = tun_sip6
        self.nhr_tun_dip6 = tun_dip6


class ReceiveL2NextHop(NextHop):
    """
    ReceiveL2NextHop class to create receive l2 nexthops

    Mandatory Parameters:
    --------------------
    nh_idx : int
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

    def __init__(self, nh_idx, nh_family=constants.AF_INET, nh_vrf=0,
                 nh_flags=constants.NH_FLAG_VALID, **kwargs):
        super(ReceiveL2NextHop, self).__init__(
            constants.NH_TYPE_L2_RCV,
            nh_idx,
            nh_family,
            nh_vrf,
            nh_flags,
            encap_oif_id=None,
            encap=None,
            encap_family=None)


class TranslateNextHop(NextHop):
    """
    TranslateNextHop class to create vrf translate nexthops

    Mandatory Parameters:
    --------------------
    nh_idx : int
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

    def __init__(self, nh_idx, nh_family=constants.AF_INET, nh_vrf=0,
                 nh_flags=constants.NH_FLAG_VALID, **kwargs):
        super(TranslateNextHop, self).__init__(
            constants.NH_TYPE_VRF_TRANSLATE,
            nh_idx,
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
    nh_idx : int
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

    def __init__(
            self,
            encap_oif_id,
            nh_idx=1,
            nh_family=constants.AF_INET,
            nh_vrf=0,
            nh_flags=constants.NH_FLAG_VALID,
            encap=None,
            encap_family=None,
            **kwargs):
        super(ReceiveNextHop, self).__init__(
            constants.NH_TYPE_RCV,
            nh_idx,
            nh_family,
            nh_vrf,
            nh_flags,
            encap_oif_id,
            encap,
            encap_family)


class CompositeNextHop(NextHop):
    def __init__(
            self,
            nh_idx=1,
            nh_family=constants.AF_INET,
            nh_vrf=0,
            nh_flags=constants.NH_FLAG_VALID,
            **kwargs):
        super(CompositeNextHop, self).__init__(
            constants.NH_TYPE_COMPOSITE,
            nh_idx,
            nh_family,
            nh_vrf,
            nh_flags,
            encap_oif_id=None,
            encap=None,
            encap_family=None)

    # Add a nexthop to this composite nexthop
    def add_nexthop(self, label, nexthop):
        if self.nhr_nh_list is None:
            self.nhr_nh_list = list()
        self.nhr_nh_list.append(nexthop)

        if self.nhr_label_list is None:
            self.nhr_label_list = list()
        self.nhr_label_list.append(label)
