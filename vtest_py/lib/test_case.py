from test_common import *

obj_list = []


class vTestTestcase(test_common_Testcase, object):
    @classmethod
    def setUpClass(self, method):
        super(vTestTestcase, self).setUpClass(method)

    @classmethod
    def tearDownClass(self, method):
        while(obj_list):
            obj_list.pop()
        super(vTestTestcase, self).tearDownClass(method)


class VIF(vr_interface_req):

    def __init__(
            self,
            idx,
            name,
            ip,
            mac,
            type=vtconst.VIF_TYPE_VIRTUAL,
            ip6_u=0,
            ip6_l=0):
        super(VIF, self).__init__()
        self.h_op = vtconst.SANDESH_OPER_ADD
        self.vifr_type = type
        self.vifr_idx = idx
        self.vifr_name = name
        self.vifr_transport = vtconst.VIF_TRANSPORT_PMD
        self.vifr_vrf = 0
        self.vifr_mac = mac
        self.vifr_mtu = 1514
        self.vifr_ip = ip
        self.vifr_ip6_u = ip6_u
        self.vifr_ip6_l = ip6_l


class NH(vr_nexthop_req):

    def __init__(self, id, type, family, encap_oif, encap):
        super(NH, self).__init__()
        self.h_op = vtconst.SANDESH_OPER_ADD
        self.nhr_id = id
        self.nhr_family = family
        self.nhr_type = type
        self.nhr_vrf = 0
        self.nhr_flags = vtconst.NH_FLAG_VALID
        self.nhr_encap_oif_id = encap_oif
        self.nhr_encap = encap


class ENCAP_NH(NH):
    """Class to represent encap nexthop object, derived from nh"""

    def __init__(self, id, family, encap_oif, encap):
        super(
            ENCAP_NH,
            self).__init__(
            id,
            vtconst.NH_TYPE_ENCAP,
            family,
            encap_oif,
            encap)


class TUNNEL_NHV4(NH):
    """Class to represent ipv4 tunnel nexthop object, derived from nh"""

    def __init__(self, id, tun_sip, tun_dip, encap_oif, encap):
        super(
            TUNNEL_NHV4,
            self).__init__(
            id,
            vtconst.NH_TYPE_TUNNEL,
            vtconst.AF_INET,
            encap_oif,
            encap)
        self.nhr_tun_sip = tun_sip
        self.nhr_tun_dip = tun_dip


class TUNNEL_NHV6(NH):
    """Class to represent ipv6 tunnel nexthop object, derived from nh"""

    def __init__(self, id, tun_sip6, tun_dip6, encap_oif, encap):
        super(
            TUNNEL_NHV6,
            self).__init__(
            id,
            vtconst.NH_TYPE_TUNNEL,
            vtconst.AF_INET6,
            encap_oif,
            encap)
        self.nhr_tun_sip6 = tun_sip6
        self.nhr_tun_dip6 = tun_dip6


class RT(vr_route_req):
    """Class to represent route object"""

    def __init__(
            self,
            family,
            vrf,
            prefix=None,
            prefix_len=None,
            mac=None,
            nh_id=None):
        super(RT, self).__init__()
        self.h_op = vtconst.SANDESH_OPER_ADD
        self.rtr_family = family
        self.rtr_vrf_id = vrf
        self.rtr_mac = mac
        self.rtr_prefix = prefix
        self.rtr_prefix_len = prefix_len
        self.rtr_nh_id = nh_id


class BRIDGE_RT(RT):
    """Class to represent bridge route object"""

    def __init__(self, vrf, mac, nh_id):
        super(
            BRIDGE_RT,
            self).__init__(
            vtconst.AF_BRIDGE,
            vrf,
            None,
            None,
            mac,
            nh_id)


class INET_RT(RT):
    """Class to represent inet route object"""

    def __init__(self, vrf, prefix, prefix_len, nh_id):
        super(
            INET_RT,
            self).__init__(
            vtconst.AF_INET,
            vrf,
            prefix,
            prefix_len,
            None,
            nh_id)


class INET6_RT(RT):
    """Class to represent inet6 route object"""

    def __init__(self, vrf, prefix, prefix_len, nh_id):
        super(
            INET6_RT,
            self).__init__(
            vtconst.AF_INET6,
            vrf,
            prefix,
            prefix_len,
            None,
            nh_id)


class FLOW(vr_flow_req):
    """Class to represent flow object"""

    def __init__(
            self,
            idx,
            sip_l,
            sip_h,
            dip_l,
            dip_h,
            family,
            proto,
            sport,
            dport):
        super(FLOW, self).__init__()
        self.fr_op = vtconst.FLOW_OPER_SET
        self.fr_index = idx
        self.fr_rindex = -1
        self.fr_flow_sip_l = sip_l
        self.fr_flow_sip_h = sip_h
        self.fr_flow_dip_l = dip_l
        self.fr_flow_dip_h = dip_h
        self.fr_family = family
        self.fr_flow_proto = proto
        self.fr_flow_sport = socket.htons(sport)
        self.fr_flow_dport = socket.htons(dport)
        self.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE
        self.fr_ecmp_nh_index = -1
        self.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
        self.fr_qos_id = -1
        # set reverse flow params as mirror of forward flow by default
        self.rflow_sip_u = self.fr_flow_dip_u
        self.rflow_sip_l = self.fr_flow_dip_l
        self.rflow_dip_u = self.fr_flow_sip_u
        self.rflow_dip_l = self.fr_flow_sip_l
        self.rflow_sport = self.fr_flow_dport
        self.rflow_dport = self.fr_flow_sport


class INET_FLOW(FLOW):
    """Class to represent inet flow object"""

    def __init__(self, idx, sip, dip, proto, sport, dport):
        super(
            INET_FLOW,
            self).__init__(
            idx,
            sip,
            0,
            dip,
            0,
            vtconst.AF_INET,
            proto,
            sport,
            dport)


class INET6_FLOW(FLOW):
    """Class to represent inet6 flow object"""

    def __init__(self, idx, sip6, dip6, proto, sport, dport):
        super(INET6_FLOW).__init__(idx, sip6[0], sip6[1], dip6[0], dip6[1],
                                   vtconst.AF_INET6, proto, sport, dport)


class DROPSTATS():
    """Class to represent dropstats object"""

    def __init__(self):
        super(DROPSTATS, self).__init__()
        self.h_op = vtconst.SANDESH_OPER_GET


class util_functions(vTestTestcase, object):
    @classmethod
    def setUpClass(self, method):
        super(util_functions, self).setUpClass(method)

    @classmethod
    def tearDownClass(self, method):
        super(util_functions, self).tearDownClass(method)

    def create_vif(
            self,
            idx,
            nh_id,
            name,
            vrf,
            ip,
            mac,
            flags,
            type=vtconst.VIF_TYPE_VIRTUAL,
            mcast_vrf=65535,
            mtu=1514,
            h_op=vtconst.SANDESH_OPER_ADD,
            transport=vtconst.VIF_TRANSPORT_PMD,
            ip6_u=0,
            ip6_l=0):
        vf = VIF(idx, name, ip, mac, type, ip6_u, ip6_l)
        vf.vifr_transport = transport
        vf.vifr_ip6_u = ip6_u
        vf.vifr_ip6_l = ip6_l
        vf.vifr_mtu = mtu
        vf.h_op = h_op
        vf.vifr_mcast_vrf = mcast_vrf
        vf.vifr_flags = flags
        vf.vifr_nh_id = nh_id
        return vf

    def create_nh(
            self,
            id,
            encap_oif_id,
            encap,
            vrf,
            type,
            flags,
            family=socket.AF_INET,
            h_op=vtconst.SANDESH_OPER_ADD):
        nh = NH(id, type, family, encap_oif_id, encap)
        nh.h_op = h_op
        nh.nh_vrf = vrf
        nh.nhr_flags = flags
        nh.nhr_family = family
        return nh

    def create_encap_nh(
            self,
            id,
            encap_oif_id,
            encap,
            vrf,
            flags,
            family=socket.AF_INET,
            h_op=vtconst.SANDESH_OPER_ADD):
        encap_nh = ENCAP_NH(id, family, encap_oif_id, encap)
        encap_nh.nhr_type = vtconst.NH_TYPE_ENCAP
        encap_nh.h_op = h_op
        encap_nh.nhr_vrf = vrf
        encap_nh.nhr_flags = flags
        encap_nh.nhr_family = family
        return encap_nh

    def create_tunnel_nhv4(
            self,
            id,
            encap_oif_id,
            encap,
            vrf,
            tun_sip,
            tun_dip,
            flags,
            family=socket.AF_INET,
            h_op=vtconst.SANDESH_OPER_ADD):
        tunnel_nh = TUNNEL_NHV4(id, tun_sip, tun_dip, encap_oif_id, encap)
        tunnel_nh.nhr_type = vtconst.NH_TYPE_TUNNEL
        tunnel_nh.h_op = h_op
        tunnel_nh.nhr_vrf = vrf
        tunnel_nh.nhr_family = family
        tunnel_nh.nhr_flags = flags
        return tunnel_nh

    def create_tunnel_nhv6(
            self,
            id,
            encap_oif_id,
            encap,
            vrf,
            tun_sip6,
            tun_dip6,
            flags,
            family=socket.AF_INET6,
            h_op=vtconst.SANDESH_OPER_ADD):
        tunnel_nh = TUNNEL_NHV6(id, tun_sip6, tun_dip6, encap_oif_id, encap)
        tunnel_nh.nhr_type = vtconst.NH_TYPE_TUNNEL
        tunnel_nh.h_op = h_op
        tunnel_nh.nhr_vrf = vrf
        tunnel_nh.nhr_family = family
        tunnel_nh.nhr_flags = flags
        return tunnel_nh

    def create_rt(
            self,
            family,
            vrf,
            nh_id,
            h_op=vtconst.SANDESH_OPER_ADD,
            prefix=None,
            prefix_len=None,
            mac=None):
        rt = RT(family, vrf, prefix, prefix_len, mac, nh_id)
        rt.h_op = h_op
        return rt

    def create_bridge_rt(
            self,
            vrf,
            nh_id,
            mac,
            h_op=vtconst.SANDESH_OPER_ADD,
            prefix=None,
            prefix_len=None):
        bridge_rt = BRIDGE_RT(vrf, mac, nh_id)
        bridge_rt.h_op = h_op
        return bridge_rt

    def create_inet_rt(
            self,
            vrf,
            nh_id,
            prefix,
            prefix_len,
            mac=None,
            h_op=vtconst.SANDESH_OPER_ADD):
        inet_rt = INET_RT(vrf, prefix, prefix_len, nh_id)
        inet_rt.h_op = h_op
        return inet_rt

    def create_inet6_rt(
            self,
            vrf,
            nh_id,
            prefix,
            prefix_len,
            mac=None,
            h_op=vtconst.SANDESH_OPER_ADD):
        inet6_rt = INET6_RT(vrf, prefix, prefix_len, nh_id)
        inet6_rt.h_op = h_op
        return inet6_rt

    def create_flow(
            self,
            idx,
            vrf,
            sip_l,
            sip_h,
            dip_l,
            dip_h,
            family,
            action,
            proto,
            sport,
            dport,
            fr_index,
            flags,
            nh_id,
            src_nh_id,
            qos_id=-1,
            rsip_u=0,
            rsip_l=0,
            rdip_u=0,
            rdip_l=0,
            rnh_id=0,
            rsport=0):
        fl = FLOW(idx, sip_l, sip_h, dip_l, dip_h, family, proto, sport, dport)
        fl.fr_flow_sip_u = 0
        fl.fr_flow_dip_u = 0
        fl.fr_rindex = fr_index
        fl.fr_flags = flags
        fl.fr_nh_id = nh_id
        fl.fr_src_nh_index = src_nh_id
        fl.fr_qos_id = qos_id
        fl.fr_action = action
        fl.fr_ecmp_nh_index = -1
        fl.fr_flow_vrf = vrf
        fl.rflow_sip_u = rsip_u
        fl.rflow_sip_l = rsip_l
        fl.rflow_dip_u = rdip_u
        fl.rflow_dip_l = rdip_l
        fl.rflow_nh_id = rnh_id
        fl.rflow_sport = socket.htons(rsport)
        return fl

    def create_inet_flow(
            self,
            idx,
            vrf,
            sip_l,
            dip_l,
            family,
            action,
            proto,
            sport,
            dport,
            fr_index,
            flags,
            nh_id,
            src_nh_id,
            qos_id=-1,
            rsip_u=0,
            rsip_l=0,
            rdip_u=0,
            rdip_l=0,
            rnh_id=0,
            rsport=0):
        fl = INET_FLOW(idx, sip, dip, proto, sport, dport)
        fl.fr_flow_sip_u = 0
        fl.fr_flow_dip_u = 0
        fl.fr_rindex = fr_index
        fl.fr_flags = flags
        fl.fr_nh_id = nh_id
        fl.fr_src_nh_index = src_nh_id
        fl.fr_qos_id = qos_id
        fl.fr_action = action
        fl.fr_ecmp_nh_index = -1
        fl.fr_flow_vrf = vrf
        fl.rflow_sip_u = rsip_u
        fl.rflow_sip_l = rsip_l
        fl.rflow_dip_u = rdip_u
        fl.rflow_dip_l = rdip_l
        fl.rflow_nh_id = rnh_id
        fl.rflow_sport = socket.htons(rsport)
        return fl

    def create_inet6_flow(
            self,
            idx,
            vrf,
            sip_l,
            dip_l,
            family,
            action,
            proto,
            sport,
            dport,
            fr_index,
            flags,
            nh_id,
            src_nh_id,
            qos_id=-1,
            rsip_u=0,
            rsip_l=0,
            rdip_u=0,
            rdip_l=0,
            rnh_id=0,
            rsport=0):
        fl = INET6_FLOW(idx, sip, dip, proto, sport, dport)
        fl.fr_flow_sip_u = 0
        fl.fr_flow_dip_u = 0
        fl.fr_rindex = fr_index
        fl.fr_flags = flags
        fl.fr_nh_id = nh_id
        fl.fr_src_nh_index = src_nh_id
        fl.fr_qos_id = qos_id
        fl.fr_action = action
        fl.fr_ecmp_nh_index = -1
        fl.fr_flow_vrf = vrf
        fl.rflow_sip_u = rsip_u
        fl.rflow_sip_l = rsip_l
        fl.rflow_dip_u = rdip_u
        fl.rflow_dip_l = rdip_l
        fl.rflow_nh_id = rnh_id
        fl.rflow_sport = socket.htons(rsport)
        return fl
