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

class dropstats(vr_drop_stats_req):
    """Class to represent dropstats object"""

    def __init__(self):
        super(dropstats, self).__init__()
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
        vf = vr_interface_req()
        vf.vifr_idx = idx
        vf.vifr_vrf = vrf
        vf.vifr_name = name
        vf.vifr_ip = ip
        vf.vifr_mac = mac
        vf.vifr_type = type
        vf.vifr_ip6_u = ip6_u
        vf.vifr_ip6_l = ip6_l
        vf.vifr_transport = transport
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
            nh_type,
            family,
            flags=vtconst.NH_FLAG_VALID,
            h_op=vtconst.SANDESH_OPER_ADD,
            tun_sip=None,
            tun_dip=None,
            tun_sip6=None,
            tun_dip6=None):
        nh = vr_nexthop_req()
        nh.nhr_id = id
        nh.nhr_type = nh_type
        nh.nhr_family = family
        nh.nhr_encap_oif_id = encap_oif_id
        nh.nhr_encap = encap
        nh.h_op = h_op
        nh.nhr_vrf = vrf
        nh.nhr_flags = flags
        nh.nhr_family = family
        nh.nhr_tun_sip = tun_sip
        nh.nhr_tun_dip = tun_dip
        nh.nhr_tun_sip6 = tun_sip6
        nh.nhr_tun_dip6 = tun_dip6
        return nh

    def create_encap_nh(
            self,
            id,
            encap_oif_id,
            encap,
            vrf,
            family,
            flags,
            type=vtconst.NH_TYPE_ENCAP,
            h_op=vtconst.SANDESH_OPER_ADD):
        e_nh = self.create_nh(id, encap_oif_id, encap, vrf, type, family, flags, h_op)
        return e_nh

    def create_tunnel_nhv4(
            self,
            id,
            encap_oif_id,
            encap,
            vrf,
            tun_sip,
            tun_dip,
            flags=vtconst.NH_FLAG_VALID,
            family=socket.AF_INET,
            h_op=vtconst.SANDESH_OPER_ADD):
        tunnel_nh = self.create_nh(id, encap_oif_id, encap, vrf, vtconst.NH_TYPE_TUNNEL, family, flags, h_op, tun_sip, tun_dip)
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
        tunnel_nh = self.create_nh(id, encap_oif_id, encap, vrf, vtconst.NH_TYPE_TUNNEL, flags, family, h_op, None, None, tun_sip6, tun_dip6)
        return tunnel_nh

    def create_rt(
            self,
            family,
            vrf,
            nh_id,
            label,
            flags,
            h_op=vtconst.SANDESH_OPER_ADD,
            prefix=None,
            prefix_len=None,
            mac=None):
        rt = vr_route_req()
        rt.rtr_family = family
        rt.rtr_vrf = vrf
        rt.rtr_prefix = prefix
        rt.rtr_prefix_len = prefix_len
        rt.rtr_mac = mac
        rt.rtr_label = label
        rt.rtr_flags = flags
        rt.rtr_nh_id = nh_id
        rt.h_op = h_op
        return rt

    def create_bridge_rt(
            self,
            vrf,
            nh_id,
            mac,
            label,
            flags,
            h_op=vtconst.SANDESH_OPER_ADD,
            prefix=None,
            prefix_len=None):
        bridge_rt = self.create_rt(vtconst.AF_BRIDGE, vrf, nh_id, label, flags, h_op, prefix, prefix_len, mac)
        return bridge_rt

    def create_inet_rt(
            self,
            vrf,
            nh_id,
            prefix,
            prefix_len,
            label,
            flags,
            mac=None,
            h_op=vtconst.SANDESH_OPER_ADD):
        inet_rt = self.create_rt(socket.AF_INET, vrf, nh_id, label, flags, h_op, prefix, prefix_len, mac)
        return inet_rt

    def create_inet6_rt(
            self,
            vrf,
            nh_id,
            prefix,
            prefix_len,
            label,
            flags,
            mac=None,
            h_op=vtconst.SANDESH_OPER_ADD):
        inet6_rt = self.create_rt(socket.AF_INET6, vrf, nh_id, label, flags, h_op, prefix, prefix_len, mac)
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
            fr_rindex,
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
        fl = vr_flow_req()
        fl.fr_op = vtconst.FLOW_OPER_SET
        fl.fr_index = idx
        fl.fr_rindex = fr_rindex
        fl.fr_flow_sip_l = sip_l
        fl.fr_flow_sip_h = sip_h
        fl.fr_flow_dip_l = dip_l
        fl.fr_flow_dip_h = dip_h
        fl.fr_family = family
        fl.fr_flow_proto = proto
        fl.fr_flow_sport = sport
        fl.fr_flow_dport = dport
        fl.fr_flags = flags
        fl.fr_ecmp_nh_index = -1
        fl.fr_action = action
        fl.rflow_dport = fl.fr_flow_sport
        fl.fr_flow_sip_u = 0
        fl.fr_flow_dip_u = 0
        fl.fr_flow_nh_id = nh_id
        fl.fr_src_nh_index = src_nh_id
        fl.fr_qos_id = qos_id
        fl.fr_flow_vrf = vrf
        fl.rflow_sip_u = rsip_u
        fl.rflow_sip_l = rsip_l
        fl.rflow_dip_u = rdip_u
        fl.rflow_dip_l = rdip_l
        fl.rflow_nh_id = rnh_id
        fl.rflow_sport = rsport
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
        fl = self.create_flow(idx, vrf, sip_l, 0, dip_l, 0, socket.AF_INET, action, proto, sport, dport, fr_index, flags, nh_id, src_nh_id,
            qos_id, rsip_u, rsip_l, rdip_u, rdip_l, rnh_id, rsport)
        return fl

    def create_inet6_flow(
            self,
            idx,
            vrf,
            sip_l,
            dip_l,
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
        fl = self.create_flow(idx, vrf, sip_l, sip_h, dip_l, dip_h, socket.AF_INET6, action, proto, sport, dport, fr_index, flags, nh_id, src_nh_id,
            qos_id=-1, rsip_u=0, rsip_l=0, rdip_u=0, rdip_l=0, rnh_id=0, rsport=0)
        return fl
