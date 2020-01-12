#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import vtconst
from vtest_object_base import *
from vr_py_sandesh.vr_py.ttypes import *

class Flow(VTestObjectBase, vr_flow_req):
    """Base class to create flows"""
    def __init__(
            self,
            sip_l,
            sip_u,
            dip_l,
            dip_u,
            sport,
            dport,
            proto,
            family,
            idx=-1,
            ridx=-1,
            flags=vtconst.VR_FLOW_FLAG_ACTIVE,
            flow_nh_id=0,
            src_nh_idx=0,
            qos_id=-1,
            action=vtconst.VR_FLOW_ACTION_FORWARD,
            ecmp_nh_index=-1,
            flow_vrf=0,
            rflow_nh_id=0,
            **kwargs):
        super(Flow, self).__init__()
        vr_flow_req.__init__(self)
        self.fr_op = vtconst.FLOW_OPER_SET
        self.fr_index = idx
        self.fr_rindex = ridx
        self.fr_flow_sip_l = sip_l
        self.fr_flow_sip_u = sip_u
        self.fr_flow_dip_l = dip_l
        self.fr_flow_dip_u = dip_u
        self.fr_family = family
        self.fr_flow_proto = proto
        self.fr_flow_sport = socket.htons(sport)
        self.fr_flow_dport = socket.htons(dport)
        self.fr_flags = flags
        self.fr_flow_nh_id = flow_nh_id
        self.fr_flow_vrf = flow_vrf
        self.fr_src_nh_index = src_nh_idx
        self.fr_ecmp_nh_index = ecmp_nh_index
        self.fr_action = action
        self.fr_qos_id = qos_id
        # set reverse flow params as mirror of forward flow by default
        self.rflow_sip_u = self.fr_flow_dip_u
        self.rflow_sip_l = self.fr_flow_dip_l
        self.rflow_dip_u = self.fr_flow_sip_u
        self.rflow_dip_l = self.fr_flow_sip_l
        self.rflow_sport = self.fr_flow_dport
        self.rflow_dport = self.fr_flow_sport
        self.rflow_nh_id = rflow_nh_id
        self.sreq_class = vr_flow_req.__name__

    # Display basic details of the flow
    def __repr__(self):
        return "Flow(sip:{} dip:{} sport:{} dport{})".format(self.fr_flow_sip_l,
                self.fr_flow_dip_l, self.fr_flow_sport, self.fr_flow_dport)

    def __str__(self):
        return "Flow(sip:{} dip:{} sport:{} dport{})".format(self.fr_flow_sip_l,
                self.fr_flow_dip_l, self.fr_flow_sport, self.fr_flow_dport)

    def sync_and_add_reverse_flow(self):
        """
        Sends a message to add forward flow and
        create corresponding reverse flow, then link both
        """
        # get forward flow index and gen_id
        self.sync(resp_required=True)
        fr_indx = self.get_fr_index()
        fr_genid = self.get_fr_gen_id()

        # create reverse flow
        rflow = Flow(sip_l=self.fr_flow_dip_l, sip_u=self.fr_flow_dip_u,
                    dip_l=self.fr_flow_sip_l, dip_u=self.fr_flow_sip_u,
                    sport=self.fr_flow_dport, dport=self.fr_flow_sport,
                    proto=self.fr_flow_proto, family=self.fr_family)
        rflow.fr_op = vtconst.FLOW_OPER_SET
        rflow.fr_index = -1
        rflow.fr_rindex = fr_indx
        rflow.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
        rflow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE | vtconst.VR_RFLOW_VALID
        rflow.fr_flow_nh_id = self.rflow_nh_id
        rflow.fr_src_nh_index = self.rflow_nh_id
        rflow.fr_qos_id = self.fr_qos_id
        rflow.fr_ecmp_nh_index = self.fr_ecmp_nh_index
        rflow.fr_flow_vrf = self.fr_flow_vrf
        rflow.rflow_sip_u = rflow.fr_flow_dip_u
        rflow.rflow_sip_l = rflow.fr_flow_dip_l
        rflow.rflow_dip_u = rflow.fr_flow_sip_u
        rflow.rflow_dip_l = rflow.fr_flow_sip_l
        rflow.rflow_nh_id = rflow.fr_flow_nh_id
        rflow.rflow_sport = self.rflow_sport

        # sync reverse flow
        rflow.sync(resp_required=True)
        rfr_indx = rflow.get_fr_index()

        # Update forward flow
        self.fr_index = fr_indx
        self.fr_rindex = int(rfr_indx)
        self.fr_gen_id = int(fr_genid)
        self.fr_flags |= vtconst.VR_RFLOW_VALID
        self.sync(resp_required=True)

    def sync_and_link_flow(self, flow2):
        """
        Links the current flow with flow2
        """
        self.sync(resp_required=True)
        fr_indx = self.get_fr_index()
        fr_genid = self.get_fr_gen_id()

        # update flow2
        flow2.fr_rindex = fr_indx
        flow2.fr_flags |= vtconst.VR_RFLOW_VALID
        flow2.sync(resp_required=True)
        rfr_indx = flow2.get_fr_index()

        # Update forward flow
        self.fr_index = fr_indx
        self.fr_rindex = int(rfr_indx)
        self.fr_gen_id = int(fr_genid)
        self.fr_flags |= vtconst.VR_RFLOW_VALID
        self.sync()

    def get(self, key):
        """Parses the key field from the response xml file"""
        return super(Flow, self).get(key)

    def get_fr_index(self):
        """Parses key fresp_index from the response xml file"""
        return int(self.get('fresp_index'))

    def get_fr_gen_id(self):
        """Parses key fresp_gen_id from the response xml file"""
        return int(self.get('fresp_gen_id'))

    def delete(self):
        pass


class InetFlow(Flow):
    """
    InetFlow class to create inet flow

    Mandatory parameters:
    --------------------
    sip : str
        Source ip
    dip : str
        Destination ip
    sport : str
        Source port
    dport : str
        Destination port
    proto : int 
        Protocol

    Optional Parameters:
    -------------------
    flags : int
        Flow flags
    flow_nh_id : int
        Flow nexthop id
    qos_id : int
        Qos id
    action : int
        Flow action
    ecmp_nh_index : int
        Ecmp nexthop index
    flow_vrf : int
        Flow vrf
    rflow_nh_id : int
        Reverse flow id
    """
    def __init__(self, sip, dip, sport, dport, proto,
                 **kwargs):
        super(InetFlow, self).__init__(
            self.vt_ipv4(sip),
            0,
            self.vt_ipv4(dip),
            0,
            sport,
            dport,
            proto,
            family=vtconst.AF_INET,
            **kwargs)


class Inet6Flow(Flow):
    """
    Inet6Flow class to create inet6 flow

    Mandatory parameters:
    --------------------
    sip6_str : str
        Source ipv6 address
    dip6_str : str
        Destination ipv6 address
    sport : str
        Source port
    dport : str
        Destination port
    proto : int 
        Protocol

    Optional Parameters:
    -------------------
    flags : int
        Flow flags
    flow_nh_id : int
        Flow nexthop id
    qos_id : int
        Qos id
    action : int
        Flow action
    ecmp_nh_index : int
        Ecmp nexthop index
    flow_vrf : int
        Flow vrf
    rflow_nh_id : int
        Reverse flow id
    """
    def __init__(self, sip6_str, dip6_str, proto, sport, dport, **kwargs):
        sip6[1], sip6[0]= self.vt_ipv6(sip6_str)
        dip6[1], dip6[0]= self.vt_ipv6(dip6_str)
        super(Inet6Flow, self).__init__(
            sip6[0],
            sip6[1],
            dip6[0],
            dip6[1],
            sport,
            dport,
            vtconst.AF_INET6,
            proto,
            **kwargs)


class NatFlow(Flow):
    """
    NatFlow class to create nat flow

    Mandatory parameters:
    --------------------
    sip : str
        Source ip address
    dip : str
        Destination ip address
    sport : str
        Source port
    dport : str
        Destination port
    proto : int 
        Protocol
    flow_dvrf : int
        Flow dvrf
    rflow_sip : str
        Reverse flow source ip
    rflow_dip : str
        Reverse flow destination ip
    flags : int
        Flow flags
    flow_nh_id : int
        Flow nexthop id
    qos_id : int
        Qos id
    action : int
        Flow action
    ecmp_nh_index : int
        Ecmp nexthop index
    flow_vrf : int
        Flow vrf
    rflow_nh_id : int
        Reverse flow id
    rflow_sport : int
        Reverse flow source port
    """
    def __init__(self, sip, dip, sport, dport, proto, flow_dvrf,
                rflow_sip, rflow_dip, rflow_nh_id, rflow_sport,
                 **kwargs):
        super(NatFlow, self).__init__(
            self.vt_ipv4(sip),
            0,
            self.vt_ipv4(dip),
            0,
            sport,
            dport,
            proto,
            family=vtconst.AF_INET,
            **kwargs)
        self.fr_action = vtconst.VR_FLOW_ACTION_NAT
        self.fr_flow_dvrf = flow_dvrf
        self.rflow_sip_u = 0
        self.rflow_sip_l = self.vt_ipv4(rflow_sip)
        self.rflow_dip_u = 0
        self.rflow_dip_l = self.vt_ipv4(rflow_dip)
        self.rflow_sport = rflow_sport
        self.rflow_nh_id = rflow_nh_id



class MirrorFlow(Flow):
    def __init__():
        pass
