#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import vtconst
import vtest_common
from vtest_object_base import *

from vr_py_sandesh.vr_py.ttypes import *


class Flow(VTestObjectBase, vr_flow_req, VTestCommon):
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

    def sync_and_add_reverse_flow(self):
        self.sync(resp_required=True)
        fr_indx = self.get_fr_index()
        fr_genid = self.get_fr_gen_id()
        print("Forward flow index {}".format(int(fr_indx)))
        print("Forward flow gen index {}".format(int(fr_genid)))

        flow = vr_flow_req()
        flow.fr_op = vtconst.FLOW_OPER_SET
        flow.fr_index = -1
        flow.fr_rindex = fr_indx
        flow.fr_flow_sip_l = self.fr_flow_dip_l
        flow.fr_flow_sip_u = self.fr_flow_dip_u
        flow.fr_flow_dip_l = self.fr_flow_sip_l
        flow.fr_flow_dip_u = self.fr_flow_sip_u
        flow.fr_flow_sport = self.fr_flow_dport
        flow.fr_flow_dport = self.fr_flow_sport
        flow.fr_flow_proto = self.fr_flow_proto
        flow.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
        flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE | vtconst.VR_RFLOW_VALID
        flow.fr_family = self.fr_family
        flow.fr_flow_nh_id = self.rflow_nh_id
        flow.fr_src_nh_index = self.rflow_nh_id
        flow.fr_qos_id = self.fr_qos_id
        flow.fr_ecmp_nh_index = self.fr_ecmp_nh_index
        flow.fr_flow_vrf = self.fr_flow_vrf
        flow.rflow_sip_u = flow.fr_flow_dip_u
        flow.rflow_sip_l = flow.fr_flow_dip_l
        flow.rflow_dip_u = flow.fr_flow_sip_u
        flow.rflow_dip_l = flow.fr_flow_sip_l
        flow.rflow_nh_id = flow.fr_flow_nh_id
        flow.rflow_sport = self.rflow_sport

        resp_file = self.send_sandesh_req(flow, self.VT_RESPONSE_REQD)
        rfr_indx = self.parse_xml_field(resp_file, "fresp_index")

        # Update forward flow
        self.fr_index = fr_indx
        self.fr_rindex = int(rfr_indx)
        self.fr_gen_id = int(fr_genid)
        self.fr_flags |= vtconst.VR_RFLOW_VALID
        resp_file = self.send_sandesh_req(self, self.VT_RESPONSE_REQD)

    def sync_and_link_flow(self, flow2):
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
        return super(Flow, self).get(key)

    def get_fr_index(self):
        return int(self.get('fresp_index'))

    def get_fr_gen_id(self):
        return int(self.get('fresp_gen_id'))

    def delete(self):
        pass


class InetFlow(Flow):
    def __init__(self, sip, dip, sport, dport, proto, family=socket.AF_INET,
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
    def __init__(self, sip6, dip6, proto, sport, dport, family=socket.AF_INET6,
                 **kwargs):
        super(Inet6Flow, self).__init__(
            sip6[0],
            sip6[1],
            dip6[0],
            dip6[1],
            vtconst.AF_INET6,
            proto,
            sport,
            dport,
            **kwargs)


class NatFlow(Flow):
    def __init__():
        pass


class MirrorFlow(Flow):
    def __init__():
        pass
