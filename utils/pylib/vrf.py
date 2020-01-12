#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

from vr_py_sandesh.vr_py.ttypes import *
from vtest_object_base import *
import os
import sys
import vtconst
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')


class Vrf(VTestObjectBase, vr_vrf_req):
    def __init__(self, vrf_rid, vrf_idx, vrf_flags=None, vrf_hbfl_vif_idx=None,
                 vrf_hbfr_vif_idx=None):
        vr_vrf_req.__init__(self)
        super(Vrf, self).__init__()
        self.h_op = vtconst.SANDESH_OPER_ADD
        self.vrf_rid = vrf_rid
        self.vrf_idx = vrf_idx
        self.vrf_flags = vrf_flags
        self.vrf_hbfl_vif_idx = vrf_hbfl_vif_idx
        self.vrf_hbfr_vif_idx = vrf_hbfr_vif_idx
        self.sreq_class = vr_vrf_req.__name__

    def get(self, key):
        self.h_op = vtconst.SANDESH_OPER_GET
        return super(Vrf, self).get(key)

    def delete(self):
        self.h_op = vtconst.SANDESH_OPER_DEL
        super(Vrf, self).delete()
