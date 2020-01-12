#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import vtconst
from vtest_object_base import *

from vr_py_sandesh.vr_py.ttypes import *


class Mpls(VtestObjectBase, vr_mpls_req):
    def __init__(self, mr_label, mr_rid=0, mr_nhid=None):
        super(Mpls, self).__init__()
        vr_mpls_req.__init__()
        self.h_op = vtconst.SANDESH_OPER_ADD
        self.mr_label = mr_label
        self.mr_rid = mr_rid
        if mr_nhid:
            self.mr_nhid = mr_nhid

    def get(self, key):
        self.h_op = vtconst.SANDESH_OPER_GET
        return super(Mpls, self).get(key)
