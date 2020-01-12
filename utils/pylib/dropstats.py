#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import vtconst

from vtest_object_base import *
from vtest_common import *
from vr_py_sandesh.vr_py.ttypes import *


class DropStats(VTestObjectBase, vr_drop_stats_req):
    def __init__(self, *args, **kwargs):
        vr_drop_stats_req.__init__(self)
        super(DropStats, self).__init__(*args, **kwargs)
        self.h_op = vtconst.SANDESH_OPER_GET
        self.sreq_class = vr_drop_stats_req.__name__

    def get_vds_invalid_arp(self):
        return int(self.get("vds_invalid_arp"))
