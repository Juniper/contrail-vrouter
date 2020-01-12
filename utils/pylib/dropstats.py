#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

from object_base import *
from common import *
from vr_py_sandesh.vr_py.ttypes import *


class DropStats(ObjectBase, vr_drop_stats_req):
    """
    DropStats class to get dropstats
    """
    def __init__(self, *args, **kwargs):
        vr_drop_stats_req.__init__(self)
        super(DropStats, self).__init__(*args, **kwargs)
        self.h_op = constants.SANDESH_OPER_GET
        self.sreq_class = vr_drop_stats_req.__name__

    def get_vds_invalid_arp(self):
        return int(self.get("vds_invalid_arp"))

    def delete(self):
        pass
