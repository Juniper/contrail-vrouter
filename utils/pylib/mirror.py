#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

from object_base import *
from vr_py_sandesh.vr_py.ttypes import *


class Mirror(ObjectBase, vr_mirror_req):
    """Base class to create mirror"""

    def __init__(
            self,
            idx,
            nh_idx,
            vni,
            flags,
            **kwargs):
        super(Mirror, self).__init__()
        vr_mirror_req.__init__(self)
        self.h_op = constants.SANDESH_OPER_ADD
        self.mirr_index = idx
        self.mirr_nhid = nh_idx
        self.mirr_flags = flags
        self.mirr_vni = vni
        self.sreq_class = vr_mirror_req.__name__
