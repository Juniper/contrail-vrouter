#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

from object_base import *
from vr_py_sandesh.vr_py.ttypes import *


class Mirror(ObjectBase, vr_mirror_req):
    """
    Base class to create mirror

    Mandatory Parameters:
    --------------------
    idx : int
        Mirror index
    nh_idx : int
        Nexthop index

    Optional Parameters:
    -------------------
    vni : int
        Vni
    flags : int
        Flags
    """

    def __init__(
            self,
            idx,
            nh_idx,
            vni=0,
            flags=0,
            **kwargs):
        super(Mirror, self).__init__()
        vr_mirror_req.__init__(self)
        self.h_op = constants.SANDESH_OPER_ADD
        self.mirr_index = idx
        self.mirr_nhid = nh_idx
        self.mirr_flags = flags
        self.mirr_vni = vni
        self.sreq_class = vr_mirror_req.__name__

    # Display basic details of mirror
    def __repr__(self):
        return "Mirror(idx:{})".format(self.mirr_index)

    def __str__(self):
        return "Mirror(idx:{})".format(self.mirr_index)

    def idx(self):
        """Returns mirror index"""
        return self.mirr_index

    def get(self, key):
        """
        Queries vrouter and return the key value from the response xml file
        """
        self.h_op = constants.SANDESH_OPER_GET
        return super(Mirror, self).get(key)

    def get_mirr_idx(self):
        """
        Queries vrouter and returns the mirr_index value from the response
        xml file
        """
        return int(self.get('mirr_index'))

    def delete(self):
        self.h_op = constants.SANDESH_OPER_DEL
        super(Mirror, self).delete()
