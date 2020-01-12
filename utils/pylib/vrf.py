#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#
from object_base import *
from vr_py_sandesh.vr_py.ttypes import *
import constants
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')


class Vrf(ObjectBase, vr_vrf_req):
    """
    Vrf class for creating vrf

    Mandatory Parameters:
    --------------------
    vrf_idx : int
        Vrf index

    Optional Parameters:
    -------------------
    vrf_rid : int
        Vrf request index:
    vrf_flags : int
        Vrf flags
    vrf_hbfl_vif_idx : int
        Hbf left vif index
    vrf_hbfr_vif_idx : int
        Hbf right vif index
    """

    def __init__(
            self,
            vrf_idx,
            vrf_rid=0):
        vr_vrf_req.__init__(self)
        super(Vrf, self).__init__()
        self.h_op = constants.SANDESH_OPER_ADD
        self.vrf_rid = vrf_rid
        self.vrf_idx = vrf_idx
        self.sreq_class = vr_vrf_req.__name__

    # Display basic details of the vrf
    def __repr__(self):
        return "Vrf(idx:{})".format(self.vrf_idx)

    def __str__(self):
        return "Vrf(idx:{})".format(self.vrf_idx)

    def set_vrf_flags(self, flags):
        self.vrf_flags = flags

    def set_hbfl_vif_idx(self, idx):
        self.vrf_hbfl_vif_idx = idx

    def set_hbfr_vif_idx(self, idx):
        self.vrf_hbfr_vif_idx = idx

    def delete_hbfl_vif_idx(self):
        self.vrf_hbfl_vif_idx = -1

    def delete_hbfr_vif_idx(self):
        self.vrf_hbfr_vif_idx = -1

    def get(self, key):
        self.h_op = constants.SANDESH_OPER_GET
        return super(Vrf, self).get(key)

    def delete(self):
        self.h_op = constants.SANDESH_OPER_DEL
        super(Vrf, self).delete()
