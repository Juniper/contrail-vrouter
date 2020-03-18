#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

from vr_py_sandesh.vr_py.ttypes import *
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from object_base import *  # noqa
import constants  # noqa


class Vxlan(ObjectBase, vr_vxlan_req):
    """
    Vxlan class for creating vxlan

    Mandatory Parameters:
    --------------------
    vxlan_idx : int
        Vxlan index

    Optional Parameters:
    -------------------
    vxlan_nhid : int
        vxlan nexthop index:
    """

    def __init__(
            self,
            vxlan_idx,
            vxlan_nhid=0):
        vr_vxlan_req.__init__(self)
        super(Vxlan, self).__init__()
        self.h_op = constants.SANDESH_OPER_ADD
        self.vxlanr_vnid = vxlan_idx
        self.vxlanr_nhid = vxlan_nhid
        self.sreq_class = vr_vxlan_req.__name__

    # Display basic details of vxlan
    def __repr__(self):
        return "Vxlan(idx:{})".format(self.vxlanr_vnid)

    def __str__(self):
        return "Vxlan(idx:{})".format(self.vxlanr_vnid)

    def idx(self):
        """Returns vxlan index"""
        return self.vxlanr_vnid

    def get(self, key):
        """
        Queries vrouter and return the key value from the response xml file
        """
        self.h_op = constants.SANDESH_OPER_GET
        return super(Vxlan, self).get(key)

    def get_vxlan_idx(self):
        """
        Queries vrouter and returns vxlanr_vnid value from the response
        xml file
        """
        return int(self.get('vxlanr_vnid'))

    def delete(self):
        self.h_op = constants.SANDESH_OPER_DEL
        super(Vxlan, self).delete()
