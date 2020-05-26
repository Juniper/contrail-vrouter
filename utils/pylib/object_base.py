#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os
import constants
from common import *
from vr_py_sandesh.vr_py.ttypes import *


class ObjectBase(Base, Common):
    """
    Base class for children classes like vif, nexthop, flow etc.
    so that they can call sync/get/delete to send/receive/delete data
    to/from vrouter
    """
    # Dict to store objects for sync all and auto cleanup
    __obj_dict__ = {}
    auto_cleanup = False
    auto_vif_idx_alloc = False
    auto_nh_id_alloc = False
    __obj_id__ = 0

    @classmethod
    def setUp(self, method):
        """Stores objects for sync all and auto cleanup"""
        super(ObjectBase, self).setUp(method)
        ObjectBase.__obj_dict__ = {}
        ObjectBase.__obj_id__ = 0

    @classmethod
    def tearDown(self):
        """Deletes objects in the reverse order from the list"""
        super(ObjectBase, self).tearDown()
        if ObjectBase.auto_cleanup:
            for id in ObjectBase.__obj_dict__.keys():
                obj = ObjectBase.__obj_dict__[id]
                self.logger.info("\nDeleting object: {}".format(obj))
                obj.delete()

    @classmethod
    def set_auto_features(self, cleanup=False, vif_idx=False, nh_idx=False):
        """Sets auto allocation and cleanup features"""
        self.auto_cleanup = cleanup
        self.auto_vif_idx_alloc = vif_idx
        self.auto_nh_id_alloc = nh_idx

    def __init__(self, *args, **kwargs):
        super(ObjectBase, self).__init__(*args, **kwargs)
        self.__resp_file__ = None
        self.__is_synced__ = False
        ObjectBase.__obj_id__ += 1
        self.__obj_id__ = ObjectBase.__obj_id__
        ObjectBase.__obj_dict__.update({self.__obj_id__: self})

    def sync(self, resp_required=False):
        """
        Launches vtest with appropriate args viz send_sandesh_req
        If successful, set the __is_synced__ to True
        """
        self.logger.info("\nSyncing object: {}".format(self))
        try:
            res_file = self.send_sandesh_req(self, resp_required)
            if resp_required:
                self.__resp_file__ = res_file
            # Sanity check
            if self.__obj_id__ not in ObjectBase.__obj_dict__:
                ObjectBase.__obj_dict__.update({self.__obj_id__: self})
        except Exception as err:
            self.logger.error("Error sending sync sandesh req")
            self.logger.error(err)
        else:
            self.__is_synced__ = True

    def delete(self):
        """Delete the object using SANDESH_OP_DELETE message"""
        try:
            self.h_op = constants.SANDESH_OPER_DEL
            self.send_sandesh_req(self)
            del ObjectBase.__obj_dict__[self.__obj_id__]
        except Exception as err:
            self.logger.error("Error sending delete sandesh req")

    def get(self, key):
        """Parses response file and returns value corresponding to the key"""
        ret_val = None
        if self.__resp_file__ is None:
            self.__resp_file__ = self.send_sandesh_req(self,
                                                       get_resp=True)
        try:
            ret_val = self.parse_xml_field(self.__resp_file__, key)
        except Exception as e:
            self.logger.error("Error %s" % e)
        return ret_val

    def reload(self):
        """Reload the object """
        self.__resp_file__ = None

    @property
    def is_synced(self):
        """Return the sync status"""
        return self.__is_synced__

    @classmethod
    def sync_all(self):
        """This method can be used to sync all objects at once"""
        for id in range(1, ObjectBase.__obj_id__+1):
            # flow has some different mechanism for sync because of reverse
            # flow hence skip flow object
            if not ObjectBase.__obj_dict__[id].__is_synced__ and \
               ObjectBase.__obj_dict__[id].sreq_class != vr_flow_req.__name__:
                ObjectBase.__obj_dict__[id].sync()
