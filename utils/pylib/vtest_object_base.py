#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os
import vtconst
from vtest_common import *
from vr_py_sandesh.vr_py.ttypes import *


class VTestObjectBase(VTestBase, VTestCommon):
    # Dict to store objects for auto cleanup
    __obj_list__ = []
    auto_vif_idx_alloc = False
    auto_nh_id_alloc = False

    # Add setUp(), tearDown() functions
    @classmethod
    def setUp(self, method):
        super(VTestObjectBase, self).setUp(method)
        self.__obj_list__ = []

    @classmethod
    def tearDown(self):
        super(VTestObjectBase, self).tearDown()
        if VTestObjectBase.auto_cleanup:
            while len(self.__obj_list__) > 0:
                obj = self.__obj_list__.pop()
                self.logger.info("\nDeleting object: {}".format(obj))
                obj.delete()

    @classmethod
    def setUpClass(self):
        super(VTestObjectBase, self).setUpClass()

    @classmethod
    def tearDownClass(self):
        super(VTestObjectBase, self).tearDownClass()

    @classmethod
    def set_auto_features(self, cleanup=False, vif_idx=False, nh_idx=False):
        self.auto_cleanup = cleanup
        self.auto_vif_idx_alloc = vif_idx
        self.auto_nh_id_alloc = nh_idx

    def __init__(self, *args, **kwargs):
        super(VTestObjectBase, self).__init__(*args, **kwargs)
        self.__resp_file__ = None
        self.__is_synced__ = False
        VTestObjectBase.__obj_list__.append(self)

    def sync(self, resp_required=False):
        # Launch vtest with appropriate args viz send_sandesh_req
        # If successful, set the __is_synced__ to True
        try:
            res_file = self.send_sandesh_req(self, resp_required)
            if resp_required:
                self.__resp_file__ = res_file
        except Exception as err:
            self.logger.error("Error sending sync sandesh req")
            self.logger.error(err)
        else:
            self.__is_synced__ = True

    def delete(self):
        # Delete the object using SANDESH_OP_DELETE message
        try:
            self.h_op = vtconst.SANDESH_OPER_DEL
            self.send_sandesh_req(self)
        except Exception as err:
            self.logger.error("Error sending delete sandesh req")

    def get(self, key):
        # parse_xml_field()  and return the value corresponding to the key
        ret_val = None
        if self.__resp_file__ is None:
            self.__resp_file__ = self.send_sandesh_req(self,
                                                       self.VT_RESPONSE_REQD)
        try:
            ret_val = self.parse_xml_field(self.__resp_file__, key)
        except Exception as e:
            self.logger.error("Error %s" % e)
        return ret_val

    @property
    def is_synced(self):
        # Return the status sync
        return self.__is_synced__

    @classmethod
    def sync_all(self):
        # This class method can be used to sync all objects
        for obj in self.__obj_list__:
            # flow has some different mechanism for sync because of reverse flow
            # hence skip flow object
            if not obj.__is_synced__ and obj.sreq_class != vr_flow_req.__name__ :
                self.logger.info("\nSyncing object: {}".format(obj))
                obj.sync()
