#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os

class VTestObjectBase(VTestCommon):
    # Add setUp(), tearDown() functions

    # Dict to store objects for auto cleanup
    __obj_list__ = []

    def __init__(self, *argc, **kwargs):
        self.__resp_file__ = ""
        self.__is_synced__ = False

        # Add current object in the list
        # if auto-cleanup is enabled
        if self.auto_cleanup:
            cls.__obj_dict__.append(self)

    def sync(self):
        # Add code to invoke launch vtest with appropriate args
        # viz send_sandesh_req
        # If successful, set the __is_synced__ to True
        #                else set it to False
        pass

    def delete(self):
        # Add code here to delete the object using SANDESH_OP_DELETE message
        pass

    def get(self, key):
        # Add code here to parse_xml_field()  and return the value 
        # corresponding to the key
        pass

    @property
    def is_synced(self):
        # Return the status sync
        return True

    @staticmethod
    def sync_all(self):
        # This static method can be used to sync all objects
        for obj in cls.__obj_list__:
            obj.sync()
