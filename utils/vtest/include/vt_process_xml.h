

#ifndef __VT_PROCESS_XML_H__
#define __VT_PROCESS_XML_H__

#include "vtest.h"
#include <libxml/xmlmemory.h>


typedef enum {
    E_PROCESS_XML_OK = EXIT_SUCCESS,
    E_PROCESS_XML_ERR_FARG,
    E_PROCESS_XML_ERR,
    E_PROCESS_XML_ERR_MSG_SEND,
    E_PROCESS_XML_ERR_MSG_RECV,
    E_PROCESS_XML_ERR_EXPECTED_NODE,

} VT_PROCESS_XML_RET_VAL;


int vt_test_name(xmlNodePtr node, struct vtest *test);
int vt_parse_file(char *file, struct vtest *test);

#endif

