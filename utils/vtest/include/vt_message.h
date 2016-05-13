#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <stdlib.h>
#include <stdlib.h>


typedef enum {

    E_MESSAGE_OK = EXIT_SUCCESS,
    E_MESSAGE_ERR_FARG,
    E_MESSAGE_ERR,
    E_MESSAGE_ERR_ALLOC,
    E_MESSAGE_ERR_SOCK,
    E_MESSAGE_ERR_MESSAGE_NODE,
    E_MESSAGE_ERR_MESSAGE_MODULES,
    E_MESSAGE_ERR_UNK

} VT_MESSAGE_RET_VAL;

int vt_expect_node(xmlNodePtr, struct vtest *);


#endif

