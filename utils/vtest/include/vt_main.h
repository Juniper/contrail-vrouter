
#ifndef __MAIN_H__
#define __MAIN_H__

#include <stdlib.h>
#include <stdlib.h>

#define vt_safe_free(ptr) safer_free((void**)&(ptr))

static void
safer_free(void **mem) {

    if (mem && *mem) {
        free(*mem);
        *mem = NULL;
    }

    return;
}

typedef enum {

    E_MAIN_OK = EXIT_SUCCESS,
    E_MAIN_CHECK_OK,
    E_MAIN_TEST_FAIL,
    E_MAIN_TEST_PASS,
    E_MAIN_ERR_XML,
    E_MAIN_ERR_FARG,
    E_MAIN_ERR,
    E_MAIN_ERR_ALLOC,
    E_MAIN_ERR_SOCK,
    E_MAIN_SKIP

} VT_MAIN_RET_VAL;

#endif

