#include <stdio.h>

#include <vtest.h>

/*
 * Parse XML structure and set structures packet and packet interface (vtest.h)
 */
int
vt_packet(xmlNodePtr node, struct vtest *test)
{
    fprintf(stderr, "Warning: packet node is not supported on Windows, skipping\n");
    return EXIT_SUCCESS;
}
