#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <malloc.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <ctype.h>
#include <stdlib.h>

#include "vr_os.h"
#include "ini_parser.h"
#include "nl_util.h"

#define BUF_LENGTH 256

static char value[BUF_LENGTH];
static char *ini_data = NULL;
static char ini_file[] = "/etc/contrail/contrail-vrouter-agent.conf";

static void
copy_line(char *buffer, const char *line, uint32_t *index)
{
    uint32_t i = 0;
    if (line[0] == '#') {
        return;
    }

    while (line[i]) {
        if (isspace(line[i])) {
            i++;
            continue;
        }
        buffer[(*index)++] = line[i++];
    }
    buffer[(*index)++] = '\n';
}

static int
read_file_size(const char *file_path)
{
    struct stat stat_buffer;

    if (stat(file_path, &stat_buffer) == 0) {
        return stat_buffer.st_size;
    }
    return 0;
}

int
parse_ini_file(void)
{
    FILE     *fp;
    char      line[4 * BUF_LENGTH];
    size_t    size;
    uint32_t  index = 0;

    fp = fopen(ini_file, "r");
    if (fp == NULL) {
        return -1;
    }

    size = read_file_size(ini_file);
    /*
     * Allocate memory to hold read buffer
     */
    ini_data = calloc(size, sizeof(char));
    if (ini_data == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        copy_line(ini_data, line, &index);
    }

    fclose(fp);
    return 0;
}

bool
read_value(const char *section, const char *key)
{
    const char *section_start = NULL;
    const char *section_end = NULL;
    const char *key_start = NULL;
    const char *value_start = NULL;
    char section_buffer[BUF_LENGTH];
    char buffer[BUF_LENGTH];

    if (!ini_data || !section || !key) {
        return false;
    }

    snprintf(section_buffer, sizeof(section_buffer), "[%s]", section);
    /*
     * Check if section is present
     */
    section_start = strstr(ini_data, section_buffer);

    /*
     * Section is missing
     */
    if (section_start == NULL) {
        return false;
    }

    section_start += strlen(section_buffer) + 1;
    section_end = strstr(section_start, "[");

    key_start = strstr(section_start, key);
    if (key_start == NULL) {
        return false;
    }

    if (section_end && key_start > section_end) {
        /* key not found in same section */
        return false;
    }

    memset(value, 0, sizeof(value));
    buffer[sizeof(buffer) - 1] = '\0';
    strncpy(buffer, key_start, sizeof(buffer) - 1);
    value_start = strtok(buffer, "=");
    value_start = strtok(NULL, "=");
    if (value_start) {
        strcpy(value, value_start);
        char *newline = strchr(value,'\n');
        *newline = '\0';
        return true;
    }
    return false;
}

int
read_int(const char *section, const char *key)
{
    if (read_value(section, key) == false) {
        return 0;
    }
    return atoi(value);
}

const char*
read_string(const char *section, const char *key)
{
    if (read_value(section, key) == false) {
        return NULL;
    }
    return value;
}

uint32_t
read_ip(const char *section, const char *key)
{
    struct in_addr ip;

    if (read_value(section, key) == false) {
        return 0;
    }

    if (inet_pton(AF_INET, value, &ip) == 1) {
        return ntohl(ip.s_addr);
    }
    return 0;
}

int
get_domain()
{
    const char *platform = read_string(DEFAULT_SECTION, PLATFORM_KEY);
    if (platform &&
       (strcmp(platform, PLATFORM_DPDK) == 0 ||
        strcmp(platform, PLATFORM_NIC) == 0)) {
        return AF_INET;
    }
    return AF_NETLINK;
}

int
get_type()
{
    const char *platform = read_string(DEFAULT_SECTION, PLATFORM_KEY);
    if (platform &&
        (strcmp(platform, PLATFORM_DPDK) == 0 ||
         strcmp(platform, PLATFORM_NIC) == 0)) {
        return SOCK_STREAM;
    }
    return SOCK_DGRAM;
}

uint16_t
get_port()
{
    const char *platform = read_string(DEFAULT_SECTION, PLATFORM_KEY);
    if (platform &&
        (strcmp(platform, PLATFORM_DPDK) == 0 ||
         strcmp(platform, PLATFORM_NIC) == 0)) {
        return vr_netlink_port;
    }
    return 0;
}

uint32_t
get_ip()
{
    return 0x7f000001;
}

int
get_protocol()
{
    const char *platform = read_string(DEFAULT_SECTION, PLATFORM_KEY);
    if (platform &&
        (strcmp(platform, PLATFORM_DPDK) == 0 ||
         strcmp(platform, PLATFORM_NIC) == 0)) {
        return 0;
    }
    return NETLINK_GENERIC;
}

int
get_platform(void)
{
    const char *platform = read_string(DEFAULT_SECTION, PLATFORM_KEY);

    if (platform) {
        if (!strcmp(platform, PLATFORM_DPDK))
            return DPDK_PLATFORM;
        else if (!strcmp(platform, PLATFORM_NIC))
            return NIC_PLATFORM;
        else
            return LINUX_PLATFORM;
    }

    return LINUX_PLATFORM;
}

const char *
get_platform_str(void)
{
    return read_string(DEFAULT_SECTION, PLATFORM_KEY);
}
