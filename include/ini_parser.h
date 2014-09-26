/*
 * ini_parser.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __INI_PARSER_H__
#define __INI_PARSER_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_SECTION "DEFAULT"
#define PLATFORM_KEY    "platform"
#define PLATFORM_DPDK   "dpdk"
#define PLATFORM_NIC    "nic"

extern int read_int(const char *section, const char *key);
extern const char *read_string(const char *section, const char *key);
extern uint32_t read_ip(const char *section, const char *key);

extern int get_domain(void);
extern int get_socket_type(void);
extern int get_vrouter_ip(void);
extern uint16_t get_port(void);
extern int parse_ini_file(void);
extern int get_protocol(void);
#ifdef __cplusplus
}
#endif
#endif /* __INI_PARSER_H__ */
