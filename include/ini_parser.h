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

#define LINUX_PLATFORM  1
#define DPDK_PLATFORM   2
#define NIC_PLATFORM    3

#define DEFAULT_SECTION "DEFAULT"
#define PLATFORM_KEY    "platform"
#define PLATFORM_DPDK   "dpdk"
#define PLATFORM_NIC    "nic"

extern int read_int(const char *section, const char *key);
extern const char *read_string(const char *section, const char *key);
extern uint32_t read_ip(const char *section, const char *key);

extern int get_type(void);
extern uint16_t get_port(void);
extern uint32_t get_ip(void);

extern int get_domain(void);
extern int get_socket_type(void);
extern int get_vrouter_ip(void);
extern int get_platform(void);
extern const char *get_platform_str(void);
extern int get_protocol(void);

extern int parse_ini_file(void);

#ifdef __cplusplus
}
#endif
#endif /* __INI_PARSER_H__ */
