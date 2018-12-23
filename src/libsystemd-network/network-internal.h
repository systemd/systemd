/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "sd-device.h"
#include "sd-dhcp-lease.h"

#include "condition.h"
#include "conf-parser.h"
#include "set.h"

#define LINK_BRIDGE_PORT_PRIORITY_INVALID 128
#define LINK_BRIDGE_PORT_PRIORITY_MAX 63

bool net_match_config(Set *match_mac,
                      char *const *match_path,
                      char *const *match_driver,
                      char *const *match_type,
                      char *const *match_name,
                      Condition *match_host,
                      Condition *match_virt,
                      Condition *match_kernel_cmdline,
                      Condition *match_kernel_version,
                      Condition *match_arch,
                      const struct ether_addr *dev_mac,
                      const char *dev_path,
                      const char *dev_parent_driver,
                      const char *dev_driver,
                      const char *dev_type,
                      const char *dev_name);

CONFIG_PARSER_PROTOTYPE(config_parse_net_condition);
CONFIG_PARSER_PROTOTYPE(config_parse_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_hwaddrs);
CONFIG_PARSER_PROTOTYPE(config_parse_ifnames);
CONFIG_PARSER_PROTOTYPE(config_parse_ifalias);
CONFIG_PARSER_PROTOTYPE(config_parse_bridge_port_priority);

int net_get_unique_predictable_data(sd_device *device, uint64_t *result);
const char *net_get_name(sd_device *device);

void serialize_in_addrs(FILE *f, const struct in_addr *addresses, size_t size);
int deserialize_in_addrs(struct in_addr **addresses, const char *string);
void serialize_in6_addrs(FILE *f, const struct in6_addr *addresses, size_t size);
int deserialize_in6_addrs(struct in6_addr **addresses, const char *string);

/* don't include "dhcp-lease-internal.h" as it causes conflicts between netinet/ip.h and linux/ip.h */
struct sd_dhcp_route;

void serialize_dhcp_routes(FILE *f, const char *key, sd_dhcp_route **routes, size_t size);
int deserialize_dhcp_routes(struct sd_dhcp_route **ret, size_t *ret_size, size_t *ret_allocated, const char *string);

/* It is not necessary to add deserialize_dhcp_option(). Use unhexmem() instead. */
int serialize_dhcp_option(FILE *f, const char *key, const void *data, size_t size);
