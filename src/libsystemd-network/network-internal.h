/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/nl80211.h>
#include <stdbool.h>

#include "sd-device.h"
#include "sd-dhcp-lease.h"

#include "conf-parser.h"
#include "set.h"
#include "strv.h"

#define LINK_BRIDGE_PORT_PRIORITY_INVALID 128
#define LINK_BRIDGE_PORT_PRIORITY_MAX 63

char *link_get_type_string(unsigned short iftype, sd_device *device);
bool net_match_config(Set *match_mac,
                      Set *match_permanent_mac,
                      char * const *match_path,
                      char * const *match_driver,
                      char * const *match_type,
                      char * const *match_name,
                      char * const *match_property,
                      char * const *match_wifi_iftype,
                      char * const *match_ssid,
                      Set *match_bssid,
                      unsigned short iftype,
                      sd_device *device,
                      const struct ether_addr *dev_mac,
                      const struct ether_addr *dev_permanent_mac,
                      const char *dev_name,
                      char * const *alternative_names,
                      enum nl80211_iftype wifi_iftype,
                      const char *ssid,
                      const struct ether_addr *bssid);

CONFIG_PARSER_PROTOTYPE(config_parse_net_condition);
CONFIG_PARSER_PROTOTYPE(config_parse_hwaddr);
CONFIG_PARSER_PROTOTYPE(config_parse_hwaddrs);
CONFIG_PARSER_PROTOTYPE(config_parse_match_strv);
CONFIG_PARSER_PROTOTYPE(config_parse_match_ifnames);
CONFIG_PARSER_PROTOTYPE(config_parse_match_property);
CONFIG_PARSER_PROTOTYPE(config_parse_ifalias);
CONFIG_PARSER_PROTOTYPE(config_parse_bridge_port_priority);

int net_get_unique_predictable_data(sd_device *device, bool use_sysname, uint64_t *result);
const char *net_get_name_persistent(sd_device *device);

size_t serialize_in_addrs(FILE *f,
                          const struct in_addr *addresses,
                          size_t size,
                          bool with_leading_space,
                          bool (*predicate)(const struct in_addr *addr));
int deserialize_in_addrs(struct in_addr **addresses, const char *string);
void serialize_in6_addrs(FILE *f, const struct in6_addr *addresses,
                         size_t size);
int deserialize_in6_addrs(struct in6_addr **addresses, const char *string);

/* don't include "dhcp-lease-internal.h" as it causes conflicts between netinet/ip.h and linux/ip.h */
struct sd_dhcp_route;

void serialize_dhcp_routes(FILE *f, const char *key, sd_dhcp_route **routes, size_t size);
int deserialize_dhcp_routes(struct sd_dhcp_route **ret, size_t *ret_size, size_t *ret_allocated, const char *string);

/* It is not necessary to add deserialize_dhcp_option(). Use unhexmem() instead. */
int serialize_dhcp_option(FILE *f, const char *key, const void *data, size_t size);
