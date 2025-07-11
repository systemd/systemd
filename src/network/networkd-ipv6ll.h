/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/if_link.h>

#include "networkd-forward.h"

typedef enum IPv6LinkLocalAddressGenMode {
       IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_EUI64          = IN6_ADDR_GEN_MODE_EUI64,
       IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_NONE           = IN6_ADDR_GEN_MODE_NONE,
       IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_STABLE_PRIVACY = IN6_ADDR_GEN_MODE_STABLE_PRIVACY,
       IPV6_LINK_LOCAL_ADDRESSS_GEN_MODE_RANDOM         = IN6_ADDR_GEN_MODE_RANDOM,
       _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_MAX,
       _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_INVALID        = -EINVAL,
} IPv6LinkLocalAddressGenMode;

bool link_ipv6ll_enabled(Link *link);
bool link_ipv6ll_enabled_harder(Link *link);

IPv6LinkLocalAddressGenMode link_get_ipv6ll_addrgen_mode(Link *link);
int ipv6ll_addrgen_mode_fill_message(sd_netlink_message *message, IPv6LinkLocalAddressGenMode mode);
int link_update_ipv6ll_addrgen_mode(Link *link, sd_netlink_message *message);

int link_set_ipv6ll_stable_secret(Link *link);
int link_set_ipv6ll_addrgen_mode(Link *link, IPv6LinkLocalAddressGenMode mode);

const char* ipv6_link_local_address_gen_mode_to_string(IPv6LinkLocalAddressGenMode s) _const_;
IPv6LinkLocalAddressGenMode ipv6_link_local_address_gen_mode_from_string(const char *s) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_link_local_address_gen_mode);
