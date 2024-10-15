/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "conf-parser.h"
#include "in-addr-util.h"
#include "networkd-util.h"

typedef struct Link Link;
typedef struct Manager Manager;
typedef struct Network Network;

typedef struct AddressLabel {
        Manager *manager;
        Network *network;
        ConfigSection *section;

        uint32_t label;
        struct in6_addr prefix;
        unsigned char prefixlen;
        bool prefix_set;
} AddressLabel;

AddressLabel *address_label_free(AddressLabel *label);

void network_drop_invalid_address_labels(Network *network);
void manager_drop_invalid_address_labels(Manager *manager);

int link_request_static_address_labels(Link *link);
int manager_request_static_address_labels(Manager *manager);

typedef enum IPv6AddressLabelConfParserType {
        IPV6_ADDRESS_LABEL,
        IPV6_ADDRESS_LABEL_PREFIX,
        _IPV6_ADDRESS_LABEL_CONF_PARSER_MAX,
        _IPV6_ADDRESS_LABEL_CONF_PARSER_INVALID = -EINVAL,

        IPV6_ADDRESS_LABEL_BY_MANAGER           = 1 << 16,
        IPV6_ADDRESS_LABEL_SECTION_MASK         = IPV6_ADDRESS_LABEL_BY_MANAGER - 1,
} IPv6AddressLabelConfParserType;

assert_cc(IPV6_ADDRESS_LABEL_BY_MANAGER >= _IPV6_ADDRESS_LABEL_CONF_PARSER_MAX);

CONFIG_PARSER_PROTOTYPE(config_parse_ipv6_address_label_section);
