/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "conf-parser.h"
#include "in-addr-util.h"

typedef struct AddressLabel AddressLabel;

#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"

typedef struct Network Network;
typedef struct Link Link;
typedef struct NetworkConfigSection NetworkConfigSection;

struct AddressLabel {
        Network *network;
        NetworkConfigSection *section;

        unsigned char prefixlen;
        uint32_t label;

        union in_addr_union in_addr;

        LIST_FIELDS(AddressLabel, labels);
};

void address_label_free(AddressLabel *label);

DEFINE_NETWORK_SECTION_FUNCTIONS(AddressLabel, address_label_free);

int address_label_configure(AddressLabel *address, Link *link, link_netlink_message_handler_t callback, bool update);

CONFIG_PARSER_PROTOTYPE(config_parse_address_label);
CONFIG_PARSER_PROTOTYPE(config_parse_address_label_prefix);
