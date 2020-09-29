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
};

AddressLabel *address_label_free(AddressLabel *label);

DEFINE_NETWORK_SECTION_FUNCTIONS(AddressLabel, address_label_free);

void network_verify_address_labels(Network *network);

int link_set_address_labels(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_address_label);
CONFIG_PARSER_PROTOTYPE(config_parse_address_label_prefix);
