/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "conf-parser.h"
#include "in-addr-util.h"
#include "networkd-util.h"

typedef struct Network Network;
typedef struct Link Link;

typedef struct AddressLabel {
        Network *network;
        NetworkConfigSection *section;

        unsigned char prefixlen;
        uint32_t label;
        union in_addr_union in_addr;
} AddressLabel;

AddressLabel *address_label_free(AddressLabel *label);

void network_drop_invalid_address_labels(Network *network);

int link_set_address_labels(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_address_label);
CONFIG_PARSER_PROTOTYPE(config_parse_address_label_prefix);
