/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "in-addr-util.h"
#include "list.h"

typedef struct IPAddressAccessItem IPAddressAccessItem;

struct IPAddressAccessItem {
        int family;
        unsigned char prefixlen;
        union in_addr_union address;
        LIST_FIELDS(IPAddressAccessItem, items);
};

CONFIG_PARSER_PROTOTYPE(config_parse_ip_address_access);

IPAddressAccessItem *ip_address_access_free_all(IPAddressAccessItem *first);

IPAddressAccessItem *ip_address_access_reduce(IPAddressAccessItem *first);
