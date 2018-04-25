/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Susant Sahani
***/

#include <inttypes.h>
#include <stdbool.h>

#include "in-addr-util.h"

typedef struct AddressLabel AddressLabel;

#include "networkd-link.h"
#include "networkd-network.h"

typedef struct Network Network;
typedef struct Link Link;
typedef struct NetworkConfigSection NetworkConfigSection;

struct AddressLabel {
        Network *network;
        Link *link;
        NetworkConfigSection *section;

        unsigned char prefixlen;
        uint32_t label;

        union in_addr_union in_addr;

        LIST_FIELDS(AddressLabel, labels);
};

int address_label_new(AddressLabel **ret);
void address_label_free(AddressLabel *label);

DEFINE_TRIVIAL_CLEANUP_FUNC(AddressLabel*, address_label_free);

int address_label_configure(AddressLabel *address, Link *link, sd_netlink_message_handler_t callback, bool update);

int config_parse_address_label(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_address_label_prefix(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
