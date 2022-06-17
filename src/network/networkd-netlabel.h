/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "set.h"

typedef struct Address Address;

int netlabels_dup(Address *address, Set *netlabels);

void address_add_netlabels(const Address *address);
void address_del_netlabels(const Address *address);

CONFIG_PARSER_PROTOTYPE(config_parse_netlabel);
