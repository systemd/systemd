/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "netdev.h"

typedef struct Vrf {
        NetDev meta;

        uint32_t table;
} Vrf;

DEFINE_NETDEV_CAST(VRF, Vrf);
extern const NetDevVTable vrf_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_vrf_table);
