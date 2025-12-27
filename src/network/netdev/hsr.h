/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/if_link.h>

#include "netdev.h"

typedef enum HsrProtocol {
        NETDEV_HSR_PROTOCOL_HSR = HSR_PROTOCOL_HSR,
        NETDEV_HSR_PROTOCOL_PRP = HSR_PROTOCOL_PRP,
        _NETDEV_HSR_PROTOCOL_MAX,
        _NETDEV_HSR_PROTOCOL_INVALID = -EINVAL,
} HsrProtocol;

typedef struct Hsr {
        NetDev meta;

        char **ports;
        HsrProtocol protocol;
        uint8_t supervision;
} Hsr;

DEFINE_NETDEV_CAST(HSR, Hsr);
extern const NetDevVTable hsr_vtable;

DECLARE_STRING_TABLE_LOOKUP_FROM_STRING(hsr_protocol, HsrProtocol);

CONFIG_PARSER_PROTOTYPE(config_parse_hsr_protocol);
