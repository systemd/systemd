/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Hsr Hsr;

#include "netdev.h"

#include <linux/if_link.h>

typedef enum HsrProtocol {
        NETDEV_HSR_PROTOCOL_HSR = HSR_PROTOCOL_HSR,
        NETDEV_HSR_PROTOCOL_PRP = HSR_PROTOCOL_PRP,
        _NETDEV_HSR_PROTOCOL_MAX,
        _NETDEV_HSR_PROTOCOL_INVALID = -EINVAL,
} HsrProtocol;

struct Hsr {
        NetDev meta;

        char **ports;
        HsrProtocol protocol;
        uint8_t supervision;
};

DEFINE_NETDEV_CAST(HSR, Hsr);
extern const NetDevVTable hsr_vtable;

HsrProtocol hsr_protocol_from_string(const char *d) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_hsr_protocol);
