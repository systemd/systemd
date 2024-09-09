/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Hsr Hsr;

#include "netdev.h"

typedef enum HsrSlave {
        NETDEV_HSR_SLAVE1,
        NETDEV_HSR_SLAVE2,
        _NETDEV_HSR_SLAVE_MAX,
        _NETDEV_HSR_SLAVE_INVALID = -EINVAL,
} HsrSlave;

typedef enum HsrProtocol {
        NETDEV_HSR_PROTOCOL_HSR = HSR_PROTOCOL_HSR,
        NETDEV_HSR_PROTOCOL_PRP = HSR_PROTOCOL_PRP,
        _NETDEV_HSR_PROTOCOL_MAX,
        _NETDEV_HSR_PROTOCOL_INVALID = -EINVAL,
} HsrProtocol;

struct Hsr {
        NetDev meta;

        char *slave_ifaces[_NETDEV_HSR_SLAVE_MAX];
        uint8_t multicast_spec;

        HsrProtocol protocol;
        uint8_t version;
};

DEFINE_NETDEV_CAST(HSR, Hsr);
extern const NetDevVTable hsr_vtable;

const char *hsr_protocol_to_string(HsrProtocol d) _const_;
HsrProtocol hsr_protocol_from_string(const char *d) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_hsr_protocol);
