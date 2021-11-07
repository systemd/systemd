/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "conf-parser.h"
#include "netdev.h"

typedef enum IPoIBConnectMode {
        IPOIB_CONNECT_MODE_DATAGRAM,
        IPOIB_CONNECT_MODE_CONNECTED,
        _IPOIB_CONNECT_MODE_MAX,
        _IPOIB_CONNECT_MODE_INVALID = -EINVAL,
} IPoIBConnectMode;

typedef struct IPoIB {
        NetDev meta;

        uint16_t pkey;
        IPoIBConnectMode mode;
        int umcast;
} IPoIB;

DEFINE_NETDEV_CAST(IPOIB, IPoIB);
extern const NetDevVTable ipoib_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_ipoib_pkey);
CONFIG_PARSER_PROTOTYPE(config_parse_ipoib_mode);
