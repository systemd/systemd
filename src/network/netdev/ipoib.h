/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "conf-parser.h"
#include "netdev.h"

typedef enum IPoIBMode {
        IP_OVER_INFINIBAND_MODE_DATAGRAM,
        IP_OVER_INFINIBAND_MODE_CONNECTED,
        _IP_OVER_INFINIBAND_MODE_MAX,
        _IP_OVER_INFINIBAND_MODE_INVALID = -EINVAL,
} IPoIBMode;

typedef struct IPoIB {
        NetDev meta;

        uint16_t pkey;
        IPoIBMode mode;
        int umcast;
} IPoIB;

DEFINE_NETDEV_CAST(IPOIB, IPoIB);
extern const NetDevVTable ipoib_vtable;

int ipoib_set_netlink_message(Link *link, sd_netlink_message *m);

CONFIG_PARSER_PROTOTYPE(config_parse_ipoib_pkey);
CONFIG_PARSER_PROTOTYPE(config_parse_ipoib_mode);
