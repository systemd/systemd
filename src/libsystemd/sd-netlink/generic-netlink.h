/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#include "netlink-internal.h"

typedef enum GenlFamily {
        /* These three are not actually families */
        GENL_FAMILY_ERROR,
        GENL_FAMILY_DONE,
        GENL_FAMILY_ID_CTRL,

        /* These ones are actual families */
        GENL_FAMILY_WIREGUARD,
        GENL_FAMILY_FOU,
        GENL_FAMILY_L2TP,
        GENL_FAMILY_MACSEC,
        GENL_FAMILY_NL80211,

        _GENL_FAMILY_MAX,
        _GENL_FAMILY_INVALID = -EINVAL,
} GenlFamily;

int nlmsg_type_to_genl_family(const sd_netlink *nl, uint16_t type, GenlFamily *ret);

const char *genl_family_to_string(GenlFamily f) _const_;
GenlFamily genl_family_from_string(const char *s) _pure_;
