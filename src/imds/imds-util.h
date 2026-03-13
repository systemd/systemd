/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"
#include "string-table.h" /* IWYU pragma: keep */

typedef enum ImdsNetworkMode {
        IMDS_NETWORK_OFF,                /* No automatic pre-IMDS network configuration, something else has to do this. (Also: no "prohibit" route) */
        IMDS_NETWORK_LOCKED,             /* "Prohibit" route for the IMDS server, unless you have SO_MARK set to 0x7FFF0815 */
        IMDS_NETWORK_UNLOCKED,           /* No "prohibit" route for the IMDS server */
        _IMDS_NETWORK_MODE_MAX,
        _IMDS_NETWORK_MODE_INVALID = -EINVAL,
} ImdsNetworkMode;

/* Various well-known keys */
typedef enum ImdsWellKnown {
        IMDS_BASE,            /* The same as "/", typically suffixed */
        IMDS_HOSTNAME,
        IMDS_REGION,
        IMDS_ZONE,
        IMDS_IPV4_PUBLIC,
        IMDS_IPV6_PUBLIC,
        IMDS_SSH_KEY,
        IMDS_USERDATA,
        IMDS_USERDATA_BASE,   /* typically suffixed */
        IMDS_USERDATA_BASE64,
        _IMDS_WELL_KNOWN_MAX,
        _IMDS_WELL_KNOWN_INVALID = -EINVAL,
} ImdsWellKnown;

static inline bool imds_well_known_can_suffix(ImdsWellKnown wk) {
        return IN_SET(wk, IMDS_BASE, IMDS_USERDATA_BASE);
}

bool imds_key_is_valid(const char *key);

DECLARE_STRING_TABLE_LOOKUP(imds_well_known, ImdsWellKnown);
DECLARE_STRING_TABLE_LOOKUP(imds_network_mode, ImdsNetworkMode);
