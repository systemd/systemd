/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>

#include "imds-util.h"
#include "string-table.h"
#include "string-util.h"
#include "utf8.h"

bool imds_key_is_valid(const char *key) {
        /* Just some pretty superficial validation. */

        if (!key)
                return false;

        if (!startswith(key, "/"))
                return false;

        if (!ascii_is_valid(key))
                return false;

        if (string_has_cc(key, /* ok= */ NULL))
                return false;

        return true;
}

static const char* const imds_well_known_table[_IMDS_WELL_KNOWN_MAX] = {
        [IMDS_BASE]            = "base",
        [IMDS_HOSTNAME]        = "hostname",
        [IMDS_REGION]          = "region",
        [IMDS_ZONE]            = "zone",
        [IMDS_IPV4_PUBLIC]     = "ipv4-public",
        [IMDS_IPV6_PUBLIC]     = "ipv6-public",
        [IMDS_SSH_KEY]         = "ssh-key",
        [IMDS_USERDATA]        = "userdata",
        [IMDS_USERDATA_BASE]   = "userdata-base",
        [IMDS_USERDATA_BASE64] = "userdata-base64",
};

DEFINE_STRING_TABLE_LOOKUP(imds_well_known, ImdsWellKnown);


static const char* const imds_network_mode_table[_IMDS_NETWORK_MODE_MAX] = {
        [IMDS_NETWORK_OFF]      = "off",
        [IMDS_NETWORK_LOCKED]   = "locked",
        [IMDS_NETWORK_UNLOCKED] = "unlocked",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(imds_network_mode, ImdsNetworkMode, IMDS_NETWORK_LOCKED);
