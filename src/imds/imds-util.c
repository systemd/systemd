/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>

#include "imds-util.h"
#include "string-table.h"
#include "string-util.h"
#include "utf8.h"

static const char* imds_well_known_table[_IMDS_WELL_KNOWN_MAX] = {
        [IMDS_BASE]            = "base",
        [IMDS_HOSTNAME]        = "hostname",
        [IMDS_REGION]          = "region",
        [IMDS_ZONE]            = "zone",
        [IMDS_IPV4_PUBLIC]     = "ipv4-public",
        [IMDS_IPV6_PUBLIC]     = "ipv6-public",
        [IMDS_USERDATA]        = "userdata",
        [IMDS_USERDATA_BASE]   = "userdata-base",
        [IMDS_USERDATA_BASE64] = "userdata-base64",
};

DEFINE_STRING_TABLE_LOOKUP(imds_well_known, ImdsWellKnown);

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
