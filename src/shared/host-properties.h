/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "forward.h"

/* Properties of a system that resources may be restricted to, see xattr-match.h. Acquired lazily, i.e. only
 * once there's actually something to match against. */
typedef struct HostProperties {
        bool loaded;

        char *hostname;
        sd_id128_t machine_id;          /* SD_ID128_NULL if not initialized */
        char **machine_tags;

        /* From os-release */
        char *os_id;
        char *os_version_id;
        char *image_id;
        char *image_version;
} HostProperties;

#define HOST_PROPERTIES_NULL (HostProperties) {}

void host_properties_done(HostProperties *h);

/* Loads the properties from the specified root directory (or the host if NULL), unless already loaded. */
int host_properties_load(HostProperties *h, const char *root);
