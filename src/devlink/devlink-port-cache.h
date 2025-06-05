/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "devlink.h"

typedef struct DevlinkPortCache {
        Devlink meta;
        uint64_t ifindex;
} DevlinkPortCache;

DEFINE_DEVLINK_CAST(PORT_CACHE, DevlinkPortCache);

extern const DevlinkVTable devlink_port_cache_vtable;

int devlink_port_cache_query_by_match(Manager *m, DevlinkMatch *match, uint64_t *ifindex);
int devlink_port_cache_query_by_ifindex(Manager *m, uint64_t ifindex, DevlinkKey *key);
