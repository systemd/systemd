/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "devlink.h"

typedef struct DevlinkReload {
        Devlink meta;
        sd_event_source *timeout_event_source;
} DevlinkReload;

DEFINE_DEVLINK_CAST(RELOAD, DevlinkReload);

extern const DevlinkVTable devlink_reload_vtable;

int devlink_reload_queue(Manager *m, DevlinkMatch *match);
