/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "devlink.h"

typedef struct DevlinkNested {
        Devlink meta;
        Devlink *nested_in;
} DevlinkNested;

DEFINE_DEVLINK_CAST(NESTED, DevlinkNested);

extern const DevlinkVTable devlink_nested_vtable;

DevlinkMatch *devlink_nested_in_match(Manager *m, DevlinkMatch *match);
