/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "devlink.h"

typedef struct DevlinkParam {
        Devlink meta;
        char *value;
} DevlinkParam;

DEFINE_DEVLINK_CAST(PARAM, DevlinkParam);

extern const DevlinkVTable devlink_param_vtable;
