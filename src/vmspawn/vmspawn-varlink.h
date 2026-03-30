/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "cleanup-util.h"

typedef struct VmspawnVarlinkBridge VmspawnVarlinkBridge;
typedef struct VmspawnVarlinkContext VmspawnVarlinkContext;

VmspawnVarlinkBridge *vmspawn_varlink_bridge_free(VmspawnVarlinkBridge *b);
DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnVarlinkBridge *, vmspawn_varlink_bridge_free);

int vmspawn_varlink_setup(VmspawnVarlinkContext **ret, int qmp_fd, sd_event *event, const char *runtime_dir, char **ret_varlink_address);
VmspawnVarlinkContext *vmspawn_varlink_context_free(VmspawnVarlinkContext *ctx);

DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnVarlinkContext *, vmspawn_varlink_context_free);
