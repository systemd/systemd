/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cleanup-util.h"
#include "shared-forward.h"
#include "vmspawn-qmp.h"

typedef struct VmspawnVarlinkContext VmspawnVarlinkContext;

/* Varlink server for VM control on top of an established bridge connection */
int vmspawn_varlink_setup(
                VmspawnVarlinkContext **ret,
                VmspawnQmpBridge *bridge,
                const char *runtime_dir,
                char **ret_control_address);

VmspawnVarlinkContext* vmspawn_varlink_context_free(VmspawnVarlinkContext *ctx);

DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnVarlinkContext *, vmspawn_varlink_context_free);
