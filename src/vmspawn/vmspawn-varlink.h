/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cleanup-util.h"
#include "shared-forward.h"

typedef struct QmpClient QmpClient;
typedef struct VmspawnQmpBridge VmspawnQmpBridge;
typedef struct VmspawnVarlinkContext VmspawnVarlinkContext;

VmspawnQmpBridge *vmspawn_qmp_bridge_free(VmspawnQmpBridge *b);
DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnQmpBridge *, vmspawn_qmp_bridge_free);

QmpClient *vmspawn_qmp_bridge_get_qmp(VmspawnQmpBridge *b);

/* Phase 1: Connect to VMM backend. Returns an opaque bridge ready for device setup. */
int vmspawn_varlink_init(VmspawnQmpBridge **ret, int qmp_fd_consume, sd_event *event);

/* Phase 3: Resume vCPUs and switch async event processing. */
int vmspawn_varlink_start(VmspawnQmpBridge *bridge);

/* Varlink server for VM control on top of an established bridge connection */
int vmspawn_varlink_setup(VmspawnVarlinkContext **ret, VmspawnQmpBridge *bridge,
                      const char *runtime_dir, char **ret_control_address);

VmspawnVarlinkContext *vmspawn_varlink_context_free(VmspawnVarlinkContext *ctx);

DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnVarlinkContext *, vmspawn_varlink_context_free);
