/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "cleanup-util.h"
#include "runtime-scope.h"

typedef struct VmspawnQmpContext VmspawnQmpContext;

int vmspawn_qmp_setup(VmspawnQmpContext **ret, int qmp_fd, sd_event *event, const char *runtime_dir, RuntimeScope runtime_scope, uid_t owner_uid, char **ret_control_address);
VmspawnQmpContext *vmspawn_qmp_context_free(VmspawnQmpContext *ctx);

DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnQmpContext *, vmspawn_qmp_context_free);
