/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef struct VmspawnQmpBridge VmspawnQmpBridge;
typedef struct VmspawnSuspendHandler VmspawnSuspendHandler;

/* Pauses the VM while the host is suspending, so the guest's monotonic clock doesn't
 * jump on resume (which would trip per-service WatchdogSec deadlines). Takes a
 * non-owning ref to `bridge`; logind subscriptions go on `system_bus`. */
int vmspawn_suspend_handler_new(
                sd_bus *system_bus,
                VmspawnQmpBridge *bridge,
                VmspawnSuspendHandler **ret);

VmspawnSuspendHandler* vmspawn_suspend_handler_free(VmspawnSuspendHandler *h);
DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnSuspendHandler*, vmspawn_suspend_handler_free);
