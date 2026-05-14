/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef struct VmspawnQmpBridge VmspawnQmpBridge;

/* Spawns a fiber that pauses the VM while the host is suspending, so the guest's monotonic
 * clock doesn't jump on resume (which would trip per-service WatchdogSec deadlines). Takes
 * a non-owning ref to `bridge`; logind subscriptions go on `system_bus`. The caller must
 * pass a non-NULL system_bus that has already been attached to an event loop via
 * sd_bus_attach_event(). The fiber is floating — owned by the event loop, torn down when
 * the loop exits. */
int vmspawn_suspend_handler_new(
                sd_bus *system_bus,
                VmspawnQmpBridge *bridge);
