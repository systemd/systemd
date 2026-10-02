/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "vmspawn-qmp.h"

/* Guest memory state of the VM, in guest-total bytes. */
struct VmspawnMemory {
        VmspawnQmpBridge *bridge;       /* weak: bridge owns us */
        uint64_t configured;            /* boot RAM as handed to QEMU */
        uint64_t target;                /* last requested size */
        uint64_t actual;                /* last reported size, 0 = not yet known */
        bool balloon;                   /* virtio-balloon device present */
};

VmspawnMemory* vmspawn_memory_free(VmspawnMemory *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnMemory*, vmspawn_memory_free);

/* Allocate the per-VM memory state on the bridge and query the balloon size. */
int vmspawn_memory_setup(VmspawnQmpBridge *bridge, uint64_t configured, bool balloon);

/* Issue query-balloon and update ->actual. */
int vmspawn_memory_refresh(VmspawnMemory *m);

/* Consumes BALLOON_CHANGE, ignores every other event. Returns 1 if consumed, negative if malformed. */
int vmspawn_memory_dispatch_event(VmspawnMemory *m, const char *event, sd_json_variant *data);
