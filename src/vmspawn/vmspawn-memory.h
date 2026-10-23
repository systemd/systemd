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
        sd_varlink *progress_link;      /* SetMemory() call with 'more' waiting for convergence */
        sd_event_source *stall_timer;   /* ends progress_link once actual stopped moving */
        bool balloon;                   /* virtio-balloon device present */
};

VmspawnMemory* vmspawn_memory_free(VmspawnMemory *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(VmspawnMemory*, vmspawn_memory_free);

/* Allocate the per-VM memory state on the bridge and query the balloon size. */
int vmspawn_memory_setup(VmspawnQmpBridge *bridge, uint64_t configured, bool balloon);

/* Resize the guest memory to 'bytes', rounded up to 64 KiB, the largest guest page size. Without 'more', 'link'
 * gets the effective target and the current size once the VMM accepted the request. With 'more', it gets a
 * notification per change of the current size, and that final reply once the guest reached the target, moved
 * away from it, or did not move for 5s. A newer accepted request ends a still pending call with Superseded.
 * 'link' gets an error if the VMM rejects the request. */
int vmspawn_memory_set_target(VmspawnMemory *m, sd_varlink *link, bool more, uint64_t bytes);

/* End a pending SetMemory() call with NotConnected, as its size can no longer change. */
void vmspawn_memory_disconnect(VmspawnMemory *m);

/* Update ->actual from the payload of a BALLOON_CHANGE event. Returns negative if malformed. */
int vmspawn_memory_dispatch_balloon_change(VmspawnMemory *m, sd_json_variant *data);

/* Build the io.systemd.MachineInstance.Memory object. */
int vmspawn_memory_build_json(VmspawnMemory *m, sd_json_variant **ret);
