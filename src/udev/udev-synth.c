/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "device-util.h"
#include "event-util.h"
#include "format-util.h"
#include "id128-util.h"
#include "pidref.h"
#include "process-util.h"
#include "reread-partition-table.h"
#include "set.h"
#include "string-util.h"
#include "time-util.h"
#include "udev-manager.h"
#include "udev-synth.h"
#include "udev-trace.h"

static int on_synthesized_events_clear(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        for (;;) {
                _cleanup_free_ sd_id128_t *uuid = set_steal_first(manager->synthesized_events);
                if (!uuid)
                        return 0;

                log_warning("Could not receive synthesized event with UUID %s, ignoring.",
                            SD_ID128_TO_STRING(*uuid));
        }
}

static int synthesize_change_one(Manager *manager, sd_device *dev) {
        int r;

        assert(manager);
        assert(dev);

        if (DEBUG_LOGGING) {
                const char *syspath = NULL;
                (void) sd_device_get_syspath(dev, &syspath);
                log_device_debug(dev, "device is closed, synthesising 'change' on %s", strna(syspath));
        }

        sd_id128_t uuid;
        r = device_trigger_with_timestamp(dev, SD_DEVICE_CHANGE, manager->device_trigger_args, &uuid);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to trigger 'change' uevent: %m");

        DEVICE_TRACE_POINT(synthetic_change_event, dev);

        /* Avoid /run/udev/queue file being removed by on_post(). */
        sd_id128_t *copy = newdup(sd_id128_t, &uuid, 1);
        if (!copy)
                return log_oom_debug();

        /* Let's not wait for too many events, to make not udevd consume huge amount of memory.
         * Typically (but unfortunately, not always), the kernel provides events in the order we triggered.
         * Hence, remembering the newest UUID should be mostly enough. */
        while (set_size(manager->synthesized_events) >= 1024) {
                _cleanup_free_ sd_id128_t *id = ASSERT_PTR(set_steal_first(manager->synthesized_events));
                log_debug("Too many synthesized events are waiting, forgetting synthesized event with UUID %s.",
                          SD_ID128_TO_STRING(*id));
        }

        r = set_ensure_consume(&manager->synthesized_events, &id128_hash_ops_free, copy);
        if (r < 0)
                return log_oom_debug();

        r = event_reset_time_relative(
                        manager->event,
                        &manager->synthesized_events_clear_event_source,
                        CLOCK_MONOTONIC,
                        1 * USEC_PER_MINUTE,
                        USEC_PER_SEC,
                        on_synthesized_events_clear,
                        manager,
                        SD_EVENT_PRIORITY_NORMAL,
                        "synthesized-events-clear",
                        /* force_reset= */ true);
        if (r < 0)
                log_debug_errno(r, "Failed to reset timer event source for clearing synthesized event UUIDs: %m");

        return 0;
}

static int synthesize_change_child_handler(sd_event_source *s, const siginfo_t *si, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        assert(s);

        sd_event_source_unref(set_remove(manager->synthesize_change_child_event_sources, s));
        return 0;
}

int manager_synthesize_change(Manager *manager, sd_device *dev) {
        int r;

        assert(manager);
        assert(dev);

        r = device_sysname_startswith(dev, "dm-");
        if (r < 0)
                return r;
        if (r > 0)
                return synthesize_change_one(manager, dev);

        r = block_device_is_whole_disk(dev);
        if (r < 0)
                return r;
        if (r == 0)
                return synthesize_change_one(manager, dev);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork(
                        "(udev-synth)",
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_REOPEN_LOG,
                        &pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                /* child */
                (void) reread_partition_table(dev, REREADPT_FORCE_UEVENT|REREADPT_BSD_LOCK, manager->device_trigger_args);
                _exit(EXIT_SUCCESS);
        }

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = event_add_child_pidref(manager->event, &s, &pidref, WEXITED, synthesize_change_child_handler, manager);
        if (r < 0) {
                log_debug_errno(r, "Failed to add child event source for "PID_FMT", ignoring: %m", pidref.pid);
                return 0;
        }

        r = set_ensure_put(&manager->synthesize_change_child_event_sources, &event_source_hash_ops, s);
        if (r < 0)
                return r;
        TAKE_PTR(s);

        return 0;
}
