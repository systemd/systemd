/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"
#include "sd-device.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "blockdev-list.h"
#include "blockdev-util.h"
#include "device-util.h"
#include "env-util.h"
#include "event-util.h"
#include "format-util.h"
#include "glyph-util.h"
#include "log.h"
#include "path-util.h"
#include "string-util.h"
#include "sysinstall-auto-device.h"
#include "time-util.h"

/* Keep in sync with the filter set io.systemd.Repart.ListCandidateDevices applies (see
 * src/repart/repart-list-candidate-devices.c), which is what the interactive device prompt is populated
 * from, so that the automatic pick never picks a device the prompt wouldn't offer. On top of that we
 * ignore devices without a medium (i.e. of zero size) – a drive without a disk in it is not something we
 * can install to, and should not be counted as a candidate. BLOCKDEV_LIST_METADATA is only there so the
 * log messages can mention vendor/model. Loopback devices are ignored on top of that (unless the
 * $SYSTEMD_SYSINSTALL_PERMIT_AUTO_TARGET_LOOP env var says otherwise, see auto_device_list_flags()). */
#define AUTO_DEVICE_LIST_FLAGS                          \
        (BLOCKDEV_LIST_REQUIRE_PARTITION_SCANNING |     \
         BLOCKDEV_LIST_IGNORE_ZRAM |                    \
         BLOCKDEV_LIST_IGNORE_READ_ONLY |               \
         BLOCKDEV_LIST_IGNORE_ROOT |                    \
         BLOCKDEV_LIST_IGNORE_EMPTY |                   \
         BLOCKDEV_LIST_DISKSEQ |                        \
         BLOCKDEV_LIST_METADATA)

/* How often to log about the remaining time while waiting for the device list to settle */
#define COUNTDOWN_INTERVAL_USEC (5 * USEC_PER_SEC)

typedef struct AutoDeviceContext {
        sd_event *event;
        sd_device_monitor *monitor;
        sd_event_source *settle_timer;
        sd_event_source *countdown_timer;
        char *candidate;             /* Device node of the single candidate seen so far, or NULL if none */
        uint64_t candidate_diskseq;  /* Diskseq of the device */
        dev_t root_devno, whole_root_devno;
        usec_t settle_timeout;
        BlockDevListFlags flags;
} AutoDeviceContext;

static BlockDevListFlags auto_device_list_flags(void) {
        int r;

        /* A loopback device is hardly ever the disk an unattended installation is supposed to end up on,
         * but it's what tests use as stand-in for a real disk. Hence ignore loopback devices by default,
         * but allow explicitly permitting them via an environment variable. */
        r = secure_getenv_bool("SYSTEMD_SYSINSTALL_PERMIT_AUTO_TARGET_LOOP");
        if (r < 0 && r != -ENXIO)
                log_warning_errno(r, "Failed to parse $SYSTEMD_SYSINSTALL_PERMIT_AUTO_TARGET_LOOP, ignoring: %m");

        return AUTO_DEVICE_LIST_FLAGS | (r > 0 ? 0 : BLOCKDEV_LIST_IGNORE_LOOP);
}

static void auto_device_context_done(AutoDeviceContext *c) {
        assert(c);

        c->settle_timer = sd_event_source_disable_unref(c->settle_timer);
        c->countdown_timer = sd_event_source_disable_unref(c->countdown_timer);
        c->monitor = sd_device_monitor_unref(c->monitor);
        c->event = sd_event_unref(c->event);
        c->candidate = mfree(c->candidate);
}

static int auto_device_on_settle(sd_event_source *s, uint64_t usec, void *userdata) {
        AutoDeviceContext *c = ASSERT_PTR(userdata);

        /* The candidate list has been stable for the settle timeout. If we have exactly one candidate at
         * this point, it's the one. (Two candidates can never be pending here, since auto_device_add()
         * terminates the event loop the moment a second one shows up.) */

        if (!c->candidate) {
                log_error("No suitable block device showed up within %s, cannot continue.",
                          FORMAT_TIMESPAN(c->settle_timeout, 0));
                return sd_event_exit(c->event, -ENODEV);
        }

        return sd_event_exit(c->event, 0);
}

static int auto_device_on_countdown(sd_event_source *s, uint64_t usec, void *userdata) {
        AutoDeviceContext *c = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(c->settle_timer);

        /* Logs how much time is left until the settle timer fires, and reschedules itself, unless the
         * settle timer fires before the next message would be due anyway. */

        usec_t deadline;
        r = sd_event_source_get_time(c->settle_timer, &deadline);
        if (r < 0)
                return log_error_errno(r, "Failed to query settle timer: %m");

        usec_t n;
        r = sd_event_now(c->event, CLOCK_MONOTONIC, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to query event loop time: %m");

        usec_t remaining = usec_sub_unsigned(deadline, n);
        if (remaining <= COUNTDOWN_INTERVAL_USEC) /* The settle timer fires soon enough anyway */
                return 0;

        log_info("Still waiting for the list of candidate devices to settle, %s left.",
                 FORMAT_TIMESPAN(remaining, USEC_PER_SEC));

        r = sd_event_source_set_time_relative(s, COUNTDOWN_INTERVAL_USEC);
        if (r < 0)
                return log_error_errno(r, "Failed to re-arm countdown timer: %m");

        r = sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
        if (r < 0)
                return log_error_errno(r, "Failed to enable countdown timer: %m");

        return 0;
}

static int auto_device_arm_countdown(AutoDeviceContext *c) {
        int r;

        assert(c);

        /* Schedules the first countdown message, unless the settle timer fires before that anyway. (The
         * subsequent messages are scheduled by auto_device_on_countdown() itself.) */

        if (c->settle_timeout <= COUNTDOWN_INTERVAL_USEC) {
                (void) event_source_disable(c->countdown_timer);
                return 0;
        }

        r = event_reset_time_relative(
                        c->event,
                        &c->countdown_timer,
                        CLOCK_MONOTONIC,
                        COUNTDOWN_INTERVAL_USEC,
                        /* accuracy= */ 0,
                        auto_device_on_countdown,
                        c,
                        SD_EVENT_PRIORITY_NORMAL + 1,
                        "sysinstall-countdown-timer",
                        /* force_reset= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to arm countdown timer: %m");

        return 0;
}

static int auto_device_arm_timer(AutoDeviceContext *c) {
        int r;

        assert(c);

        /* (Re)starts the settle clock. Use a priority below the device monitor's, so that uevents that are
         * already queued are always dispatched before the timer fires. */

        bool initial = !c->settle_timer;

        r = event_reset_time_relative(
                        c->event,
                        &c->settle_timer,
                        CLOCK_MONOTONIC,
                        c->settle_timeout,
                        /* accuracy= */ 0,
                        auto_device_on_settle,
                        c,
                        SD_EVENT_PRIORITY_NORMAL + 1,
                        "sysinstall-settle-timer",
                        /* force_reset= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to arm settle timer: %m");

        /* Log the wait at INFO only when we start waiting; re-arms happen once per change to the candidate
         * set, and are already accompanied by a message about that change. */
        log_full(initial ? LOG_INFO : LOG_DEBUG,
                 "Waiting %s for the list of candidate devices to settle...",
                 FORMAT_TIMESPAN(c->settle_timeout, 0));

        return auto_device_arm_countdown(c);
}

static int auto_device_get_node(AutoDeviceContext *c, char **ret) {
        assert(c);
        assert(c->candidate);
        assert(ret);

        /* Return a by-diskseq path for the disk, if we have it */

        if (c->candidate_diskseq != UINT64_MAX) {
                if (asprintf(ret, "/dev/disk/by-diskseq/%" PRIu64, c->candidate_diskseq) < 0)
                        return log_oom();

                return 0;
        }

        if (strdup_to(ret, c->candidate) < 0)
                return log_oom();

        return 0;
}

static int auto_device_add(AutoDeviceContext *c, const BlockDevice *d) {
        int r;

        assert(c);
        assert(d);
        assert(d->node);

        if (c->candidate) {
                if (!path_equal(c->candidate, d->node)) {
                        log_error("Multiple candidate block devices found (%s, %s), refusing to pick one "
                                  "automatically. Please specify the target device explicitly.",
                                  c->candidate, d->node);
                        return sd_event_exit(c->event, -ENOTUNIQ);
                }

                /* Already known, e.g. a "change" uevent for our candidate */
                if (c->candidate_diskseq == d->diskseq)
                        return 0; /* no change */

                /* Same node, but a different diskseq: the medium behind the node is not the one we saw
                 * before (e.g. medium swapped, or a "remove" uevent got lost). We are going to be
                 * destructive on this device, hence don't silently switch the target, but treat this like a
                 * new candidate: announce it below and restart the settle clock. */
                log_info("Medium of candidate device %s changed (diskseq %" PRIu64 " %s %" PRIu64 ").",
                         c->candidate, c->candidate_diskseq, glyph(GLYPH_ARROW_RIGHT), d->diskseq);
        } else {
                c->candidate = strdup(d->node);
                if (!c->candidate)
                        return log_oom();
        }

        c->candidate_diskseq = d->diskseq;

        _cleanup_free_ char *description = NULL;
        if (!isempty(d->vendor) && !strextend_with_separator(&description, " ", d->vendor))
                return log_oom();
        if (!isempty(d->model) && !strextend_with_separator(&description, " ", d->model))
                return log_oom();
        if (d->size != UINT64_MAX && !strextend_with_separator(&description, ", ", FORMAT_BYTES(d->size)))
                return log_oom();

        _cleanup_free_ char *n = NULL;
        r = auto_device_get_node(c, &n);
        if (r < 0)
                return r;

        log_info("Found candidate device %s%s%s%s.",
                 n,
                 description ? " (" : "", strempty(description), description ? ")" : "");

        return 1; /* positive change */
}

static int auto_device_remove(AutoDeviceContext *c, sd_device *dev) {
        int r;

        assert(c);
        assert(dev);

        if (!c->candidate)
                return 0; /* no change */

        const char *node;
        r = sd_device_get_devname(dev, &node);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to acquire device node of block device: %m");

        if (!path_equal(c->candidate, node))
                return 0; /* no change */

        log_info("Candidate device %s disappeared.", node);
        c->candidate = mfree(c->candidate);
        c->candidate_diskseq = UINT64_MAX;

        return 1; /* negative change */
}

static int auto_device_on_uevent(sd_device_monitor *monitor, sd_device *dev, void *userdata) {
        AutoDeviceContext *c = ASSERT_PTR(userdata);
        int r;

        assert(dev);

        /* Note that any failure returned from this callback terminates the event loop (and hence the
         * automatic pick) with that error, see the sd_event_source_set_exit_on_failure() call in
         * sysinstall_auto_pick_block_device(). We must never continue with uevent processing disabled: the
         * settle timer would keep ticking and commit to the current candidate, while a second disk showing
         * up – i.e. the very thing that must make us refuse – would go unnoticed. */

        sd_device_action_t action;
        r = sd_device_get_action(dev, &action);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to acquire uevent action of block device: %m");

        if (action == SD_DEVICE_REMOVE)
                r = auto_device_remove(c, dev);
        else {
                /* All non-REMOVE actions mean "device exists afterwards". Re-run the full filter set, the
                 * tri-state distinguishes "never interesting" from "was/is a candidate, but currently
                 * fails a dynamic filter (e.g. medium ejected, read-only flipped on)". */
                _cleanup_(block_device_done) BlockDevice d = BLOCK_DEVICE_NULL;
                r = blockdev_list_one(dev, c->flags, c->root_devno, c->whole_root_devno, &d);
                if (r < 0)
                        return r;

                switch (r) {

                case BLOCKDEV_LIST_MATCH_NO:
                case BLOCKDEV_LIST_MATCH_SKIPPED:
                case BLOCKDEV_LIST_MATCH_FILTERED:
                        r = auto_device_remove(c, dev);
                        break;

                case BLOCKDEV_LIST_MATCH_YES:
                        r = auto_device_add(c, &d);
                        break;

                default:
                        assert_not_reached();
                }
        }
        if (r <= 0)
                return r;

        /* Restart the timer if auto_device_add()/auto_device_remove() indicated a relevant change by
         * returning > 0. */
        return auto_device_arm_timer(c);
}

int sysinstall_auto_pick_block_device(usec_t settle_timeout, char **ret_node) {
        int r;

        assert(ret_node);

        /* Watches the block device tree until it has been quiet for 'settle_timeout' (measured from
         * invocation or from the last block device uevent, whichever is later), and then returns the one
         * candidate device present. Fails immediately if more than one candidate is ever present, and
         * fails after the timeout if none is. */

        _cleanup_(auto_device_context_done) AutoDeviceContext c = {
                .settle_timeout = settle_timeout,
                .candidate_diskseq = UINT64_MAX,
                .flags = auto_device_list_flags(),
        };

        r = sd_event_new(&c.event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        /* Make SIGINT/SIGTERM terminate the loop cleanly, with an error code we recognize below */
        r = sd_event_add_signal(c.event, /* ret= */ NULL, SIGINT|SD_EVENT_SIGNAL_PROCMASK,
                                /* callback= */ NULL, INT_TO_PTR(-ECANCELED));
        if (r < 0)
                return log_error_errno(r, "Failed to add SIGINT handler: %m");
        r = sd_event_add_signal(c.event, /* ret= */ NULL, SIGTERM|SD_EVENT_SIGNAL_PROCMASK,
                                /* callback= */ NULL, INT_TO_PTR(-ECANCELED));
        if (r < 0)
                return log_error_errno(r, "Failed to add SIGTERM handler: %m");

        /* Determine the disk the running system is booted from, so that we never pick it as installation
         * target. In the interactive flow a failure to determine it merely changes which devices a human is
         * offered, but here it decides what may be erased unattended, hence refuse operation if the booted
         * disk cannot be determined (e.g. NFS or multi-device root file systems). */
        r = blockdev_get_root(LOG_ERR, &c.root_devno);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV),
                                       "Unable to determine the disk the running system is booted from, "
                                       "cannot reliably exclude it from the candidate set, refusing.");

        r = block_get_whole_disk(c.root_devno, &c.whole_root_devno);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whole disk of the root block device: %m");

        /* Start the monitor *before* the initial enumeration so we don't lose events that fire during the
         * enumeration window. Seeing the same device twice is harmless, auto_device_add() is idempotent. */
        r = sd_device_monitor_new(&c.monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate block device monitor: %m");

        (void) sd_device_monitor_set_description(c.monitor, "sysinstall-auto-device");

        r = sd_device_monitor_filter_add_match_subsystem_devtype(c.monitor, "block", /* devtype= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to configure block device monitor filter: %m");

        r = sd_device_monitor_attach_event(c.monitor, c.event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach block device monitor to event loop: %m");

        r = sd_device_monitor_start(c.monitor, auto_device_on_uevent, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to start block device monitor: %m");

        /* By default sd-event just disables an event source whose callback fails. That would leave us
         * running blind: the settle timer would keep going and eventually commit to whatever candidate we
         * had, while further devices – in particular a second candidate – could no longer be observed.
         * Hence make any failure in the uevent callback terminate the event loop (and thus the automatic
         * pick) instead. */
        r = sd_event_source_set_exit_on_failure(sd_device_monitor_get_event_source(c.monitor), true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable exit-on-failure for block device monitor: %m");

        BlockDevice *l = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(l, n, block_device_array_free);

        r = blockdev_list_full(c.flags, c.root_devno, c.whole_root_devno, &l, &n);
        if (r < 0)
                return r;

        FOREACH_ARRAY(d, l, n) {
                r = auto_device_add(&c, d);
                if (r < 0)
                        return r;
        }

        /* The settle clock starts ticking now, regardless of whether we found something already */
        r = auto_device_arm_timer(&c);
        if (r < 0)
                return r;

        /* Tell the service manager (if any) that we are now watching for devices, so that whoever runs us
         * knows it's safe to plug in the target disk now. */
        (void) sd_notify(/* unset_environment= */ false, "READY=1");

        r = sd_event_loop(c.event);
        if (r == -ECANCELED)
                return log_error_errno(r, "Installation cancelled.");
        if (r < 0)
                return r; /* Already logged about */

        r = auto_device_get_node(&c, ret_node);
        if (r < 0)
                return r;

        log_info("Selected '%s' as installation target.", *ret_node);

        return 0;
}
