/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2009 Canonical Ltd.
 * Copyright © 2009 Scott James Remnant <scott@netsplit.com>
 */

#include <sys/signalfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "daemon-util.h"
#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "inotify-util.h"
#include "parse-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "set.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "time-util.h"
#include "udev-manager.h"
#include "udev-trace.h"
#include "udev-util.h"
#include "udev-watch.h"
#include "udev-worker.h"

static int udev_watch_clear_by_wd(sd_device *dev, int dirfd, int wd);

static int device_new_from_watch_handle_at(sd_device **ret, int dirfd, int wd) {
        char path_wd[STRLEN("/run/udev/watch/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *id = NULL;
        int r;

        assert(ret);

        if (wd < 0)
                return -EBADF;

        if (dirfd >= 0) {
                xsprintf(path_wd, "%d", wd);
                r = readlinkat_malloc(dirfd, path_wd, &id);
        } else {
                xsprintf(path_wd, "/run/udev/watch/%d", wd);
                r = readlink_malloc(path_wd, &id);
        }
        if (r < 0)
                return r;

        return sd_device_new_from_device_id(ret, id);
}

void udev_watch_dump(void) {
        int r;

        _cleanup_closedir_ DIR *dir = opendir("/run/udev/watch/");
        if (!dir)
                return (void) log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                             "Failed to open old watches directory '/run/udev/watch/': %m");

        _cleanup_set_free_ Set *pending_wds = NULL, *verified_wds = NULL;
        FOREACH_DIRENT(de, dir, break) {
                if (safe_atoi(de->d_name, NULL) >= 0) {
                        /* This should be wd -> ID symlink */

                        if (set_contains(verified_wds, de->d_name))
                                continue;

                        r = set_put_strdup(&pending_wds, de->d_name);
                        if (r < 0)
                                log_warning_errno(r, "Failed to store pending watch handle %s, ignoring: %m", de->d_name);
                        continue;
                }

                _cleanup_free_ char *wd = NULL;
                r = readlinkat_malloc(dirfd(dir), de->d_name, &wd);
                if (r < 0) {
                        log_warning_errno(r, "Found broken inotify watch, failed to read symlink %s, ignoring: %m", de->d_name);
                        continue;
                }

                const char *devnode = NULL;
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                if (sd_device_new_from_device_id(&dev, de->d_name) >= 0)
                        (void) sd_device_get_devname(dev, &devnode);

                _cleanup_free_ char *id = NULL;
                r = readlinkat_malloc(dirfd(dir), wd, &id);
                if (r < 0) {
                        log_warning_errno(r, "Found broken inotify watch %s on %s (%s), failed to read symlink %s, ignoring: %m",
                                          wd, strna(devnode), de->d_name, wd);
                        continue;
                }

                if (!streq(de->d_name, id)) {
                        log_warning("Found broken inotify watch %s on %s (%s), broken symlink chain: %s → %s → %s",
                                    wd, strna(devnode), de->d_name, de->d_name, wd, id);
                        continue;
                }

                log_debug("Found inotify watch %s on %s (%s).", wd, strna(devnode), de->d_name);

                free(set_remove(pending_wds, wd));

                r = set_ensure_put(&verified_wds, &string_hash_ops_free, wd);
                if (r < 0) {
                        log_warning_errno(r, "Failed to store verified watch handle %s, ignoring: %m", wd);
                        continue;
                }
                TAKE_PTR(wd);
        }

        const char *w;
        SET_FOREACH(w, pending_wds) {
                _cleanup_free_ char *id = NULL;
                r = readlinkat_malloc(dirfd(dir), w, &id);
                if (r < 0) {
                        log_warning_errno(r, "Found broken inotify watch %s, failed to read symlink %s, ignoring: %m", w, w);
                        continue;
                }

                const char *devnode = NULL;
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                if (sd_device_new_from_device_id(&dev, id) >= 0)
                        (void) sd_device_get_devname(dev, &devnode);

                _cleanup_free_ char *wd = NULL;
                (void) readlinkat_malloc(dirfd(dir), id, &wd);

                log_warning("Found broken inotify watch %s on %s (%s), broken symlink chain: %s → %s → %s",
                            wd, strna(devnode), id, w, id, wd);
        }
}

static int synthesize_change_one(sd_device *dev, sd_device *target) {
        int r;

        assert(dev);
        assert(target);

        if (DEBUG_LOGGING) {
                const char *syspath = NULL;
                (void) sd_device_get_syspath(target, &syspath);
                log_device_debug(dev, "device is closed, synthesising 'change' on %s", strna(syspath));
        }

        r = sd_device_trigger(target, SD_DEVICE_CHANGE);
        if (r < 0)
                return log_device_debug_errno(target, r, "Failed to trigger 'change' uevent: %m");

        DEVICE_TRACE_POINT(synthetic_change_event, dev);

        return 0;
}

static int synthesize_change_all(sd_device *dev, sd_device_enumerator *enumerator) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert(dev);

        if (!enumerator) {
                r = partition_enumerator_new(dev, &e);
                if (r < 0) {
                        log_device_debug_errno(dev, r, "Failed to enumerate partitions, ignoring: %m");
                        return synthesize_change_one(dev, dev);
                }

                enumerator = e;
        }

        r = synthesize_change_one(dev, dev);
        FOREACH_DEVICE(enumerator, d)
                RET_GATHER(r, synthesize_change_one(dev, d));

        return r;
}

#if HAVE_BLKID
typedef struct Partition {
        char *node;
        unsigned nr;
        uint64_t start;
        uint64_t size;
        char *uuid;
} Partition;

static Partition* partition_free(Partition *p) {
        if (!p)
                return NULL;

        free(p->node);
        free(p->uuid);
        return mfree(p);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Partition*, partition_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                partition_hash_ops,
                char, path_hash_func, path_compare,
                Partition, partition_free);

static int partition_add(sd_device *dev, blkid_partition pp, Hashmap **partitions) {
        int r;

        assert(dev);
        assert(pp);
        assert(partitions);

        errno = 0;
        int nr = sym_blkid_partition_get_partno(pp);
        if (nr < 0)
                return errno_or_else(EIO);

        const char *whole_devname;
        r = sd_device_get_devname(dev, &whole_devname);
        if (r < 0)
                return r;

        size_t l = strlen(whole_devname);
        if (l <= 0)
                return -EINVAL;
        bool need_p = ascii_isdigit(whole_devname[l - 1]);

        _cleanup_free_ char *node = NULL;
        if (asprintf(&node, "%s%s%i", whole_devname, need_p ? "p" : "", nr) < 0)
                return -ENOMEM;

        errno = 0;
        blkid_loff_t start = sym_blkid_partition_get_start(pp);
        if (start < 0)
                return errno_or_else(EIO);
        assert((uint64_t) start < UINT64_MAX / 512);

        errno = 0;
        blkid_loff_t size = sym_blkid_partition_get_size(pp);
        if (size < 0)
                return errno_or_else(EIO);
        assert((uint64_t) size < UINT64_MAX / 512);

        /* Use string to support both GPT and DOS. Fortunately, the blkid and kernel uses the same format.
         * GPT: standard UUID xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
         * DOS: 4 byte disk signature and 1 byte partition xxxxxxxx-xx */
        _cleanup_free_ char *uuid = NULL;
        r = strdup_to(&uuid, sym_blkid_partition_get_uuid(pp));
        if (r < 0)
                return r;

        _cleanup_(partition_freep) Partition *p = new(Partition, 1);
        if (!p)
                return -ENOMEM;

        *p = (Partition) {
                .node = TAKE_PTR(node),
                .nr = nr,
                .start = start,
                .size = size,
                .uuid = TAKE_PTR(uuid),
        };

        r = hashmap_ensure_put(partitions, &partition_hash_ops, p->node, p);
        if (r < 0)
                return r;

        TAKE_PTR(p);
        return 0;
}

static int enumerate_partitions_by_blkid(sd_device *dev, Hashmap **ret) {
        int r;

        assert(dev);
        assert(ret);

        _cleanup_close_ int fd = sd_device_open(dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return fd;

        if (flock(fd, LOCK_EX|LOCK_NB) < 0)
                /* The device may be currently locked? If so, let's try again after short delay. */
                return -errno;

        r = dlopen_libblkid();
        if (r < 0)
                return r;

        _cleanup_(blkid_free_probep) blkid_probe b = sym_blkid_new_probe();
        if (!b)
                return -ENOMEM;

        errno = 0;
        r = sym_blkid_probe_set_device(b, fd, /* off= */ 0, /* size= */ 0);
        if (r != 0)
                return errno_or_else(ENOMEM);

        sym_blkid_probe_enable_partitions(b, /* enable= */ true);
        sym_blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = sym_blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return errno_or_else(EIO);
        if (r != _BLKID_SAFEPROBE_FOUND) {
                if (r == _BLKID_SAFEPROBE_AMBIGUOUS)
                        log_device_debug(dev, "Found broken partition table, assuming no valid partition exists.");
                else if (r == _BLKID_SAFEPROBE_NOT_FOUND)
                        log_device_debug(dev, "Could not find partition table, assuming no valid partition exists.");
                else
                        log_device_debug(dev, "Unknown blkid_do_safeprobe() result %i, assuming no valid partition exists.", r);

                *ret = NULL;
                return 0;
        }

        errno = 0;
        blkid_partlist pl = sym_blkid_probe_get_partitions(b);
        if (!pl) {
                if (errno > 0)
                        return -errno;

                /* Maybe the whole disk is used as a filesystem or crypt device. Anyway, no valid partition
                 * should exist.*/
                log_device_debug(dev, "No partition found on the disk.");

                *ret = NULL;
                return 0;
        }

        errno = 0;
        int n_partitions = sym_blkid_partlist_numof_partitions(pl);
        if (n_partitions < 0)
                return errno_or_else(EIO);

        _cleanup_hashmap_free_ Hashmap *partitions = NULL;
        for (int i = 0; i < n_partitions; i++) {
                blkid_partition pp;

                errno = 0;
                pp = sym_blkid_partlist_get_partition(pl, i);
                if (!pp)
                        return errno_or_else(EIO);

                r = partition_add(dev, pp, &partitions);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(partitions);
        return 0;
}

static int partitions_synced(sd_device *dev) {
        int r;

        assert(dev);

        /* This returns 0 when partitions in sysfs are not synced, 1 when synced, negative errno on failure. */

        /* Enumerate partitions by blkid. Note, unfortunately(?) we need to enumerate partitions in each
         * trial. Otherwise, if the partition table is modified again soon after we received inotify event,
         * the check will always fail and we cannot leave the event loop until the timeout. */
        _cleanup_hashmap_free_ Hashmap *partitions = NULL;
        r = enumerate_partitions_by_blkid(dev, &partitions);
        if (r < 0)
                return r;

        /* Enumerate partitions by sysfs. */
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        r = partition_enumerator_new(dev, &e);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                const char *node;
                r = sd_device_get_devname(d, &node);
                if (r < 0)
                        return r;

                _cleanup_(partition_freep) Partition *p = hashmap_remove(partitions, node);
                if (!p) {
                        log_device_debug(dev, "Partition '%s' found in sysfs was not found by blkid.", node);
                        return 0;
                }

                uint64_t start;
                r = device_get_sysattr_u64(d, "start", &start);
                if (r < 0)
                        return r;

                if (p->start != start) {
                        log_device_debug(dev, "Partition offset of '%s' does not match: blkid=%"PRIu64", sysfs=%"PRIu64,
                                         node, p->start, start);
                        return 0;
                }

                uint64_t size;
                r = device_get_sysattr_u64(d, "size", &size);
                if (r < 0)
                        return r;

                if (p->size != size) {
                        log_device_debug(dev, "Partition size of '%s' does not match: blkid=%"PRIu64", sysfs=%"PRIu64,
                                         node, p->size, size);
                        return 0;
                }

                /* PARTUUID is since 758737d86f8a2d74c0fa9f8b2523fa7fd1e0d0aa (v6.13) */
                const char *uuid = NULL;
                r = sd_device_get_property_value(d, "PARTUUID", &uuid);
                if (r < 0 && r != -ENOENT)
                        return r;

                if (uuid && !streq_ptr(p->uuid, uuid)) {
                        log_device_debug(dev, "Partition UUID of '%s' does not match: blkid=%s, sysfs=%s",
                                         node, p->uuid, uuid);
                        return 0;
                }
        }

        if (!hashmap_isempty(partitions)) {
                Partition *p = hashmap_first(partitions);
                log_device_debug(dev, "Partition '%s' found by blkid was not found in sysfs.", p->node);
                return 0;
        }

        if (partitions)
                log_device_debug(dev, "All partitions found by blkid are available in sysfs, triggering 'change' events without requesting the kernel to reread partition table.");
        else
                log_device_debug(dev, "No partition found in blkid or sysfs, triggering 'change' event for the disk without requesting the kernel to reread partition table.");

        (void) synthesize_change_all(dev, e);
        return 1; /* synced and sent change events */
}

#define WAIT_SYNCED_DEFAULT_TIMEOUT_USEC (30 * USEC_PER_SEC)
#define WAIT_SYNCED_INITIAL_DELAY_USEC   (100 * USEC_PER_MSEC)

static usec_t sync_partition_timeout_usec(void) {
        static usec_t saved = WAIT_SYNCED_DEFAULT_TIMEOUT_USEC;
        static bool parsed = false;
        int r;

        if (parsed)
                return saved;

        parsed = true;

        const char *e = getenv("SYSTEMD_UDEV_SYNC_PARTITION_TIMEOUT_SEC");
        if (!e)
                return saved;

        usec_t timeout;
        r = parse_sec(e, &timeout);
        if (r < 0)
                log_debug_errno(r, "Failed to parse $SYSTEMD_UDEV_SYNC_PARTITION_TIMEOUT_SEC=%s, ignoring: %m", e);

        if (timeout > 5 * USEC_PER_HOUR) /* Add an arbitrary upper bound for safety */
                log_debug("Parsed $SYSTEMD_UDEV_SYNC_PARTITION_TIMEOUT_SEC=%s is too large, ignoring.", e);
        else
                saved = timeout;

        return saved;
}

typedef struct SyncDeviceContext {
        sd_device *dev;
        sd_event *event;
        sd_event_source *timer;
        usec_t delay;
} SyncDeviceContext;

static void sync_device_context_done(SyncDeviceContext *c) {
        assert(c);

        sd_device_unref(c->dev);
        sd_event_unref(c->event);
        sd_event_source_unref(c->timer);
}

static int on_watch_timer(sd_event_source *s, uint64_t usec, void *userdata);

static int context_check_partitions_synced(SyncDeviceContext *c) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(c)->dev);
        int r;

        r = partitions_synced(dev);
        if (r == -EBUSY) {
                log_device_debug(dev, "The device is currently locked, trying to check if partitions are synced again after a short delay.");

                r = event_reset_time_relative(
                                c->event, &c->timer, CLOCK_MONOTONIC, c->delay, /* accuracy = */ 0,
                                on_watch_timer, c, SD_EVENT_PRIORITY_NORMAL,
                                "watch-timer", /* force_reset = */ false);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to reset timer: %m");

                /* Let's exponentially increase the delay, to make not torture the disk. */
                c->delay *= 2;
                return 0;
        }
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to check if partitions are synced: %m");
        if (r == 0)
                /* We have enumerated partitions by both sysfs and blkid, and they are not synced.
                 * Let's check again later when we receive an event for one of the device.
                 * Here, we reset the delay, as we know the whole block device is not locked. */
                c->delay = WAIT_SYNCED_INITIAL_DELAY_USEC;

        return r;
}

static int context_on_event(SyncDeviceContext *c) {
        int r;

        assert(c);

        r = context_check_partitions_synced(c);
        if (r != 0)
                return sd_event_exit(c->event, r);

        return 0;
}

static int on_watch_monitor(sd_device_monitor *monitor, sd_device *dev, void *userdata) {
        return context_on_event(userdata);
}

static int on_watch_timer(sd_event_source *s, uint64_t usec, void *userdata) {
        return context_on_event(userdata);
}

static int wait_for_partitions_synced(sd_device *dev) {
        int r;

        assert(dev);

        _cleanup_(sync_device_context_done) SyncDeviceContext c = {
                .dev = sd_device_ref(dev),
                .delay = WAIT_SYNCED_INITIAL_DELAY_USEC,
        };

        r = sd_event_new(&c.event);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to allocate event loop: %m");

        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        r = device_monitor_new_full(&monitor, MONITOR_GROUP_KERNEL, -EBADF);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to allocate device monitor: %m");

        /* Only monitor the whole block device and its children (i.e. partitions). */
        r = sd_device_monitor_filter_add_match_parent(monitor, dev, /* match = */ true);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to add device monitor filter: %m");

        r = sd_device_monitor_attach_event(monitor, c.event);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to attach event to device monitor: %m");

        r = sd_device_monitor_start(monitor, on_watch_monitor, &c);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to start device monitor: %m");

        r = sd_event_add_time_relative(c.event, NULL, CLOCK_MONOTONIC, sync_partition_timeout_usec(),
                                       /* accuracy = */ 0, /* callback = */ NULL, INT_TO_PTR(-ETIMEDOUT));
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to add timer event source: %m");

        /* Let's check if partitions are already synced before entering the event loop. If synced, it is not
         * necessary to enter the loop.*/
        r = context_check_partitions_synced(&c);
        if (r != 0)
                return r;

        r = sd_event_loop(c.event);
        if (r == -ETIMEDOUT)
                return log_device_debug_errno(dev, r,
                                              "Partitions in sysfs are not synced in %s, requesting the kernel to reread partition table.",
                                              FORMAT_TIMESPAN(sync_partition_timeout_usec(), USEC_PER_SEC));
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to run event loop: %m");

        return 0; /* synced and sent change events */
}
#endif

static void synthesize_change_synced(sd_device *dev) {
        int r;

        assert(dev);

#if HAVE_BLKID
        if (wait_for_partitions_synced(dev) >= 0)
                return;

        /* Fall back to requesting the kernel to reread partition table on any errors. */
#endif

        /* If this succeeds, the kernel should sent out a "change" event for the disk, and "remove/add" for
         * all partitions. Hence, it is not necessary to trigger synthetic events by us. */
        r = blockdev_reread_partition_table(dev);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to request the kernel to reread partition table: %m");

                /* On any errors, as a fallback, let's enumerate pertitions and send change events to the
                 * whole block device and its partitions. */
                (void) synthesize_change_all(dev, /* enumerator = */ NULL);
        }
}

static int synthesize_change_child_handler(sd_event_source *s, const siginfo_t *si, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        assert(s);

        sd_event_source_unref(set_remove(manager->synthesize_change_child_event_sources, s));
        return 0;
}

static int synthesize_change(Manager *manager, sd_device *dev) {
        int r;

        assert(manager);
        assert(dev);

        r = device_sysname_startswith(dev, "dm-");
        if (r < 0)
                return r;
        if (r > 0)
                return synthesize_change_one(dev, dev);

        r = block_device_is_whole_disk(dev);
        if (r < 0)
                return r;
        if (r == 0)
                return synthesize_change_one(dev, dev);

#if HAVE_BLKID
        /* For caching timeout in the manager process, hence the forked process can use it. */
        sync_partition_timeout_usec();
#endif

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork(
                        "(udev-synth)",
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REOPEN_LOG|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE,
                        &pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                /* child */
                synthesize_change_synced(dev);
                _exit(EXIT_SUCCESS);
        }

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = event_add_child_pidref(manager->event, &s, &pidref, WEXITED, synthesize_change_child_handler, manager);
        if (r < 0) {
                log_debug_errno(r, "Failed to add child event source for "PID_FMT", ignoring: %m", pidref.pid);
                return 0;
        }

        r = sd_event_source_set_child_pidfd_own(s, true);
        if (r < 0)
                return r;
        TAKE_PIDREF(pidref);

        r = set_ensure_put(&manager->synthesize_change_child_event_sources, &event_source_hash_ops, s);
        if (r < 0)
                return r;
        TAKE_PTR(s);

        return 0;
}

static int manager_process_inotify(Manager *manager, const struct inotify_event *e) {
        int r;

        assert(manager);
        assert(e);

        if (FLAGS_SET(e->mask, IN_IGNORED)) {
                log_debug("Received inotify event about removal of watch handle %i.", e->wd);

                r = udev_watch_clear_by_wd(/* dev = */ NULL, /* dirfd = */ -EBADF, e->wd);
                if (r < 0)
                        log_warning_errno(r, "Failed to remove saved symlink(s) for watch handle %i, ignoring: %m", e->wd);

                return 0;
        }

        if (!FLAGS_SET(e->mask, IN_CLOSE_WRITE))
                return 0;

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = device_new_from_watch_handle_at(&dev, -EBADF, e->wd);
        if (r < 0) /* Device may be removed just after closed. */
                return log_debug_errno(r, "Failed to create sd_device object from watch handle, ignoring: %m");

        log_device_debug(dev, "Received inotify event of watch handle %i.", e->wd);

        (void) manager_requeue_locked_events_by_device(manager, dev);
        (void) synthesize_change(manager, dev);
        return 0;
}

static int on_inotify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        assert(fd >= 0);

        union inotify_event_buffer buffer;
        ssize_t l = read(fd, &buffer, sizeof(buffer));
        if (l < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return log_error_errno(errno, "Failed to read inotify fd: %m");
        }

        FOREACH_INOTIFY_EVENT_WARN(e, buffer, l)
                (void) manager_process_inotify(manager, e);

        return 0;
}

static int udev_watch_restore(Manager *manager) {
        _cleanup_(rm_rf_safep) const char *old = "/run/udev/watch.old/";
        int r;

        /* Move any old watches directory out of the way, and then restore the watches. */

        assert(manager);

        rm_rf_safe(old);
        if (rename("/run/udev/watch/", old) < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to move watches directory '/run/udev/watch/': %m");
        }

        _cleanup_closedir_ DIR *dir = opendir(old);
        if (!dir)
                return log_warning_errno(errno, "Failed to open old watches directory '%s': %m", old);

        FOREACH_DIRENT(de, dir, break) {

                /* For backward compatibility, read symlink from watch handle to device ID. This is necessary
                 * when udevd is restarted after upgrading from v248 or older. The new format (ID -> wd) was
                 * introduced by e7f781e473f5119bf9246208a6de9f6b76a39c5d (v249). */

                int wd;
                if (safe_atoi(de->d_name, &wd) < 0)
                        continue; /* This should be ID -> wd symlink. Skipping. */

                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                r = device_new_from_watch_handle_at(&dev, dirfd(dir), wd);
                if (r < 0) {
                        log_full_errno(ERRNO_IS_NEG_DEVICE_ABSENT(r) ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to create sd_device object from saved watch handle '%i', ignoring: %m",
                                       wd);
                        continue;
                }

                (void) manager_add_watch(manager, dev);
        }

        return 0;
}

int manager_init_inotify(Manager *manager, int fd) {
        int r;

        assert(manager);

        /* This takes passed file descriptor on success. */

        if (fd >= 0) {
                if (manager->inotify_fd >= 0)
                        return log_warning_errno(SYNTHETIC_ERRNO(EALREADY), "Received multiple inotify fd (%i), ignoring.", fd);

                log_debug("Received inotify fd (%i) from service manager.", fd);
                manager->inotify_fd = fd;
                return 0;
        }

        if (manager->inotify_fd >= 0)
                return 0;

        fd = inotify_init1(IN_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to create inotify descriptor: %m");

        log_debug("Initialized new inotify instance, restoring inotify watches of previous invocation.");
        manager->inotify_fd = fd;
        (void) udev_watch_restore(manager);

        r = notify_push_fd(manager->inotify_fd, "inotify");
        if (r < 0)
                log_warning_errno(r, "Failed to push inotify fd to service manager, ignoring: %m");
        else
                log_debug("Pushed inotify fd to service manager.");

        return 0;
}

int manager_start_inotify(Manager *manager) {
        int r;

        assert(manager);
        assert(manager->event);

        r = manager_init_inotify(manager, -EBADF);
        if (r < 0)
                return r;

        udev_watch_dump();

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(manager->event, &s, manager->inotify_fd, EPOLLIN, on_inotify, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create inotify event source: %m");

        r = sd_event_source_set_priority(s, EVENT_PRIORITY_INOTIFY_WATCH);
        if (r < 0)
                return log_error_errno(r, "Failed to set priority to inotify event source: %m");

        (void) sd_event_source_set_description(s, "manager-inotify");

        manager->inotify_event = TAKE_PTR(s);
        return 0;
}

static int udev_watch_clear_by_wd(sd_device *dev, int dirfd, int wd) {
        int r;

        _cleanup_close_ int dirfd_close = -EBADF;
        if (dirfd < 0) {
                dirfd_close = RET_NERRNO(open("/run/udev/watch/", O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_RDONLY));
                if (dirfd_close < 0)
                        return log_device_debug_errno(dev, dirfd_close, "Failed to open %s: %m", "/run/udev/watch/");

                dirfd = dirfd_close;
        }

        char wd_str[DECIMAL_STR_MAX(int)];
        xsprintf(wd_str, "%d", wd);

        _cleanup_free_ char *id = NULL, *wd_alloc = NULL;
        r = readlinkat_malloc(dirfd, wd_str, &id);
        if (r == -ENOENT)
                return 0;
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to read '/run/udev/watch/%s': %m", wd_str);
                goto finalize;
        }

        r = readlinkat_malloc(dirfd, id, &wd_alloc);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to read '/run/udev/watch/%s': %m", id);
                goto finalize;
        }

        if (!streq(wd_str, wd_alloc)) {
                r = log_device_debug_errno(dev, SYNTHETIC_ERRNO(ESTALE), "Unmatching watch handle found: %s -> %s -> %s", wd_str, id, wd_alloc);
                goto finalize;
        }

        if (unlinkat(dirfd, id, 0) < 0 && errno != ENOENT)
                r = log_device_debug_errno(dev, errno, "Failed to remove '/run/udev/watch/%s': %m", id);

finalize:
        if (unlinkat(dirfd, wd_str, 0) < 0 && errno != ENOENT)
                RET_GATHER(r, log_device_debug_errno(dev, errno, "Failed to remove '/run/udev/watch/%s': %m", wd_str));

        return r;
}

static int udev_watch_clear(sd_device *dev, int dirfd, int *ret_wd) {
        _cleanup_free_ char *wd_str = NULL, *buf = NULL;
        const char *id;
        int wd = -1, r;

        assert(dev);
        assert(dirfd >= 0);

        r = sd_device_get_device_id(dev, &id);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device ID: %m");

        /* 1. read symlink ID -> wd */
        r = readlinkat_malloc(dirfd, id, &wd_str);
        if (r == -ENOENT) {
                if (ret_wd)
                        *ret_wd = -1;
                return 0;
        }
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to read symlink '/run/udev/watch/%s': %m", id);
                goto finalize;
        }

        r = safe_atoi(wd_str, &wd);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to parse watch handle from symlink '/run/udev/watch/%s': %m", id);
                goto finalize;
        }

        if (wd < 0) {
                r = log_device_debug_errno(dev, SYNTHETIC_ERRNO(EBADF), "Invalid watch handle %i.", wd);
                goto finalize;
        }

        /* 2. read symlink wd -> ID */
        r = readlinkat_malloc(dirfd, wd_str, &buf);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to read symlink '/run/udev/watch/%s': %m", wd_str);
                goto finalize;
        }

        /* 3. check if the symlink wd -> ID is owned by the device. */
        if (!streq(buf, id)) {
                r = log_device_debug_errno(dev, SYNTHETIC_ERRNO(ENOENT),
                                           "Symlink '/run/udev/watch/%s' is owned by another device '%s'.", wd_str, buf);
                goto finalize;
        }

        /* 4. remove symlink wd -> ID.
         * In the above, we already confirmed that the symlink is owned by us. Hence, no other workers remove
         * the symlink and cannot create a new symlink with the same filename but to a different ID. Hence,
         * the removal below is safe even the steps in this function are not atomic. */
        if (unlinkat(dirfd, wd_str, 0) < 0 && errno != ENOENT)
                log_device_debug_errno(dev, errno, "Failed to remove '/run/udev/watch/%s', ignoring: %m", wd_str);

        if (ret_wd)
                *ret_wd = wd;
        r = 1;

finalize:
        /* 5. remove symlink ID -> wd.
         * The file is always owned by the device. Hence, it is safe to remove it unconditionally. */
        if (unlinkat(dirfd, id, 0) < 0 && errno != ENOENT)
                log_device_debug_errno(dev, errno, "Failed to remove '/run/udev/watch/%s', ignoring: %m", id);

        return r;
}

int manager_add_watch(Manager *manager, sd_device *dev) {
        char wd_str[DECIMAL_STR_MAX(int)];
        _cleanup_close_ int dirfd = -EBADF;
        const char *devnode, *id;
        int wd, r;

        assert(manager);
        assert(dev);

        /* Ignore the request of watching the device node on remove event, as the device node specified by
         * DEVNAME= has already been removed, and may already be assigned to another device. Consider the
         * case e.g. a USB stick memory was unplugged and then another one is plugged. */
        if (device_for_action(dev, SD_DEVICE_REMOVE))
                return 0;

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device node: %m");

        r = sd_device_get_device_id(dev, &id);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device ID: %m");

        r = dirfd = open_mkdir("/run/udev/watch", O_CLOEXEC | O_RDONLY, 0755);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to create and open '/run/udev/watch/': %m");

        /* 1. Clear old symlinks */
        (void) udev_watch_clear(dev, dirfd, NULL);

        /* 2. Add inotify watch */
        log_device_debug(dev, "Adding watch on '%s'", devnode);
        wd = inotify_add_watch(manager->inotify_fd, devnode, IN_CLOSE_WRITE);
        if (wd < 0)
                return log_device_debug_errno(dev, errno, "Failed to watch device node '%s': %m", devnode);

        /* 3. Clear old symlinks by the newly acquired watch handle, for the case that the watch handle is reused. */
        (void) udev_watch_clear_by_wd(dev, dirfd, wd);

        xsprintf(wd_str, "%d", wd);

        /* 4. Create new symlinks */
        if (symlinkat(wd_str, dirfd, id) < 0) {
                r = log_device_debug_errno(dev, errno, "Failed to create symlink '/run/udev/watch/%s' to '%s': %m", id, wd_str);
                goto on_failure;
        }

        if (symlinkat(id, dirfd, wd_str) < 0) {
                /* Possibly, the watch handle is previously assigned to another device, and udev_watch_end()
                 * is not called for the device yet. */
                r = log_device_debug_errno(dev, errno, "Failed to create symlink '/run/udev/watch/%s' to '%s': %m", wd_str, id);
                goto on_failure;
        }

        return 0;

on_failure:
        (void) unlinkat(dirfd, id, 0);
        (void) inotify_rm_watch(manager->inotify_fd, wd);
        return r;
}

int manager_remove_watch(Manager *manager, sd_device *dev) {
        _cleanup_close_ int dirfd = -EBADF;
        int wd, r;

        assert(manager);
        assert(dev);

        dirfd = RET_NERRNO(open("/run/udev/watch", O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_RDONLY));
        if (dirfd == -ENOENT)
                return 0;
        if (dirfd < 0)
                return log_device_debug_errno(dev, dirfd, "Failed to open %s: %m", "/run/udev/watch/");

        /* First, clear symlinks. */
        r = udev_watch_clear(dev, dirfd, &wd);
        if (r <= 0)
                return r;

        /* Then, remove inotify watch. */
        log_device_debug(dev, "Removing watch handle %i.", wd);
        (void) inotify_rm_watch(manager->inotify_fd, wd);

        return 0;
}

static int on_sigusr1(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        UdevWorker *worker = ASSERT_PTR(userdata);

        if (!si_code_from_process(si->ssi_code)) {
                log_debug("Received SIGUSR1 with unexpected .si_code %i, ignoring.", si->ssi_code);
                return 0;
        }

        if ((pid_t) si->ssi_pid != worker->manager_pid) {
                log_debug("Received SIGUSR1 from unexpected process [%"PRIu32"], ignoring.", si->ssi_pid);
                return 0;
        }

        return sd_event_exit(sd_event_source_get_event(s), 0);
}

static int notify_and_wait_signal(UdevWorker *worker, sd_device *dev, const char *msg) {
        int r;

        assert(worker);
        assert(dev);
        assert(msg);

        if (sd_device_get_devname(dev, NULL) < 0)
                return 0;

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        r = sd_event_new(&e);
        if (r < 0)
                return r;

        r = sd_event_add_signal(e, /* ret = */ NULL, SIGUSR1 | SD_EVENT_SIGNAL_PROCMASK, on_sigusr1, worker);
        if (r < 0)
                return r;

        r = sd_notify(/* unset_environment = */ false, msg);
        if (r <= 0)
                return r;

        return sd_event_loop(e);
}

int udev_watch_begin(UdevWorker *worker, sd_device *dev) {
        assert(worker);
        assert(dev);

        if (device_for_action(dev, SD_DEVICE_REMOVE))
                return 0;

        return notify_and_wait_signal(worker, dev, "INOTIFY_WATCH_ADD=1");
}

int udev_watch_end(UdevWorker *worker, sd_device *dev) {
        assert(worker);
        assert(dev);

        return notify_and_wait_signal(worker, dev, "INOTIFY_WATCH_REMOVE=1");
}
