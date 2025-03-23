/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2009 Canonical Ltd.
 * Copyright © 2009 Scott James Remnant <scott@netsplit.com>
 */

#include "alloc-util.h"
#include "blockdev-util.h"
#include "daemon-util.h"
#include "device-util.h"
#include "dirent-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "inotify-util.h"
#include "json-util.h"
#include "memfd-util.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "udev-manager.h"
#include "udev-trace.h"
#include "udev-util.h"
#include "udev-watch.h"

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

static int synthesize_change_all(sd_device *dev) {
        int r;

        assert(dev);

        r = blockdev_reread_partition_table(dev);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to re-read partition table, ignoring: %m");
        bool part_table_read = r >= 0;

        /* search for partitions */
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        r = partition_enumerator_new(dev, &e);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to initialize partition enumerator, ignoring: %m");

        /* We have partitions and re-read the table, the kernel already sent out a "change"
         * event for the disk, and "remove/add" for all partitions. */
        if (part_table_read && sd_device_enumerator_get_device_first(e))
                return 0;

        /* We have partitions but re-reading the partition table did not work, synthesize
         * "change" for the disk and all partitions. */
        r = synthesize_change_one(dev, dev);
        FOREACH_DEVICE(e, d)
                RET_GATHER(r, synthesize_change_one(dev, d));

        return r;
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

        const char *sysname;
        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return r;

        if (startswith(sysname, "dm-") || block_device_is_whole_disk(dev) <= 0)
                return synthesize_change_one(dev, dev);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork(
                        "(udev-synth)",
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE,
                        &pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                /* child */
                (void) synthesize_change_all(dev);
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

static int manager_save_watch_impl(Manager *manager, const char *id, int wd) {
        int r;

        assert(manager);
        assert(id);
        assert(wd >= 0);

        _cleanup_free_ char *copy = strdup(id);
        if (!copy)
                return -ENOMEM;

        r = hashmap_ensure_put(&manager->inotify_device_ids_by_watch_handle, &trivial_hash_ops_value_free, INT_TO_PTR(wd), copy);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&manager->inotify_watch_handles_by_device_id, &string_hash_ops, copy, INT_TO_PTR(wd));
        if (r < 0) {
                free(hashmap_remove(manager->inotify_device_ids_by_watch_handle, INT_TO_PTR(wd)));
                return r;
        }

        TAKE_PTR(copy);
        return 0;
}

int manager_save_watch(Manager *manager, sd_device *dev, const char *s) {
        int r;

        assert(manager);
        assert(dev);
        assert(s);

        int wd;
        r = safe_atoi(s, &wd);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to parse inotify watch '%s': %m", s);
        if (wd < 0)
                return log_device_warning_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                                "Received invalid inotify watch %i.", wd);

        const char *id;
        r = sd_device_get_device_id(dev, &id);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get device ID: %m");

        r = manager_save_watch_impl(manager, id, wd);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to save inotify watch %i: %m", wd);

        log_device_debug(dev, "Saved inotify watch %i.", wd);
        return 0;
}

int manager_remove_watch(Manager *manager, sd_device *dev) {
        int r;

        assert(manager);
        assert(dev);

        const char *id;
        r = sd_device_get_device_id(dev, &id);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get device id: %m");

        void *p = hashmap_remove(manager->inotify_watch_handles_by_device_id, id);
        if (!p)
                return 0;

        _cleanup_free_ char *saved_id = hashmap_remove(manager->inotify_device_ids_by_watch_handle, p);
        assert(streq(saved_id, id));

        int wd = PTR_TO_INT(p);
        (void) inotify_rm_watch(manager->inotify_fd, wd);

        log_device_debug(dev, "Removed inotify watch %i.", wd);
        return 0;
}

static int manager_process_inotify(Manager *manager, const struct inotify_event *e) {
        int r;

        assert(manager);
        assert(e);

        const char *id = hashmap_get(manager->inotify_device_ids_by_watch_handle, INT_TO_PTR(e->wd));
        if (!id)
                /* FIXME: This is racy. We may receive an inotify event before receiving the
                 * notification about the watch handle from the worker. */
                return log_debug_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "Received inotify event of unknown watch handle %i, ignoring.",
                                       e->wd);

        if (FLAGS_SET(e->mask, IN_IGNORED)) {
                const char *p = hashmap_remove(manager->inotify_watch_handles_by_device_id, id);
                assert(p && PTR_TO_INT(p) == e->wd);
                free(hashmap_remove(manager->inotify_device_ids_by_watch_handle, p));
                return 0;
        }

        if (!FLAGS_SET(e->mask, IN_CLOSE_WRITE))
                return 0;

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = sd_device_new_from_device_id(&dev, id);
        if (r < 0) /* Device may be removed just after closed. */
                return log_debug_errno(r, "Failed to create sd_device object from device ID '%s', ignoring: %m", id);

        log_device_debug(dev, "Received inotify event of watch handle %i.", e->wd);

        (void) event_queue_assume_block_device_unlocked(manager, dev);
        (void) synthesize_change(manager, dev);
        return 0;
}

static int manager_on_inotify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
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

static int manager_build_json(Manager *manager, sd_json_variant **ret) {
        int r;

        assert(manager);
        assert(ret);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        const char *id;
        const void *wd;
        HASHMAP_FOREACH_KEY(id, wd, manager->inotify_device_ids_by_watch_handle) {
                r = sd_json_variant_append_arraybo(
                                &w,
                                SD_JSON_BUILD_PAIR_STRING("id", id),
                                SD_JSON_BUILD_PAIR_INTEGER("handle", PTR_TO_INT(wd)));
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = sd_json_variant_set_field(&v, "inotifyWatch", w);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

int manager_serialize(Manager *manager) {
        int r;

        assert(manager);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = manager_build_json(manager, &v);
        if (r < 0)
                return log_error_errno(r, "Failed to serialize inotify watches: %m");

        /* If we are running as a service, then use the fd store. */
        r = notify_push_fd(manager->inotify_fd, "inotify");
        if (r < 0)
                return log_error_errno(r, "Failed to push inotify file descriptor: %m");
        if (r > 0) {
                /* Yay! The inotify fd is pushed. Let's also push the serialized json variant. */

                _cleanup_free_ char *dump = NULL;
                r = sd_json_variant_format(v, /* flags = */ 0, &dump);
                if (r < 0)
                        return log_error_errno(r, "Failed to format json variant: %m");

                _cleanup_close_ int fd = -EBADF;
                fd = memfd_new_and_seal_string("serialization", dump);
                if (fd < 0)
                        return log_debug_errno(fd, "Failed to create memfd: %m");

                r = notify_push_fd(fd, "manager-serialization");
                if (r < 0)
                        return log_error_errno(r, "Failed to push serialization file descriptor: %m");

        } else {
                /* It seems systemd-udevd is not running as a systemd service. */
                _cleanup_(unlink_and_freep) char *path = NULL;
                _cleanup_fclose_ FILE *f = NULL;
                r = fopen_tmpfile_linkable("/run/udev/serialization", O_WRONLY|O_CLOEXEC, &path, &f);
                if (r < 0)
                        return log_error_errno(r, "Failed to open temporary file: %m");

                r = sd_json_variant_dump(v, SD_JSON_FORMAT_NEWLINE | SD_JSON_FORMAT_FLUSH, f, /* prefix = */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to dump json variant: %m");

                if (rename(path, "/run/udev/serialization") < 0)
                        return log_error_errno(errno, "Failed to rename temporary file '%s': %m", path);

                path = mfree(path);
        }

        return 0;
}

static int manager_add_watch(Manager *manager, const char *id) {
        int r;

        assert(manager);
        assert(id);

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = sd_device_new_from_device_id(&dev, id);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r))
                return 0;
        if (r < 0)
                return log_warning_errno(r, "Could not find device from id '%s': %m", id);

        const char *node;
        r = sd_device_get_devname(dev, &node);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get device node: %m");

        int wd = inotify_add_watch(manager->inotify_fd, node, IN_CLOSE_WRITE);
        if (wd < 0) {
                if (errno == ENOENT)
                        return 0;
                return log_device_warning_errno(dev, errno, "Failed to add inotify watch on '%s': %m", node);
        }

        r = manager_save_watch_impl(manager, id, wd);
        if (r < 0) {
                log_device_warning_errno(dev, r, "Failed to save inotify watch %i on '%s': %m", wd, node);
                (void) inotify_rm_watch(manager->inotify_fd, wd);
                return r;
        }

        return 0;
}

static int manager_restore_watch(Manager *manager) {
        int r;

        assert(manager);

        _cleanup_closedir_ DIR *dir = opendir("/run/udev/watch/");
        if (!dir) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to open /run/udev/watch/: %m");
        }

        FOREACH_DIRENT(de, dir, break) {

                /* For backward compatibility, read symlink from watch handle to device ID. This is necessary
                 * when udevd is restarted after upgrading from v248 or older. The new format (ID -> wd) was
                 * introduced by e7f781e473f5119bf9246208a6de9f6b76a39c5d (v249). */

                if (safe_atoi(de->d_name, NULL) < 0)
                        continue; /* This should be ID -> wd symlink. Skipping. */

                _cleanup_free_ char *id = NULL;
                r = readlinkat_malloc(dirfd(dir), de->d_name, &id);
                if (r < 0) {
                        log_warning_errno(r, "Failed to read symlink /run/udev/watch/%s, ignoring: %m", de->d_name);
                        continue;
                }

                (void) manager_add_watch(manager, id);
        }

        return 0;
}

static int manager_dispatch_watch(Manager *manager, sd_json_variant *v, bool add) {
        int r;

        assert(manager);
        assert(v);

        struct {
                const char *id;
                int wd;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "id",     SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, voffsetof(p, id), SD_JSON_MANDATORY },
                { "handle", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int,          voffsetof(p, wd), SD_JSON_MANDATORY },
                {},
        };

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return log_warning_errno(r, "Failed to dispatch inotify watch from json variant: %m");

        if (p.wd < 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid watch handle %i.", p.wd);

        if (add)
                return manager_add_watch(manager, p.id);

        return manager_save_watch_impl(manager, p.id, p.wd);
}

static int manager_deserialize(Manager *manager, FILE *f, const char *path, bool add_watch) {
        int r;

        assert(manager);
        assert(path);

        unsigned err_line = 0, err_column = 0;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = sd_json_parse_file(
                        f,
                        path,
                        /* flags = */ 0,
                        &v,
                        /* ret_line = */ &err_line,
                        /* ret_column = */ &err_column);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_warning_errno(r, "Failed to parse %s (line=%u, column=%u): %m", path, err_line, err_column);

        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, sd_json_variant_by_key(v, "inotifyWatch"))
                RET_GATHER(r, manager_dispatch_watch(manager, i, add_watch));

        manager->deserialized = true;
        return r;
}

int manager_deserialize_fd(Manager *manager, int *fd) {
        assert(manager);
        assert(fd);
        assert(*fd >= 0);

        if (manager->deserialized)
                return log_warning_errno(SYNTHETIC_ERRNO(EALREADY), "Received multiple serialization fd (%i), ignoring.", *fd);

        _cleanup_fclose_ FILE *f = take_fdopen(fd, "r");
        if (!f)
                return log_debug_errno(errno, "Failed to fdopen() serialization file descriptor: %m");

        return manager_deserialize(manager, f, "(serialization-fd)", /* add_watch = */ false);
}

int manager_init_inotify(Manager *manager, int fd) {
        assert(manager);

        /* This takes passed file descriptor on success. */

        if (fd >= 0) {
                if (manager->inotify_fd >= 0)
                        return log_warning_errno(SYNTHETIC_ERRNO(EALREADY), "Received multiple inotify fd (%i), ignoring.", fd);
        } else {
                if (manager->inotify_fd >= 0)
                        return 0;

                fd = inotify_init1(IN_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to create inotify descriptor: %m");
        }

        manager->inotify_fd = fd;
        return 0;
}

int manager_start_inotify(Manager *manager) {
        int r;

        assert(manager);
        assert(manager->event);

        r = manager_init_inotify(manager, -EBADF);
        if (r < 0)
                return r;

        if (!manager->deserialized) {
                r = manager_deserialize(manager, /* f = */ NULL, "/run/udev/serialization", /* install = */ true);
                if (r < 0)
                        return r;
        }
        if (!manager->deserialized) {
                r = manager_restore_watch(manager);
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(manager->event, &s, manager->inotify_fd, EPOLLIN, manager_on_inotify, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create inotify event source: %m");

        (void) sd_event_source_set_description(s, "manager-inotify");

        manager->inotify_event = TAKE_PTR(s);
        return 0;
}

int udev_watch_begin(int inotify_fd, sd_device *dev) {
        int r;

        assert(inotify_fd >= 0);
        assert(dev);

        /* Ignore the request of watching the device node on remove event, as the device node specified by
         * DEVNAME= has already been removed, and may already be assigned to another device. Consider the
         * case e.g. a USB stick memory was unplugged and then another one is plugged. */
        if (device_for_action(dev, SD_DEVICE_REMOVE))
                return 0;

        const char *node;
        r = sd_device_get_devname(dev, &node);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to get device node: %m");

        /* 1. Create inotify watch on device node. */
        int wd = inotify_add_watch(inotify_fd, node, IN_CLOSE_WRITE);
        if (wd < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_device_warning_errno(dev, errno, "Failed to add inotify watch on '%s': %m", node);
        }

        /* 2. Send the inotify watch handle to the manager process. */
        r = sd_notifyf(/* unset_environment = */ false, "INOTIFY_WATCH_ADD=%i", wd);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to send INOTIFY_WATCH_ADD=%i to manager process: %m", wd);

        log_device_debug(dev, "Added inotify watch '%i' on '%s'.", wd, node);
        return 0;
}

int udev_watch_end(sd_device *dev) {
        int r;

        assert(dev);

        if (sd_device_get_devname(dev, NULL) < 0)
                return 0;

        r = sd_notifyf(/* unset_environment = */ false, "INOTIFY_WATCH_REMOVE=1");
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to send INOTIFY_REMOVE_WATCH_HANDLE=1 to manager process: %m");

        log_device_debug(dev, "Requested to remove inotify watch.");
        return 0;
}
