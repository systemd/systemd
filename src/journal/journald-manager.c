/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/audit.h>
#include <linux/sockios.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-journal.h"
#include "sd-messages.h"
#include "sd-varlink.h"

#include "acl-util.h"
#include "alloc-util.h"
#include "audit-util.h"
#include "cgroup-util.h"
#include "conf-parser.h"
#include "creds-util.h"
#include "daemon-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "hostname-setup.h"
#include "initrd-util.h"
#include "iovec-util.h"
#include "journal-authenticate.h"
#include "journal-file-util.h"
#include "journal-internal.h"
#include "journal-vacuum.h"
#include "journald-audit.h"
#include "journald-config.h"
#include "journald-context.h"
#include "journald-kmsg.h"
#include "journald-manager.h"
#include "journald-native.h"
#include "journald-rate-limit.h"
#include "journald-socket.h"
#include "journald-stream.h"
#include "journald-sync.h"
#include "journald-syslog.h"
#include "journald-varlink.h"
#include "log.h"
#include "log-ratelimit.h"
#include "memory-util.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "prioq.h"
#include "process-util.h"
#include "rm-rf.h"
#include "set.h"
#include "signal-util.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "time-util.h"
#include "uid-classification.h"
#include "user-util.h"

#define USER_JOURNALS_MAX 1024

#define DEFAULT_KMSG_OWN_INTERVAL (5 * USEC_PER_SEC)
#define DEFAULT_KMSG_OWN_BURST 50

#define RECHECK_SPACE_USEC (30*USEC_PER_SEC)

#define NOTIFY_SNDBUF_SIZE (8*1024*1024)

/* The period to insert between posting changes for coalescing */
#define POST_CHANGE_TIMER_INTERVAL_USEC (250*USEC_PER_MSEC)

#define DEFERRED_CLOSES_MAX (4096)

#define IDLE_TIMEOUT_USEC (30*USEC_PER_SEC)

#define FAILED_TO_WRITE_ENTRY_RATELIMIT ((const RateLimit) { .interval = 1 * USEC_PER_SEC, .burst = 1 })

static int manager_schedule_sync(Manager *m, int priority);
static int manager_refresh_idle_timer(Manager *m);

static int manager_determine_path_usage(
                Manager *m,
                const char *path,
                uint64_t *ret_used,
                uint64_t *ret_free) {

        _cleanup_closedir_ DIR *d = NULL;
        struct statvfs ss;

        assert(m);
        assert(path);
        assert(ret_used);
        assert(ret_free);

        d = opendir(path);
        if (!d)
                return log_ratelimit_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR,
                                                errno, JOURNAL_LOG_RATELIMIT, "Failed to open %s: %m", path);

        if (fstatvfs(dirfd(d), &ss) < 0)
                return log_ratelimit_error_errno(errno, JOURNAL_LOG_RATELIMIT,
                                                 "Failed to fstatvfs(%s): %m", path);

        *ret_free = ss.f_bsize * ss.f_bavail;
        *ret_used = 0;
        FOREACH_DIRENT_ALL(de, d, break) {
                struct stat st;

                if (!endswith(de->d_name, ".journal") &&
                    !endswith(de->d_name, ".journal~"))
                        continue;

                if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                        log_debug_errno(errno, "Failed to stat %s/%s, ignoring: %m", path, de->d_name);
                        continue;
                }

                if (!S_ISREG(st.st_mode))
                        continue;

                *ret_used += (uint64_t) st.st_blocks * 512UL;
        }

        return 0;
}

static void cache_space_invalidate(JournalStorageSpace *space) {
        zero(*space);
}

static int cache_space_refresh(Manager *m, JournalStorage *storage) {
        JournalStorageSpace *space;
        JournalMetrics *metrics;
        uint64_t vfs_used, vfs_avail, avail;
        usec_t ts;
        int r;

        assert(m);
        assert(storage);

        metrics = &storage->metrics;
        space = &storage->space;

        ts = now(CLOCK_MONOTONIC);

        if (space->timestamp != 0 && usec_add(space->timestamp, RECHECK_SPACE_USEC) > ts)
                return 0;

        r = manager_determine_path_usage(m, storage->path, &vfs_used, &vfs_avail);
        if (r < 0)
                return r;

        space->vfs_used = vfs_used;
        space->vfs_available = vfs_avail;

        avail = LESS_BY(vfs_avail, metrics->keep_free);

        space->limit = CLAMP(vfs_used + avail, metrics->min_use, metrics->max_use);
        space->available = LESS_BY(space->limit, vfs_used);
        space->timestamp = ts;
        return 1;
}

static void patch_min_use(JournalStorage *storage) {
        assert(storage);

        /* Let's bump the min_use limit to the current usage on disk. We do
         * this when starting up and first opening the journal files. This way
         * sudden spikes in disk usage will not cause journald to vacuum files
         * without bounds. Note that this means that only a restart of journald
         * will make it reset this value. */

        storage->metrics.min_use = MAX(storage->metrics.min_use, storage->space.vfs_used);
}

static JournalStorage* manager_current_storage(Manager *m) {
        assert(m);

        return m->system_journal ? &m->system_storage : &m->runtime_storage;
}

static int manager_determine_space(Manager *m, uint64_t *available, uint64_t *limit) {
        JournalStorage *js;
        int r;

        assert(m);

        js = manager_current_storage(m);

        r = cache_space_refresh(m, js);
        if (r >= 0) {
                if (available)
                        *available = js->space.available;
                if (limit)
                        *limit = js->space.limit;
        }
        return r;
}

void manager_space_usage_message(Manager *m, JournalStorage *storage) {
        assert(m);

        if (!storage)
                storage = manager_current_storage(m);

        if (cache_space_refresh(m, storage) < 0)
                return;

        const JournalMetrics *metrics = &storage->metrics;

        manager_driver_message(m, 0,
                               LOG_MESSAGE_ID(SD_MESSAGE_JOURNAL_USAGE_STR),
                               LOG_MESSAGE("%s (%s) is %s, max %s, %s free.",
                                           storage->name, storage->path,
                                           FORMAT_BYTES(storage->space.vfs_used),
                                           FORMAT_BYTES(storage->space.limit),
                                           FORMAT_BYTES(storage->space.available)),
                               LOG_ITEM("JOURNAL_NAME=%s", storage->name),
                               LOG_ITEM("JOURNAL_PATH=%s", storage->path),
                               LOG_ITEM("CURRENT_USE=%"PRIu64, storage->space.vfs_used),
                               LOG_ITEM("CURRENT_USE_PRETTY=%s", FORMAT_BYTES(storage->space.vfs_used)),
                               LOG_ITEM("MAX_USE=%"PRIu64, metrics->max_use),
                               LOG_ITEM("MAX_USE_PRETTY=%s", FORMAT_BYTES(metrics->max_use)),
                               LOG_ITEM("DISK_KEEP_FREE=%"PRIu64, metrics->keep_free),
                               LOG_ITEM("DISK_KEEP_FREE_PRETTY=%s", FORMAT_BYTES(metrics->keep_free)),
                               LOG_ITEM("DISK_AVAILABLE=%"PRIu64, storage->space.vfs_available),
                               LOG_ITEM("DISK_AVAILABLE_PRETTY=%s", FORMAT_BYTES(storage->space.vfs_available)),
                               LOG_ITEM("LIMIT=%"PRIu64, storage->space.limit),
                               LOG_ITEM("LIMIT_PRETTY=%s", FORMAT_BYTES(storage->space.limit)),
                               LOG_ITEM("AVAILABLE=%"PRIu64, storage->space.available),
                               LOG_ITEM("AVAILABLE_PRETTY=%s", FORMAT_BYTES(storage->space.available)));
}

static void manager_add_acls(JournalFile *f, uid_t uid) {
        assert(f);

#if HAVE_ACL
        int r;

        if (uid_for_system_journal(uid))
                return;

        r = fd_add_uid_acl_permission(f->fd, uid, ACL_READ);
        if (r < 0)
                log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                            "Failed to set ACL on %s, ignoring: %m", f->path);
#endif
}

static JournalFileFlags manager_get_file_flags(Manager *m, bool seal) {
        assert(m);

        return (m->config.compress.enabled ? JOURNAL_COMPRESS : 0) |
                (seal ? JOURNAL_SEAL : 0) |
                JOURNAL_STRICT_ORDER;
}

static int manager_open_journal(
                Manager *m,
                bool reliably,
                const char *fname,
                int open_flags,
                bool seal,
                JournalMetrics *metrics,
                JournalFile **ret) {

        _cleanup_(journal_file_offline_closep) JournalFile *f = NULL;
        JournalFileFlags file_flags;
        int r;

        assert(m);
        assert(fname);
        assert(ret);

        file_flags = manager_get_file_flags(m, seal);

        set_clear(m->deferred_closes);

        if (reliably)
                r = journal_file_open_reliably(
                                fname,
                                open_flags,
                                file_flags,
                                0640,
                                m->config.compress.threshold_bytes,
                                metrics,
                                m->mmap,
                                &f);
        else
                r = journal_file_open(
                                /* fd= */ -EBADF,
                                fname,
                                open_flags,
                                file_flags,
                                0640,
                                m->config.compress.threshold_bytes,
                                metrics,
                                m->mmap,
                                /* template= */ NULL,
                                &f);
        if (r < 0)
                return r;

        r = journal_file_enable_post_change_timer(f, m->event, POST_CHANGE_TIMER_INTERVAL_USEC);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return r;
}

static bool manager_flushed_flag_is_set(Manager *m) {
        const char *fn;

        assert(m);

        /* We don't support the "flushing" concept for namespace instances, we assume them to always have
         * access to /var */
        if (m->namespace)
                return true;

        fn = strjoina(m->runtime_directory, "/flushed");
        return access(fn, F_OK) >= 0;
}

static void manager_drop_flushed_flag(Manager *m) {
        const char *fn;

        assert(m);

        if (m->namespace)
                return;

        fn = strjoina(m->runtime_directory, "/flushed");
        if (unlink(fn) < 0 && errno != ENOENT)
                log_ratelimit_warning_errno(errno, JOURNAL_LOG_RATELIMIT,
                                            "Failed to unlink %s, ignoring: %m", fn);
}

static int manager_system_journal_open(
                Manager *m,
                bool flush_requested,
                bool relinquish_requested) {

        const char *fn;
        int r = 0;

        if (!m->system_journal &&
            IN_SET(m->config.storage, STORAGE_PERSISTENT, STORAGE_AUTO) &&
            (flush_requested || manager_flushed_flag_is_set(m)) &&
            !relinquish_requested) {

                /* If in auto mode: first try to create the machine path, but not the prefix.
                 *
                 * If in persistent mode: create /var/log/journal and the machine path */

                if (m->config.storage == STORAGE_PERSISTENT)
                        (void) mkdir_parents(m->system_storage.path, 0755);

                (void) mkdir(m->system_storage.path, 0755);

                fn = strjoina(m->system_storage.path, "/system.journal");
                r = manager_open_journal(
                                m,
                                /* reliably= */ true,
                                fn,
                                O_RDWR|O_CREAT,
                                m->config.seal,
                                &m->system_storage.metrics,
                                &m->system_journal);
                if (r >= 0) {
                        manager_add_acls(m->system_journal, 0);
                        (void) cache_space_refresh(m, &m->system_storage);
                        patch_min_use(&m->system_storage);
                } else {
                        if (!IN_SET(r, -ENOENT, -EROFS))
                                log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                            "Failed to open system journal: %m");

                        r = 0;
                }

                /* If the runtime journal is open, and we're post-flush, we're recovering from a failed
                 * system journal rotate (ENOSPC) for which the runtime journal was reopened.
                 *
                 * Perform an implicit flush to var, leaving the runtime journal closed, now that the system
                 * journal is back.
                 */
                if (!flush_requested)
                        (void) manager_flush_to_var(m, true);
        }

        if (!m->runtime_journal &&
            (m->config.storage != STORAGE_NONE)) {

                fn = strjoina(m->runtime_storage.path, "/system.journal");

                if (!m->system_journal || relinquish_requested) {

                        /* OK, we really need the runtime journal, so create it if necessary. */

                        (void) mkdir_parents(m->runtime_storage.path, 0755);
                        (void) mkdir(m->runtime_storage.path, 0750);

                        r = manager_open_journal(
                                        m,
                                        /* reliably= */ true,
                                        fn,
                                        O_RDWR|O_CREAT,
                                        /* seal= */ false,
                                        &m->runtime_storage.metrics,
                                        &m->runtime_journal);
                        if (r < 0)
                                return log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                                   "Failed to open runtime journal: %m");

                } else if (!manager_flushed_flag_is_set(m)) {
                        /* Try to open the runtime journal, but only if it already exists, so that we can
                         * flush it into the system journal */

                        r = manager_open_journal(
                                        m,
                                        /* reliably= */ false,
                                        fn,
                                        O_RDWR,
                                        /* seal= */ false,
                                        &m->runtime_storage.metrics,
                                        &m->runtime_journal);
                        if (r < 0) {
                                if (r != -ENOENT)
                                        log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                                    "Failed to open runtime journal: %m");

                                r = 0;
                        }
                }

                if (m->runtime_journal) {
                        manager_add_acls(m->runtime_journal, 0);
                        (void) cache_space_refresh(m, &m->runtime_storage);
                        patch_min_use(&m->runtime_storage);
                        manager_drop_flushed_flag(m);
                }
        }

        return r;
}

static int manager_find_user_journal(Manager *m, uid_t uid, JournalFile **ret) {
        _cleanup_(journal_file_offline_closep) JournalFile *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(!uid_for_system_journal(uid));

        f = ordered_hashmap_get(m->user_journals, UID_TO_PTR(uid));
        if (f)
                goto found;

        if (asprintf(&p, "%s/user-" UID_FMT ".journal", m->system_storage.path, uid) < 0)
                return log_oom();

        /* Too many open? Then let's close one (or more) */
        while (ordered_hashmap_size(m->user_journals) >= USER_JOURNALS_MAX) {
                JournalFile *first;

                assert_se(first = ordered_hashmap_steal_first(m->user_journals));
                (void) journal_file_offline_close(first);
        }

        r = manager_open_journal(
                        m,
                        /* reliably= */ true,
                        p,
                        O_RDWR|O_CREAT,
                        m->config.seal,
                        &m->system_storage.metrics,
                        &f);
        if (r < 0)
                return r;

        r = ordered_hashmap_put(m->user_journals, UID_TO_PTR(uid), f);
        if (r < 0)
                return r;

        manager_add_acls(f, uid);

found:
        *ret = TAKE_PTR(f);
        return 0;
}

static JournalFile* manager_find_journal(Manager *m, uid_t uid) {
        int r;

        assert(m);

        /* A rotate that fails to create the new journal (ENOSPC) leaves the rotated journal as NULL.  Unless
         * we revisit opening, even after space is made available we'll continue to return NULL indefinitely.
         *
         * system_journal_open() is a noop if the journals are already open, so we can just call it here to
         * recover from failed rotates (or anything else that's left the journals as NULL).
         *
         * Fixes https://github.com/systemd/systemd/issues/3968 */
        (void) manager_system_journal_open(m, /* flush_requested= */ false, /* relinquish_requested= */ false);

        /* We split up user logs only on /var, not on /run. If the runtime file is open, we write to it
         * exclusively, in order to guarantee proper order as soon as we flush /run to /var and close the
         * runtime file. */

        if (m->runtime_journal)
                return m->runtime_journal;

        /* If we are not in persistent mode, then we need return NULL immediately rather than opening a
         * persistent journal of any sort.
         *
         * Fixes https://github.com/systemd/systemd/issues/20390 */
        if (!IN_SET(m->config.storage, STORAGE_AUTO, STORAGE_PERSISTENT))
                return NULL;

        if (!uid_for_system_journal(uid)) {
                JournalFile *f = NULL;

                r = manager_find_user_journal(m, uid, &f);
                if (r >= 0)
                        return ASSERT_PTR(f);

                log_warning_errno(r, "Failed to open user journal file, falling back to system journal: %m");
        }

        return m->system_journal;
}

static int manager_do_rotate(
                Manager *m,
                JournalFile **f,
                const char* name,
                bool seal,
                uint32_t uid) {

        int r;

        assert(f);
        assert(m);

        if (!*f)
                return -EINVAL;

        log_debug("Rotating journal file %s.", (*f)->path);

        r = journal_file_rotate(f, m->mmap, manager_get_file_flags(m, seal), m->config.compress.threshold_bytes, m->deferred_closes);
        if (r < 0) {
                if (*f)
                        return log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT,
                                                         "Failed to rotate %s: %m", (*f)->path);
                else
                        return log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT,
                                                         "Failed to create new %s journal: %m", name);
        }

        manager_add_acls(*f, uid);
        return r;
}

static void manager_process_deferred_closes(Manager *m) {
        JournalFile *f;

        /* Perform any deferred closes which aren't still offlining. */
        SET_FOREACH(f, m->deferred_closes) {
                if (journal_file_is_offlining(f))
                        continue;

                (void) set_remove(m->deferred_closes, f);
                (void) journal_file_offline_close(f);
        }
}

static void manager_vacuum_deferred_closes(Manager *m) {
        assert(m);

        /* Make some room in the deferred closes list, so that it doesn't grow without bounds */
        if (set_size(m->deferred_closes) < DEFERRED_CLOSES_MAX)
                return;

        /* Let's first remove all journal files that might already have completed closing */
        manager_process_deferred_closes(m);

        /* And now, let's close some more until we reach the limit again. */
        while (set_size(m->deferred_closes) >= DEFERRED_CLOSES_MAX) {
                JournalFile *f;

                assert_se(f = set_steal_first(m->deferred_closes));
                journal_file_offline_close(f);
        }
}

static int manager_archive_offline_user_journals(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(m);

        d = opendir(m->system_storage.path);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_ratelimit_error_errno(errno, JOURNAL_LOG_RATELIMIT,
                                                 "Failed to open %s: %m", m->system_storage.path);
        }

        for (;;) {
                _cleanup_free_ char *full = NULL;
                _cleanup_close_ int fd = -EBADF;
                struct dirent *de;
                JournalFile *f;
                uid_t uid;

                errno = 0;
                de = readdir_no_dot(d);
                if (!de) {
                        if (errno != 0)
                                log_ratelimit_warning_errno(errno, JOURNAL_LOG_RATELIMIT,
                                                            "Failed to enumerate %s, ignoring: %m",
                                                            m->system_storage.path);
                        break;
                }

                r = journal_file_parse_uid_from_filename(de->d_name, &uid);
                if (r < 0) {
                        /* Don't warn if the file is not an online or offline user journal. */
                        if (r != -EREMOTE)
                                log_warning_errno(r, "Failed to parse UID from file name '%s', ignoring: %m", de->d_name);
                        continue;
                }

                /* Already rotated in the above loop? i.e. is it an open user journal? */
                if (ordered_hashmap_contains(m->user_journals, UID_TO_PTR(uid)))
                        continue;

                full = path_join(m->system_storage.path, de->d_name);
                if (!full)
                        return log_oom();

                fd = openat(dirfd(d), de->d_name, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW|O_NONBLOCK);
                if (fd < 0) {
                        log_ratelimit_full_errno(IN_SET(errno, ELOOP, ENOENT) ? LOG_DEBUG : LOG_WARNING,
                                                 errno, JOURNAL_LOG_RATELIMIT,
                                                 "Failed to open journal file '%s' for rotation: %m", full);
                        continue;
                }

                /* Make some room in the set of deferred close()s */
                manager_vacuum_deferred_closes(m);

                /* Open the file briefly, so that we can archive it */
                r = journal_file_open(
                                fd,
                                full,
                                O_RDWR,
                                manager_get_file_flags(m, m->config.seal) & ~JOURNAL_STRICT_ORDER, /* strict order does not matter here */
                                0640,
                                m->config.compress.threshold_bytes,
                                &m->system_storage.metrics,
                                m->mmap,
                                /* template= */ NULL,
                                &f);
                if (r < 0) {
                        log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                    "Failed to read journal file %s for rotation, trying to move it out of the way: %m",
                                                    full);

                        r = journal_file_dispose(dirfd(d), de->d_name);
                        if (r < 0)
                                log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                            "Failed to move %s out of the way, ignoring: %m",
                                                            full);
                        else
                                log_debug("Successfully moved %s out of the way.", full);

                        continue;
                }

                TAKE_FD(fd); /* Donated to journal_file_open() */

                journal_file_write_final_tag(f);
                r = journal_file_archive(f, NULL);
                if (r < 0)
                        log_debug_errno(r, "Failed to archive journal file '%s', ignoring: %m", full);

                journal_file_initiate_close(TAKE_PTR(f), m->deferred_closes);
        }

        return 0;
}

void manager_rotate(Manager *m) {
        JournalFile *f;
        void *k;
        int r;

        log_debug("Rotating...");

        /* First, rotate the system journal (either in its runtime flavour or in its runtime flavour) */
        (void) manager_do_rotate(m, &m->runtime_journal, "runtime", /* seal= */ false, /* uid= */ 0);
        (void) manager_do_rotate(m, &m->system_journal, "system", m->config.seal, /* uid= */ 0);

        /* Then, rotate all user journals we have open (keeping them open) */
        ORDERED_HASHMAP_FOREACH_KEY(f, k, m->user_journals) {
                r = manager_do_rotate(m, &f, "user", m->config.seal, PTR_TO_UID(k));
                if (r >= 0)
                        ordered_hashmap_replace(m->user_journals, k, f);
                else if (!f)
                        /* Old file has been closed and deallocated */
                        ordered_hashmap_remove(m->user_journals, k);
        }

        /* Finally, also rotate all user journals we currently do not have open. (But do so only if we
         * actually have access to /var, i.e. are not in the log-to-runtime-journal mode). */
        if (!m->runtime_journal)
                (void) manager_archive_offline_user_journals(m);

        manager_process_deferred_closes(m);
}

static void manager_rotate_journal(Manager *m, JournalFile *f, uid_t uid) {
        int r;

        assert(m);
        assert(f);

        /* This is similar to manager_rotate(), but rotates only specified journal file.
         *
         * 💣💣💣 This invalidate 'f', and the caller cannot reuse the passed JournalFile object. 💣💣💣 */

        if (f == m->system_journal)
                (void) manager_do_rotate(m, &m->system_journal, "system", m->config.seal, /* uid= */ 0);
        else if (f == m->runtime_journal)
                (void) manager_do_rotate(m, &m->runtime_journal, "runtime", /* seal= */ false, /* uid= */ 0);
        else {
                assert(ordered_hashmap_get(m->user_journals, UID_TO_PTR(uid)) == f);
                r = manager_do_rotate(m, &f, "user", m->config.seal, uid);
                if (r >= 0)
                        ordered_hashmap_replace(m->user_journals, UID_TO_PTR(uid), f);
                else if (!f)
                        /* Old file has been closed and deallocated */
                        ordered_hashmap_remove(m->user_journals, UID_TO_PTR(uid));
        }

        manager_process_deferred_closes(m);
}

static void manager_sync(Manager *m, bool wait) {
        JournalFile *f;
        int r;

        if (m->system_journal) {
                r = journal_file_set_offline(m->system_journal, wait);
                if (r < 0)
                        log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                    "Failed to sync system journal, ignoring: %m");
        }

        ORDERED_HASHMAP_FOREACH(f, m->user_journals) {
                r = journal_file_set_offline(f, wait);
                if (r < 0)
                        log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                    "Failed to sync user journal, ignoring: %m");
        }

        r = sd_event_source_set_enabled(m->sync_event_source, SD_EVENT_OFF);
        if (r < 0)
                log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                            "Failed to disable sync timer source, ignoring: %m");

        m->sync_scheduled = false;
}

static void manager_do_vacuum(Manager *m, JournalStorage *storage, bool verbose) {
        int r;

        assert(m);
        assert(storage);

        (void) cache_space_refresh(m, storage);

        if (verbose)
                manager_space_usage_message(m, storage);

        r = journal_directory_vacuum(storage->path, storage->space.limit,
                                     storage->metrics.n_max_files, m->config.max_retention_usec,
                                     &m->oldest_file_usec, verbose);
        if (r < 0 && r != -ENOENT)
                log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                            "Failed to vacuum %s, ignoring: %m", storage->path);

        cache_space_invalidate(&storage->space);
}

void manager_vacuum(Manager *m, bool verbose) {
        assert(m);

        log_debug("Vacuuming...");

        m->oldest_file_usec = 0;

        if (m->system_journal)
                manager_do_vacuum(m, &m->system_storage, verbose);
        if (m->runtime_journal)
                manager_do_vacuum(m, &m->runtime_storage, verbose);
}

static void manager_cache_machine_id(Manager *m) {
        sd_id128_t id;
        int r;

        assert(m);

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return;

        sd_id128_to_string(id, stpcpy(m->machine_id_field, "_MACHINE_ID="));
}

static void manager_cache_boot_id(Manager *m) {
        sd_id128_t id;
        int r;

        assert(m);

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return;

        sd_id128_to_string(id, stpcpy(m->boot_id_field, "_BOOT_ID="));
}

static void manager_cache_hostname(Manager *m) {
        _cleanup_free_ char *t = NULL;
        char *x;

        assert(m);

        t = gethostname_malloc();
        if (!t)
                return;

        x = strjoin("_HOSTNAME=", t);
        if (!x)
                return;

        free_and_replace(m->hostname_field, x);
}

static bool shall_try_append_again(JournalFile *f, int r) {
        switch (r) {

        case -E2BIG:           /* Hit configured limit          */
        case -EFBIG:           /* Hit fs limit                  */
        case -EDQUOT:          /* Quota limit hit               */
        case -ENOSPC:          /* Disk full                     */
                log_debug_errno(r, "%s: Allocation limit reached, rotating.", f->path);
                return true;

        case -EROFS: /* Read-only file system */
                /* When appending an entry fails if shall_try_append_again returns true, the journal is
                 * rotated. If the FS is read-only, rotation will fail and m->system_journal will be set to
                 * NULL. After that, when find_journal will try to open the journal since m->system_journal
                 * will be NULL, it will open the runtime journal. */
                log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT, "%s: Read-only file system, rotating.", f->path);
                return true;

        case -EIO:             /* I/O error of some kind (mmap) */
                log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT, "%s: IO error, rotating.", f->path);
                return true;

        case -EHOSTDOWN:       /* Other machine                 */
                log_ratelimit_info_errno(r, JOURNAL_LOG_RATELIMIT, "%s: Journal file from other machine, rotating.", f->path);
                return true;

        case -EBUSY:           /* Unclean shutdown              */
                log_ratelimit_info_errno(r, JOURNAL_LOG_RATELIMIT, "%s: Unclean shutdown, rotating.", f->path);
                return true;

        case -EPROTONOSUPPORT: /* Unsupported feature           */
                log_ratelimit_info_errno(r, JOURNAL_LOG_RATELIMIT, "%s: Unsupported feature, rotating.", f->path);
                return true;

        case -EBADMSG:         /* Corrupted                     */
        case -ENODATA:         /* Truncated                     */
        case -ESHUTDOWN:       /* Already archived              */
        case -EADDRNOTAVAIL:   /* Referenced object offset out of bounds */
                log_ratelimit_info_errno(r, JOURNAL_LOG_RATELIMIT, "%s: Journal file corrupted, rotating.", f->path);
                return true;

        case -EIDRM:           /* Journal file has been deleted */
                log_ratelimit_info_errno(r, JOURNAL_LOG_RATELIMIT, "%s: Journal file has been deleted, rotating.", f->path);
                return true;

        case -EREMCHG:         /* Wallclock time (CLOCK_REALTIME) jumped backwards relative to last journal entry */
                log_ratelimit_info_errno(r, JOURNAL_LOG_RATELIMIT, "%s: Realtime clock jumped backwards relative to last journal entry, rotating.", f->path);
                return true;

        case -ENOTNAM: /* Monotonic time (CLOCK_MONOTONIC) jumped backwards relative to last journal entry with the same boot ID */
                log_ratelimit_info_errno(
                                r,
                                JOURNAL_LOG_RATELIMIT,
                                "%s: Monotonic clock jumped backwards relative to last journal entry with the same boot ID, rotating.",
                                f->path);
                return true;

        case -EILSEQ:          /* seqnum ID last used in the file doesn't match the one we'd passed when writing an entry to it */
                log_ratelimit_info_errno(r, JOURNAL_LOG_RATELIMIT, "%s: Journal file uses a different sequence number ID, rotating.", f->path);
                return true;

        case -EAFNOSUPPORT:
                log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT, "%s: Underlying file system does not support memory mapping or another required file system feature.", f->path);
                return false;

        default:
                log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT, "%s: Unexpected error while writing to journal file: %m", f->path);
                return false;
        }
}

static void manager_write_to_journal(
                Manager *m,
                uid_t uid,
                const struct iovec *iovec,
                size_t n,
                const dual_timestamp *ts,
                int priority) {

        bool vacuumed = false;
        JournalFile *f;
        int r;

        assert(m);
        assert(iovec);
        assert(n > 0);
        assert(ts);

        if (ts->realtime < m->last_realtime_clock) {
                /* When the time jumps backwards, let's immediately rotate. Of course, this should not happen during
                 * regular operation. However, when it does happen, then we should make sure that we start fresh files
                 * to ensure that the entries in the journal files are strictly ordered by time, in order to ensure
                 * bisection works correctly. */

                log_ratelimit_info(JOURNAL_LOG_RATELIMIT, "Time jumped backwards, rotating.");
                manager_rotate(m);
                manager_vacuum(m, /* verbose = */ false);
                vacuumed = true;
        }

        f = manager_find_journal(m, uid);
        if (!f)
                return;

        if (journal_file_rotate_suggested(f, m->config.max_file_usec, LOG_DEBUG)) {
                if (vacuumed) {
                        log_ratelimit_warning(JOURNAL_LOG_RATELIMIT,
                                              "Suppressing rotation, as we already rotated immediately before write attempt. Giving up.");
                        return;
                }

                log_debug("%s: Journal header limits reached or header out-of-date, rotating.", f->path);

                manager_rotate_journal(m, TAKE_PTR(f), uid);
                manager_vacuum(m, /* verbose = */ false);
                vacuumed = true;

                f = manager_find_journal(m, uid);
                if (!f)
                        return;
        }

        m->last_realtime_clock = ts->realtime;

        r = journal_file_append_entry(
                        f,
                        ts,
                        /* boot_id= */ NULL,
                        iovec, n,
                        &m->seqnum->seqnum,
                        &m->seqnum->id,
                        /* ret_object= */ NULL,
                        /* ret_offset= */ NULL);
        if (r >= 0) {
                manager_schedule_sync(m, priority);
                return;
        }

        log_debug_errno(r, "Failed to write entry to %s (%zu items, %zu bytes): %m", f->path, n, iovec_total_size(iovec, n));

        if (!shall_try_append_again(f, r))
                return;
        if (vacuumed) {
                log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                            "Suppressing rotation, as we already rotated immediately before write attempt. Giving up.");
                return;
        }

        manager_rotate_journal(m, TAKE_PTR(f), uid);
        manager_vacuum(m, /* verbose = */ false);

        f = manager_find_journal(m, uid);
        if (!f)
                return;

        log_debug_errno(r, "Retrying write.");
        r = journal_file_append_entry(
                        f,
                        ts,
                        /* boot_id= */ NULL,
                        iovec, n,
                        &m->seqnum->seqnum,
                        &m->seqnum->id,
                        /* ret_object= */ NULL,
                        /* ret_offset= */ NULL);
        if (r < 0)
                log_ratelimit_error_errno(r, FAILED_TO_WRITE_ENTRY_RATELIMIT,
                                          "Failed to write entry to %s (%zu items, %zu bytes) despite vacuuming, ignoring: %m",
                                          f->path, n, iovec_total_size(iovec, n));
        else
                manager_schedule_sync(m, priority);
}

#define IOVEC_ADD_NUMERIC_FIELD(iovec, n, value, type, isset, format, field)  \
        if (isset(value)) {                                             \
                char *k;                                                \
                k = newa(char, STRLEN(field "=") + DECIMAL_STR_MAX(type) + 1); \
                sprintf(k, field "=" format, value);                    \
                iovec[n++] = IOVEC_MAKE_STRING(k);                      \
        }

#define IOVEC_ADD_STRING_FIELD(iovec, n, value, field)                  \
        if (!isempty(value)) {                                          \
                char *k;                                                \
                k = strjoina(field "=", value);                         \
                iovec[n++] = IOVEC_MAKE_STRING(k);                      \
        }

#define IOVEC_ADD_ID128_FIELD(iovec, n, value, field)                   \
        if (!sd_id128_is_null(value)) {                                 \
                char *k;                                                \
                k = newa(char, STRLEN(field "=") + SD_ID128_STRING_MAX); \
                sd_id128_to_string(value, stpcpy(k, field "="));        \
                iovec[n++] = IOVEC_MAKE_STRING(k);                      \
        }

#define IOVEC_ADD_SIZED_FIELD(iovec, n, value, value_size, field)               \
        if (value_size > 0) {                                                   \
                char *k;                                                        \
                k = newa(char, STRLEN(field "=") + value_size + 1);             \
                *mempcpy_typesafe(stpcpy(k, field "="), value, value_size) = 0; \
                iovec[n++] = IOVEC_MAKE_STRING(k);                              \
        }

static void manager_dispatch_message_real(
                Manager *m,
                struct iovec *iovec, size_t n, size_t mm,
                const ClientContext *c,
                const struct timeval *tv,
                int priority,
                pid_t object_pid) {

        char source_time[STRLEN("_SOURCE_REALTIME_TIMESTAMP=") + DECIMAL_STR_MAX(usec_t)];
        _unused_ _cleanup_free_ char *cmdline1 = NULL, *cmdline2 = NULL;
        uid_t journal_uid;
        ClientContext *o;

        assert(m);
        assert(iovec);
        assert(n > 0);
        assert(n +
               N_IOVEC_META_FIELDS +
               (pid_is_valid(object_pid) ? N_IOVEC_OBJECT_FIELDS : 0) +
               client_context_extra_fields_n_iovec(c) <= mm);

        if (c) {
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, c->pid, pid_t, pid_is_valid, PID_FMT, "_PID");
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, c->uid, uid_t, uid_is_valid, UID_FMT, "_UID");
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, c->gid, gid_t, gid_is_valid, GID_FMT, "_GID");

                IOVEC_ADD_STRING_FIELD(iovec, n, c->comm, "_COMM"); /* At most TASK_COMM_LENGTH (16 bytes) */
                IOVEC_ADD_STRING_FIELD(iovec, n, c->exe, "_EXE"); /* A path, so at most PATH_MAX (4096 bytes) */

                if (c->cmdline)
                        /* At most _SC_ARG_MAX (2MB usually), which is too much to put on stack.
                         * Let's use a heap allocation for this one. */
                        cmdline1 = set_iovec_string_field(iovec, &n, "_CMDLINE=", c->cmdline);

                IOVEC_ADD_NUMERIC_FIELD(iovec, n, c->capability_quintet.effective, uint64_t, capability_is_set, "%" PRIx64, "_CAP_EFFECTIVE");
                IOVEC_ADD_SIZED_FIELD(iovec, n, c->label, c->label_size, "_SELINUX_CONTEXT");
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, c->auditid, uint32_t, audit_session_is_valid, "%" PRIu32, "_AUDIT_SESSION");
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, c->loginuid, uid_t, uid_is_valid, UID_FMT, "_AUDIT_LOGINUID");

                IOVEC_ADD_STRING_FIELD(iovec, n, c->cgroup, "_SYSTEMD_CGROUP"); /* A path */
                IOVEC_ADD_STRING_FIELD(iovec, n, c->session, "_SYSTEMD_SESSION");
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, c->owner_uid, uid_t, uid_is_valid, UID_FMT, "_SYSTEMD_OWNER_UID");
                IOVEC_ADD_STRING_FIELD(iovec, n, c->unit, "_SYSTEMD_UNIT"); /* Unit names are bounded by UNIT_NAME_MAX */
                IOVEC_ADD_STRING_FIELD(iovec, n, c->user_unit, "_SYSTEMD_USER_UNIT");
                IOVEC_ADD_STRING_FIELD(iovec, n, c->slice, "_SYSTEMD_SLICE");
                IOVEC_ADD_STRING_FIELD(iovec, n, c->user_slice, "_SYSTEMD_USER_SLICE");

                IOVEC_ADD_ID128_FIELD(iovec, n, c->invocation_id, "_SYSTEMD_INVOCATION_ID");

                if (c->extra_fields_n_iovec > 0) {
                        memcpy(iovec + n, c->extra_fields_iovec, c->extra_fields_n_iovec * sizeof(struct iovec));
                        n += c->extra_fields_n_iovec;
                }
        }

        assert(n <= mm);

        if (pid_is_valid(object_pid) && client_context_get(m, object_pid, NULL, NULL, 0, NULL, &o) >= 0) {

                IOVEC_ADD_NUMERIC_FIELD(iovec, n, o->pid, pid_t, pid_is_valid, PID_FMT, "OBJECT_PID");
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, o->uid, uid_t, uid_is_valid, UID_FMT, "OBJECT_UID");
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, o->gid, gid_t, gid_is_valid, GID_FMT, "OBJECT_GID");

                /* See above for size limits, only ->cmdline may be large, so use a heap allocation for it. */
                IOVEC_ADD_STRING_FIELD(iovec, n, o->comm, "OBJECT_COMM");
                IOVEC_ADD_STRING_FIELD(iovec, n, o->exe, "OBJECT_EXE");
                if (o->cmdline)
                        cmdline2 = set_iovec_string_field(iovec, &n, "OBJECT_CMDLINE=", o->cmdline);

                IOVEC_ADD_NUMERIC_FIELD(iovec, n, o->capability_quintet.effective, uint64_t, capability_is_set, "%" PRIx64, "OBJECT_CAP_EFFECTIVE");
                IOVEC_ADD_SIZED_FIELD(iovec, n, o->label, o->label_size, "OBJECT_SELINUX_CONTEXT");
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, o->auditid, uint32_t, audit_session_is_valid, "%" PRIu32, "OBJECT_AUDIT_SESSION");
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, o->loginuid, uid_t, uid_is_valid, UID_FMT, "OBJECT_AUDIT_LOGINUID");

                IOVEC_ADD_STRING_FIELD(iovec, n, o->cgroup, "OBJECT_SYSTEMD_CGROUP");
                IOVEC_ADD_STRING_FIELD(iovec, n, o->session, "OBJECT_SYSTEMD_SESSION");
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, o->owner_uid, uid_t, uid_is_valid, UID_FMT, "OBJECT_SYSTEMD_OWNER_UID");
                IOVEC_ADD_STRING_FIELD(iovec, n, o->unit, "OBJECT_SYSTEMD_UNIT");
                IOVEC_ADD_STRING_FIELD(iovec, n, o->user_unit, "OBJECT_SYSTEMD_USER_UNIT");
                IOVEC_ADD_STRING_FIELD(iovec, n, o->slice, "OBJECT_SYSTEMD_SLICE");
                IOVEC_ADD_STRING_FIELD(iovec, n, o->user_slice, "OBJECT_SYSTEMD_USER_SLICE");

                IOVEC_ADD_ID128_FIELD(iovec, n, o->invocation_id, "OBJECT_SYSTEMD_INVOCATION_ID");
        }

        assert(n <= mm);

        if (tv) {
                xsprintf(source_time, "_SOURCE_REALTIME_TIMESTAMP=" USEC_FMT, timeval_load(tv));
                iovec[n++] = IOVEC_MAKE_STRING(source_time);
        }

        /* Note that strictly speaking storing the boot id here is
         * redundant since the entry includes this in-line
         * anyway. However, we need this indexed, too. */
        if (!isempty(m->boot_id_field))
                iovec[n++] = IOVEC_MAKE_STRING(m->boot_id_field);

        if (!isempty(m->machine_id_field))
                iovec[n++] = IOVEC_MAKE_STRING(m->machine_id_field);

        if (!isempty(m->hostname_field))
                iovec[n++] = IOVEC_MAKE_STRING(m->hostname_field);

        if (!isempty(m->namespace_field))
                iovec[n++] = IOVEC_MAKE_STRING(m->namespace_field);

        iovec[n++] = in_initrd() ? IOVEC_MAKE_STRING("_RUNTIME_SCOPE=initrd") : IOVEC_MAKE_STRING("_RUNTIME_SCOPE=system");
        assert(n <= mm);

        if (m->config.split_mode == SPLIT_UID && c && uid_is_valid(c->uid))
                /* Split up strictly by (non-root) UID */
                journal_uid = c->uid;
        else if (m->config.split_mode == SPLIT_LOGIN && c && c->uid > 0 && uid_is_valid(c->owner_uid))
                /* Split up by login UIDs.  We do this only if the
                 * realuid is not root, in order not to accidentally
                 * leak privileged information to the user that is
                 * logged by a privileged process that is part of an
                 * unprivileged session. */
                journal_uid = c->owner_uid;
        else
                journal_uid = 0;

        /* Get the closest, linearized time we have for this log event from the event loop. (Note that we do
         * not use the source time, and not even the time the event was originally seen, but instead simply
         * the time we started processing it, as we want strictly linear ordering in what we write out.) */
        struct dual_timestamp ts;
        event_dual_timestamp_now(m->event, &ts);

        (void) manager_forward_socket(m, iovec, n, &ts, priority);

        manager_write_to_journal(m, journal_uid, iovec, n, &ts, priority);
}

void manager_driver_message_internal(Manager *m, pid_t object_pid, const char *format, ...) {
        struct iovec *iovec;
        size_t n = 0, k, mm;
        va_list ap;
        int r;

        assert(m);
        assert(format);

        mm = N_IOVEC_META_FIELDS + 5 + N_IOVEC_PAYLOAD_FIELDS + client_context_extra_fields_n_iovec(m->my_context) + N_IOVEC_OBJECT_FIELDS;
        iovec = newa(struct iovec, mm);

        assert_cc(3 == LOG_FAC(LOG_DAEMON));
        iovec[n++] = IOVEC_MAKE_STRING("SYSLOG_FACILITY=3");
        iovec[n++] = IOVEC_MAKE_STRING("SYSLOG_IDENTIFIER=systemd-journald");

        iovec[n++] = IOVEC_MAKE_STRING("_TRANSPORT=driver");
        assert_cc(6 == LOG_INFO);
        iovec[n++] = IOVEC_MAKE_STRING("PRIORITY=6");

        k = n;

        va_start(ap, format);
        DISABLE_WARNING_FORMAT_NONLITERAL;
        r = log_format_iovec(iovec, mm, &n, false, 0, format, ap);
        REENABLE_WARNING;
        /* Error handling below */
        va_end(ap);

        if (r >= 0)
                manager_dispatch_message_real(m, iovec, n, mm, m->my_context, /* tv= */ NULL, LOG_INFO, object_pid);

        while (k < n)
                free(iovec[k++].iov_base);

        if (r < 0) {
                /* We failed to format the message. Emit a warning instead. */
                char buf[LINE_MAX];

                errno = -r;
                xsprintf(buf, "MESSAGE=Entry printing failed: %m");

                n = 3;
                iovec[n++] = IOVEC_MAKE_STRING("PRIORITY=4");
                iovec[n++] = IOVEC_MAKE_STRING(buf);
                manager_dispatch_message_real(m, iovec, n, mm, m->my_context, /* tv= */ NULL, LOG_INFO, object_pid);
        }
}

void manager_dispatch_message(
                Manager *m,
                struct iovec *iovec, size_t n, size_t mm,
                ClientContext *c,
                const struct timeval *tv,
                int priority,
                pid_t object_pid) {

        uint64_t available = 0;
        int rl;

        assert(m);
        assert(iovec || n == 0);

        if (n == 0)
                return;

        if (LOG_PRI(priority) > m->config.max_level_store)
                return;

        /* Stop early in case the information will not be stored
         * in a journal. */
        if (m->config.storage == STORAGE_NONE)
                return;

        if (c && c->unit) {
                (void) manager_determine_space(m, &available, /* limit= */ NULL);

                rl = journal_ratelimit_test(
                                &m->ratelimit_groups_by_id,
                                c->unit,
                                c->log_ratelimit_interval,
                                c->log_ratelimit_burst,
                                LOG_PRI(priority),
                                available);
                if (rl == 0)
                        return;

                /* Write a suppression message if we suppressed something */
                if (rl > 1)
                        manager_driver_message(m, c->pid,
                                              LOG_MESSAGE_ID(SD_MESSAGE_JOURNAL_DROPPED_STR),
                                              LOG_MESSAGE("Suppressed %i messages from %s", rl - 1, c->unit),
                                              LOG_ITEM("N_DROPPED=%i", rl - 1));
        }

        manager_dispatch_message_real(m, iovec, n, mm, c, tv, priority, object_pid);
}

int manager_flush_to_var(Manager *m, bool require_flag_file) {
        sd_journal *j = NULL;
        const char *fn;
        unsigned n = 0;
        usec_t start;
        int r, k;

        assert(m);

        if (!IN_SET(m->config.storage, STORAGE_AUTO, STORAGE_PERSISTENT))
                return 0;

        if (m->namespace) /* Flushing concept does not exist for namespace instances */
                return 0;

        if (!m->runtime_journal) /* Nothing to flush? */
                return 0;

        if (require_flag_file && !manager_flushed_flag_is_set(m))
                return 0;

        (void) manager_system_journal_open(m, /* flush_requested=*/ true, /* relinquish_requested= */ false);

        if (!m->system_journal)
                return 0;

        /* Offline and close the 'main' runtime journal file to allow the runtime journal to be opened with
         * the SD_JOURNAL_ASSUME_IMMUTABLE flag in the below. */
        m->runtime_journal = journal_file_offline_close(m->runtime_journal);

        /* Reset current seqnum data to avoid unnecessary rotation when switching to system journal.
         * See issue #30092. */
        zero(*m->seqnum);

        log_debug("Flushing to %s...", m->system_storage.path);

        start = now(CLOCK_MONOTONIC);

        r = sd_journal_open(&j, SD_JOURNAL_RUNTIME_ONLY | SD_JOURNAL_ASSUME_IMMUTABLE);
        if (r < 0) {
                log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT, "Failed to read runtime journal: %m");
                goto finish;
        }

        sd_journal_set_data_threshold(j, 0);

        SD_JOURNAL_FOREACH(j) {
                Object *o = NULL;
                JournalFile *f;

                f = j->current_file;
                assert(f && f->current_offset > 0);

                n++;

                r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
                if (r < 0) {
                        log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT, "Can't read entry: %m");
                        goto finish;
                }

                r = journal_file_copy_entry(
                                f,
                                m->system_journal,
                                o,
                                f->current_offset,
                                &m->seqnum->seqnum,
                                &m->seqnum->id);
                if (r >= 0)
                        continue;

                if (!shall_try_append_again(m->system_journal, r)) {
                        log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT, "Can't write entry: %m");
                        goto finish;
                }

                log_ratelimit_info(JOURNAL_LOG_RATELIMIT, "Rotating system journal.");

                manager_rotate_journal(m, m->system_journal, /* uid = */ 0);
                manager_vacuum(m, /* verbose = */ false);

                if (!m->system_journal) {
                        log_ratelimit_notice(JOURNAL_LOG_RATELIMIT,
                                             "Didn't flush runtime journal since rotation of system journal wasn't successful.");
                        r = -EIO;
                        goto finish;
                }

                log_debug("Retrying write.");
                r = journal_file_copy_entry(
                                f,
                                m->system_journal,
                                o,
                                f->current_offset,
                                &m->seqnum->seqnum,
                                &m->seqnum->id);
                if (r < 0) {
                        log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT, "Can't write entry: %m");
                        goto finish;
                }
        }

        r = 0;

finish:
        if (m->system_journal)
                journal_file_post_change(m->system_journal);

        /* Save parent directories of runtime journals before closing runtime journals. */
        _cleanup_strv_free_ char **dirs = NULL;
        (void) journal_get_directories(j, &dirs);

        /* First, close all runtime journals opened in the above. */
        sd_journal_close(j);

        /* Remove the runtime directory if the all entries are successfully flushed to /var/. */
        if (r >= 0) {
                r = rm_rf(m->runtime_storage.path, REMOVE_ROOT);
                if (r < 0)
                        log_debug_errno(r, "Failed to remove runtime journal directory %s, ignoring: %m", m->runtime_storage.path);
                else
                        log_debug("Removed runtime journal directory %s.", m->runtime_storage.path);

                /* The initrd may have a different machine ID from the host's one. Typically, that happens
                 * when our tests running on qemu, as the host's initrd is picked as is without updating
                 * the machine ID in the initrd with the one used in the image. Even in such the case, the
                 * runtime journals in the subdirectory named with the initrd's machine ID are flushed to
                 * the persistent journal. To make not the runtime journal flushed multiple times, let's
                 * also remove the runtime directories. */
                STRV_FOREACH(p, dirs) {
                        r = rm_rf(*p, REMOVE_ROOT);
                        if (r < 0)
                                log_debug_errno(r, "Failed to remove additional runtime journal directory %s, ignoring: %m", *p);
                        else
                                log_debug("Removed additional runtime journal directory %s.", *p);
                }
        }

        manager_driver_message(m, 0,
                              LOG_MESSAGE("Time spent on flushing to %s is %s for %u entries.",
                                          m->system_storage.path,
                                          FORMAT_TIMESPAN(usec_sub_unsigned(now(CLOCK_MONOTONIC), start), 0),
                                          n));

        fn = strjoina(m->runtime_directory, "/flushed");
        k = touch(fn);
        if (k < 0)
                log_ratelimit_warning_errno(k, JOURNAL_LOG_RATELIMIT,
                                            "Failed to touch %s, ignoring: %m", fn);

        manager_refresh_idle_timer(m);
        return r;
}

int manager_relinquish_var(Manager *m) {
        assert(m);

        if (m->config.storage == STORAGE_NONE)
                return 0;

        if (m->namespace) /* Concept does not exist for namespaced instances */
                return -EOPNOTSUPP;

        if (m->runtime_journal && !m->system_journal)
                return 0;

        log_debug("Relinquishing %s...", m->system_storage.path);

        (void) manager_system_journal_open(m, /* flush_requested = */ false, /* relinquish_requested = */ true);

        m->system_journal = journal_file_offline_close(m->system_journal);
        ordered_hashmap_clear(m->user_journals);
        set_clear(m->deferred_closes);

        manager_refresh_idle_timer(m);
        return 0;
}

int manager_process_datagram(
                sd_event_source *es,
                int fd,
                uint32_t revents,
                void *userdata) {

        size_t label_len = 0, mm;
        Manager *m = ASSERT_PTR(userdata);
        struct ucred *ucred = NULL;
        struct timeval tv_buf, *tv = NULL;
        struct cmsghdr *cmsg;
        char *label = NULL;
        struct iovec iovec;
        ssize_t n;
        int *fds = NULL, v = 0;
        size_t n_fds = 0;

        /* We use NAME_MAX space for the SELinux label here. The kernel currently enforces no limit, but
         * according to suggestions from the SELinux people this will change and it will probably be
         * identical to NAME_MAX. For now we use that, but this should be updated one day when the final
         * limit is known.
         *
         * Here, we need to explicitly initialize the buffer with zero, as glibc has a bug in
         * __convert_scm_timestamps(), which assumes the buffer is initialized. See #20741.
         * The issue is fixed on glibc-2.35 (8fba672472ae0055387e9315fc2eddfa6775ca79). */
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred)) +
                         CMSG_SPACE_TIMEVAL +
                         CMSG_SPACE(sizeof(int)) + /* fd */
                         CMSG_SPACE(NAME_MAX) /* selinux label */) control = {};

        union sockaddr_union sa = {};

        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
                .msg_name = &sa,
                .msg_namelen = sizeof(sa),
        };

        assert(fd == m->native_fd || fd == m->syslog_fd || fd == m->audit_fd);

        if (revents != EPOLLIN)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Got invalid event from epoll for datagram fd: %" PRIx32,
                                       revents);

        /* Try to get the right size, if we can. (Not all sockets support SIOCINQ, hence we just try, but don't rely on
         * it.) */
        (void) ioctl(fd, SIOCINQ, &v);

        /* Fix it up, if it is too small. We use the same fixed value as auditd here. Awful! */
        mm = PAGE_ALIGN(MAX3((size_t) v + 1,
                            (size_t) LINE_MAX,
                            ALIGN(sizeof(struct nlmsghdr)) + ALIGN((size_t) MAX_AUDIT_MESSAGE_LENGTH)) + 1);

        if (!GREEDY_REALLOC(m->buffer, mm))
                return log_oom();

        iovec = IOVEC_MAKE(m->buffer, MALLOC_ELEMENTSOF(m->buffer) - 1); /* Leave room for trailing NUL we add later */

        n = recvmsg_safe(fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if (ERRNO_IS_NEG_TRANSIENT(n))
                return 0;
        if (n == -ECHRNG) {
                log_ratelimit_warning_errno(n, JOURNAL_LOG_RATELIMIT,
                                            "Got message with truncated control data (too many fds sent?), ignoring.");
                return 0;
        }
        if (n == -EXFULL) {
                log_ratelimit_warning_errno(n, JOURNAL_LOG_RATELIMIT, "Got message with truncated payload data, ignoring.");
                return 0;
        }
        if (n < 0)
                return log_ratelimit_error_errno(n, JOURNAL_LOG_RATELIMIT, "Failed to receive message: %m");

        CMSG_FOREACH(cmsg, &msghdr) {
                if (cmsg->cmsg_level != SOL_SOCKET)
                        continue;

                if (cmsg->cmsg_type == SCM_CREDENTIALS &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
                        assert(!ucred);
                        ucred = CMSG_TYPED_DATA(cmsg, struct ucred);
                } else if (cmsg->cmsg_type == SCM_SECURITY) {
                        assert(!label);
                        label = CMSG_TYPED_DATA(cmsg, char);
                        label_len = cmsg->cmsg_len - CMSG_LEN(0);
                } else if (cmsg->cmsg_type == SCM_TIMESTAMP &&
                           cmsg->cmsg_len == CMSG_LEN(sizeof(struct timeval))) {
                        assert(!tv);
                        tv = memcpy(&tv_buf, CMSG_DATA(cmsg), sizeof(struct timeval));
                } else if (cmsg->cmsg_type == SCM_RIGHTS) {
                        assert(!fds);
                        fds = CMSG_TYPED_DATA(cmsg, int);
                        n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                }
        }

        /* And a trailing NUL, just in case */
        m->buffer[n] = 0;

        if (fd == m->syslog_fd) {
                if (n > 0 && n_fds == 0)
                        manager_process_syslog_message(m, m->buffer, n, ucred, tv, label, label_len);
                else if (n_fds > 0)
                        log_ratelimit_warning(JOURNAL_LOG_RATELIMIT,
                                              "Got file descriptors via syslog socket. Ignoring.");

                if (tv)
                        m->syslog_timestamp = timeval_load(tv);

        } else if (fd == m->native_fd) {
                if (n > 0 && n_fds == 0)
                        manager_process_native_message(m, m->buffer, n, ucred, tv, label, label_len);
                else if (n == 0 && n_fds == 1)
                        (void) manager_process_native_file(m, fds[0], ucred, tv, label, label_len);
                else if (n_fds > 0)
                        log_ratelimit_warning(JOURNAL_LOG_RATELIMIT,
                                              "Got too many file descriptors via native socket. Ignoring.");

                if (tv)
                        m->native_timestamp = timeval_load(tv);

        } else {
                assert(fd == m->audit_fd);

                if (n > 0 && n_fds == 0)
                        manager_process_audit_message(m, m->buffer, n, ucred, &sa, msghdr.msg_namelen);
                else if (n_fds > 0)
                        log_ratelimit_warning(JOURNAL_LOG_RATELIMIT,
                                              "Got file descriptors via audit socket. Ignoring.");
        }

        close_many(fds, n_fds);

        if (tv)
                sync_req_revalidate_by_timestamp(m);

        manager_refresh_idle_timer(m);
        return 0;
}

void manager_full_flush(Manager *m) {
        assert(m);

        (void) manager_flush_to_var(m, false);
        manager_sync(m, /* wait = */ false);
        manager_vacuum(m, false);

        manager_space_usage_message(m, NULL);

        manager_refresh_idle_timer(m);
}

static int dispatch_sigusr1(sd_event_source *es, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        assert(si);

        if (!si_code_from_process(si->ssi_code)) {
                log_warning("Received SIGUSR1 with unexpected .si_code %i, ignoring.", si->ssi_code);
                return 0;
        }

        if (m->namespace) {
                log_warning("Received SIGUSR1 signal from PID %u, but flushing runtime journals not supported for namespaced instances, ignoring.", si->ssi_pid);
                return 0;
        }

        log_info("Received SIGUSR1 signal from PID %u, as request to flush runtime journal.", si->ssi_pid);
        manager_full_flush(m);

        return 0;
}

void manager_full_rotate(Manager *m) {
        const char *fn;
        int r;

        assert(m);

        manager_rotate(m);
        manager_vacuum(m, true);

        if (m->system_journal)
                patch_min_use(&m->system_storage);
        if (m->runtime_journal)
                patch_min_use(&m->runtime_storage);

        /* Let clients know when the most recent rotation happened. */
        fn = strjoina(m->runtime_directory, "/rotated");
        r = write_timestamp_file_atomic(fn, now(CLOCK_MONOTONIC));
        if (r < 0)
                log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                            "Failed to write %s, ignoring: %m", fn);
}

static int dispatch_sigusr2(sd_event_source *es, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        assert(si);

        if (!si_code_from_process(si->ssi_code)) {
                log_warning("Received SIGUSR2 with unexpected .si_code %i, ignoring.", si->ssi_code);
                return 0;
        }

        log_info("Received SIGUSR2 signal from PID %u, as request to rotate journal, rotating.", si->ssi_pid);
        manager_full_rotate(m);

        return 0;
}

static int dispatch_sigterm(sd_event_source *es, const struct signalfd_siginfo *si, void *userdata) {
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *news = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        log_received_signal(LOG_INFO, si);

        (void) sd_event_source_set_enabled(es, SD_EVENT_OFF); /* Make sure this handler is called at most once */

        /* So on one hand we want to ensure that SIGTERMs are definitely handled in appropriate, bounded
         * time. On the other hand we want that everything pending is first comprehensively processed and
         * written to disk. These goals are incompatible, hence we try to find a middle ground: we'll process
         * SIGTERM with high priority, but from the handler (this one right here) we'll install two new event
         * sources: one low priority idle one that will issue the exit once everything else is processed (and
         * which is hopefully the regular, clean codepath); and one high priority timer that acts as safety
         * net: if our idle handler isn't run within 10s, we'll exit anyway.
         *
         * TLDR: we'll exit either when everything is processed, or after 10s max, depending on what happens
         * first.
         *
         * Note that exiting before the idle event is hit doesn't typically mean that we lose any data, as
         * messages will remain queued in the sockets they came in from, and thus can be processed when we
         * start up next – unless we are going down for the final system shutdown, in which case everything
         * is lost. */

        r = sd_event_add_defer(m->event, &news, NULL, NULL); /* NULL handler means → exit when triggered */
        if (r < 0) {
                log_error_errno(r, "Failed to allocate exit idle event handler: %m");
                goto fail;
        }

        (void) sd_event_source_set_description(news, "exit-idle");

        /* Run everything relevant before this. */
        r = sd_event_source_set_priority(news, SD_EVENT_PRIORITY_NORMAL+20);
        if (r < 0) {
                log_error_errno(r, "Failed to adjust priority of exit idle event handler: %m");
                goto fail;
        }

        /* Give up ownership, so that this event source is freed automatically when the event loop is freed. */
        r = sd_event_source_set_floating(news, true);
        if (r < 0) {
                log_error_errno(r, "Failed to make exit idle event handler floating: %m");
                goto fail;
        }

        news = sd_event_source_unref(news);

        r = sd_event_add_time_relative(m->event, &news, CLOCK_MONOTONIC, 10 * USEC_PER_SEC, 0, NULL, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate exit timeout event handler: %m");
                goto fail;
        }

        (void) sd_event_source_set_description(news, "exit-timeout");

        r = sd_event_source_set_priority(news, SD_EVENT_PRIORITY_IMPORTANT-20); /* This is a safety net, with highest priority */
        if (r < 0) {
                log_error_errno(r, "Failed to adjust priority of exit timeout event handler: %m");
                goto fail;
        }

        r = sd_event_source_set_floating(news, true);
        if (r < 0) {
                log_error_errno(r, "Failed to make exit timeout event handler floating: %m");
                goto fail;
        }

        news = sd_event_source_unref(news);

        log_debug("Exit event sources are now pending.");
        return 0;

fail:
        sd_event_exit(m->event, 0);
        return 0;
}

void manager_full_sync(Manager *m, bool wait) {
        const char *fn;
        int r;

        assert(m);

        manager_sync(m, wait);

        /* Let clients know when the most recent sync happened. */
        fn = strjoina(m->runtime_directory, "/synced");
        r = write_timestamp_file_atomic(fn, now(CLOCK_MONOTONIC));
        if (r < 0)
                log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                            "Failed to write %s, ignoring: %m", fn);
}

static int dispatch_sigrtmin1(sd_event_source *es, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        assert(si);

        if (!si_code_from_process(si->ssi_code)) {
                log_warning("Received SIGRTMIN1 with unexpected .si_code %i, ignoring.", si->ssi_code);
                return 0;
        }

        log_debug("Received SIGRTMIN1 signal from PID %u, as request to sync.", si->ssi_pid);
        manager_full_sync(m, /* wait = */ false);

        return 0;
}

static int manager_setup_signals(Manager *m) {
        int r;

        assert(m);

        r = sd_event_add_signal(m->event, &m->sigusr1_event_source, SIGUSR1|SD_EVENT_SIGNAL_PROCMASK, dispatch_sigusr1, m);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, &m->sigusr2_event_source, SIGUSR2|SD_EVENT_SIGNAL_PROCMASK, dispatch_sigusr2, m);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, &m->sigterm_event_source, SIGTERM|SD_EVENT_SIGNAL_PROCMASK, dispatch_sigterm, m);
        if (r < 0)
                return r;

        /* Let's process SIGTERM early, so that we definitely react to it */
        r = sd_event_source_set_priority(m->sigterm_event_source, SD_EVENT_PRIORITY_IMPORTANT-10);
        if (r < 0)
                return r;

        /* When journald is invoked on the terminal (when debugging), it's useful if C-c is handled
         * equivalent to SIGTERM. */
        r = sd_event_add_signal(m->event, &m->sigint_event_source, SIGINT|SD_EVENT_SIGNAL_PROCMASK, dispatch_sigterm, m);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(m->sigint_event_source, SD_EVENT_PRIORITY_IMPORTANT-10);
        if (r < 0)
                return r;

        /* SIGRTMIN+1 causes an immediate sync. We process this very late, so that everything else queued at
         * this point is really written to disk. Clients can watch /run/systemd/journal/synced with inotify
         * until its mtime changes to see when a sync happened. */
        r = sd_event_add_signal(m->event, &m->sigrtmin1_event_source, (SIGRTMIN+1)|SD_EVENT_SIGNAL_PROCMASK, dispatch_sigrtmin1, m);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(m->sigrtmin1_event_source, SD_EVENT_PRIORITY_NORMAL+15);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, /* ret= */ NULL, (SIGRTMIN+18)|SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, &m->sigrtmin18_info);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGHUP|SD_EVENT_SIGNAL_PROCMASK, manager_dispatch_reload_signal, m);
        if (r < 0)
                return r;

        return 0;
}

static int manager_dispatch_sync(sd_event_source *es, usec_t t, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        manager_sync(m, /* wait = */ false);
        return 0;
}

static int manager_schedule_sync(Manager *m, int priority) {
        int r;

        assert(m);

        if (priority <= LOG_CRIT) {
                /* Immediately sync to disk when this is of priority CRIT, ALERT, EMERG */
                manager_sync(m, /* wait = */ false);
                return 0;
        }

        if (!m->event || sd_event_get_state(m->event) == SD_EVENT_FINISHED) {
                /* Shutting down the server? Let's sync immediately. */
                manager_sync(m, /* wait = */ false);
                return 0;
        }

        if (m->sync_scheduled)
                return 0;

        if (m->config.sync_interval_usec > 0) {

                if (!m->sync_event_source) {
                        r = sd_event_add_time_relative(
                                        m->event,
                                        &m->sync_event_source,
                                        CLOCK_MONOTONIC,
                                        m->config.sync_interval_usec, 0,
                                        manager_dispatch_sync, m);
                        if (r < 0)
                                return r;

                        r = sd_event_source_set_priority(m->sync_event_source, SD_EVENT_PRIORITY_IMPORTANT);
                } else {
                        r = sd_event_source_set_time_relative(m->sync_event_source, m->config.sync_interval_usec);
                        if (r < 0)
                                return r;

                        r = sd_event_source_set_enabled(m->sync_event_source, SD_EVENT_ONESHOT);
                }
                if (r < 0)
                        return r;

                m->sync_scheduled = true;
        }

        return 0;
}

static int dispatch_hostname_change(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        manager_cache_hostname(m);
        return 0;
}

static int manager_open_hostname(Manager *m) {
        int r;

        assert(m);

        m->hostname_fd = open("/proc/sys/kernel/hostname",
                              O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (m->hostname_fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", "/proc/sys/kernel/hostname");

        r = sd_event_add_io(m->event, &m->hostname_event_source, m->hostname_fd, 0, dispatch_hostname_change, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register hostname fd in event loop: %m");

        r = sd_event_source_set_priority(m->hostname_event_source, SD_EVENT_PRIORITY_IMPORTANT-10);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust priority of hostname event source: %m");

        return 0;
}

static int dispatch_notify_event(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(m->notify_event_source == es);
        assert(m->notify_fd == fd);

        /* The $NOTIFY_SOCKET is writable again, now send exactly one
         * message on it. Either it's the watchdog event, the initial
         * READY=1 event or an stdout stream event. If there's nothing
         * to write anymore, turn our event source off. The next time
         * there's something to send it will be turned on again. */

        if (!m->sent_notify_ready) {
                if (send(m->notify_fd, NOTIFY_READY_MESSAGE, strlen(NOTIFY_READY_MESSAGE), MSG_DONTWAIT) < 0) {
                        if (errno == EAGAIN)
                                return 0;

                        return log_error_errno(errno, "Failed to send READY=1 notification message: %m");
                }

                m->sent_notify_ready = true;
                log_debug("Sent READY=1 notification.");

        } else if (m->send_watchdog) {
                static const char p[] = "WATCHDOG=1";

                if (send(m->notify_fd, p, strlen(p), MSG_DONTWAIT) < 0) {
                        if (errno == EAGAIN)
                                return 0;

                        return log_error_errno(errno, "Failed to send WATCHDOG=1 notification message: %m");
                }

                m->send_watchdog = false;
                log_debug("Sent WATCHDOG=1 notification.");

        } else if (m->stdout_streams_notify_queue)
                /* Dispatch one stream notification event */
                stdout_stream_send_notify(m->stdout_streams_notify_queue);

        /* Leave us enabled if there's still more to do. */
        if (m->send_watchdog || m->stdout_streams_notify_queue)
                return 0;

        /* There was nothing to do anymore, let's turn ourselves off. */
        r = sd_event_source_set_enabled(es, SD_EVENT_OFF);
        if (r < 0)
                return log_error_errno(r, "Failed to turn off notify event source: %m");

        return 0;
}

static int dispatch_watchdog(sd_event_source *es, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        m->send_watchdog = true;

        r = sd_event_source_set_enabled(m->notify_event_source, SD_EVENT_ON);
        if (r < 0)
                log_warning_errno(r, "Failed to turn on notify event source: %m");

        r = sd_event_source_set_time(m->watchdog_event_source, usec + m->watchdog_usec / 2);
        if (r < 0)
                return log_error_errno(r, "Failed to restart watchdog event source: %m");

        r = sd_event_source_set_enabled(m->watchdog_event_source, SD_EVENT_ON);
        if (r < 0)
                return log_error_errno(r, "Failed to enable watchdog event source: %m");

        return 0;
}

static int manager_connect_notify(Manager *m) {
        union sockaddr_union sa;
        socklen_t sa_len;
        const char *e;
        int r;

        assert(m);
        assert(m->notify_fd < 0);
        assert(!m->notify_event_source);

        /*
         * So here's the problem: we'd like to send notification messages to PID 1, but we cannot do that via
         * sd_notify(), since that's synchronous, and we might end up blocking on it. Specifically: given
         * that PID 1 might block on dbus-daemon during IPC, and dbus-daemon is logging to us, and might
         * hence block on us, we might end up in a deadlock if we block on sending PID 1 notification
         * messages — by generating a full blocking circle. To avoid this, let's create a non-blocking
         * socket, and connect it to the notification socket, and then wait for POLLOUT before we send
         * anything. This should efficiently avoid any deadlocks, as we'll never block on PID 1, hence PID 1
         * can safely block on dbus-daemon which can safely block on us again.
         *
         * Don't think that this issue is real? It is, see: https://github.com/systemd/systemd/issues/1505
         */

        e = getenv("NOTIFY_SOCKET");
        if (!e)
                return 0;

        r = sockaddr_un_set_path(&sa.un, e);
        if (r < 0)
                return log_error_errno(r, "NOTIFY_SOCKET set to invalid value '%s': %m", e);
        sa_len = r;

        m->notify_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->notify_fd < 0)
                return log_error_errno(errno, "Failed to create notify socket: %m");

        (void) fd_inc_sndbuf(m->notify_fd, NOTIFY_SNDBUF_SIZE);

        r = connect(m->notify_fd, &sa.sa, sa_len);
        if (r < 0)
                return log_error_errno(errno, "Failed to connect to notify socket: %m");

        r = sd_event_add_io(m->event, &m->notify_event_source, m->notify_fd, EPOLLOUT, dispatch_notify_event, m);
        if (r < 0)
                return log_error_errno(r, "Failed to watch notification socket: %m");

        if (sd_watchdog_enabled(false, &m->watchdog_usec) > 0) {
                m->send_watchdog = true;

                r = sd_event_add_time_relative(m->event, &m->watchdog_event_source, CLOCK_MONOTONIC, m->watchdog_usec/2, m->watchdog_usec/4, dispatch_watchdog, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to add watchdog time event: %m");
        }

        /* This should fire pretty soon, which we'll use to send the READY=1 event. */

        return 0;
}

int manager_map_seqnum_file(
                Manager *m,
                const char *fname,
                size_t size,
                void **ret) {

        _cleanup_free_ char *fn = NULL;
        _cleanup_close_ int fd = -EBADF;
        uint64_t *p;
        int r;

        assert(m);
        assert(fname);
        assert(size > 0);
        assert(ret);

        fn = path_join(m->runtime_directory, fname);
        if (!fn)
                return -ENOMEM;

        fd = open(fn, O_RDWR|O_CREAT|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0644);
        if (fd < 0)
                return -errno;

        r = posix_fallocate_loop(fd, 0, size);
        if (r < 0)
                return r;

        p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED)
                return -errno;

        *ret = p;
        return 0;
}

void manager_unmap_seqnum_file(void *p, size_t size) {
        assert(size > 0);

        if (!p)
                return;

        assert_se(munmap(p, size) >= 0);
}

int manager_unlink_seqnum_file(Manager *m, const char *fname) {
        assert(m);
        assert(fname);

        _cleanup_free_ char *fn = path_join(m->runtime_directory, fname);
        if (!fn)
                return log_oom();

        if (unlink(fn) < 0 && errno != ENOENT)
                return log_warning_errno(errno, "Failed to remove '%s': %m", fname);

        return 0;
}

static bool manager_is_idle(Manager *m) {
        assert(m);

        /* The server for the main namespace is never idle */
        if (!m->namespace)
                return false;

        /* If a retention maximum is set larger than the idle time we need to be running to enforce it, hence
         * turn off the idle logic. */
        if (m->config.max_retention_usec > IDLE_TIMEOUT_USEC)
                return false;

        /* We aren't idle if we have a varlink client */
        if (sd_varlink_server_current_connections(m->varlink_server) > 0)
                return false;

        /* If we have stdout streams we aren't idle */
        if (m->n_stdout_streams > 0)
                return false;

        return true;
}

static int manager_idle_handler(sd_event_source *source, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(source);

        log_debug("Manager is idle, exiting.");
        sd_event_exit(m->event, 0);
        return 0;
}

int manager_start_or_stop_idle_timer(Manager *m) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
        int r;

        assert(m);

        if (sd_event_get_state(m->event) == SD_EVENT_FINISHED ||
            !manager_is_idle(m)) {
                m->idle_event_source = sd_event_source_disable_unref(m->idle_event_source);
                return 0;
        }

        if (m->idle_event_source)
                return 1;

        r = sd_event_add_time_relative(m->event, &source, CLOCK_MONOTONIC, IDLE_TIMEOUT_USEC, 0, manager_idle_handler, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate idle timer: %m");

        r = sd_event_source_set_priority(source, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                return log_error_errno(r, "Failed to set idle timer priority: %m");

        (void) sd_event_source_set_description(source, "idle-timer");

        m->idle_event_source = TAKE_PTR(source);
        return 1;
}

static int manager_refresh_idle_timer(Manager *m) {
        int r;

        assert(m);

        if (!m->idle_event_source)
                return 0;

        r = sd_event_source_set_time_relative(m->idle_event_source, IDLE_TIMEOUT_USEC);
        if (r < 0)
                return log_error_errno(r, "Failed to refresh idle timer: %m");

        return 1;
}

int manager_set_namespace(Manager *m, const char *namespace) {
        assert(m);

        if (!namespace)
                return 0;

        if (!log_namespace_name_valid(namespace))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified namespace name not valid, refusing: %s", namespace);

        m->namespace = strdup(namespace);
        if (!m->namespace)
                return log_oom();

        m->namespace_field = strjoin("_NAMESPACE=", namespace);
        if (!m->namespace_field)
                return log_oom();

        return 1;
}

static int manager_memory_pressure(sd_event_source *es, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        log_info("Under memory pressure, flushing caches.");

        /* Flushed the cached info we might have about client processes */
        client_context_flush_regular(m);

        /* Let's also close all user files (but keep the system/runtime one open) */
        for (;;) {
                JournalFile *first = ordered_hashmap_steal_first(m->user_journals);

                if (!first)
                        break;

                (void) journal_file_offline_close(first);
        }

        sd_event_trim_memory();

        return 0;
}

static int manager_setup_memory_pressure(Manager *m) {
        int r;

        assert(m);

        r = sd_event_add_memory_pressure(m->event, NULL, manager_memory_pressure, m);
        if (r < 0)
                log_full_errno(ERRNO_IS_NOT_SUPPORTED(r) || ERRNO_IS_PRIVILEGE(r) || (r == -EHOSTDOWN) ? LOG_DEBUG : LOG_NOTICE, r,
                               "Failed to install memory pressure event source, ignoring: %m");

        return 0;
}

void manager_reopen_journals(Manager *m, const JournalConfig *old) {
        assert(m);

        if (m->config.storage == old->storage &&
            m->config.compress.enabled == old->compress.enabled &&
            m->config.compress.threshold_bytes == old->compress.threshold_bytes &&
            m->config.seal == old->seal &&
            m->config.sync_interval_usec == old->sync_interval_usec &&
            journal_metrics_equal(&m->config.system_storage_metrics, &old->system_storage_metrics) &&
            journal_metrics_equal(&m->config.runtime_storage_metrics, &old->runtime_storage_metrics))
                return; /* no-op */

        /* Explicitly close the runtime journal to make it reopened later by manager_system_journal_open().
         * But only when volatile (or no) storage is requested. If auto or persistent storage is requested,
         * we may need to flush the runtime journal to the persistent storage, it will done through
         * manager_system_journal_open(). Hence, we should not touch the runtime journal here in that case. */
        if (IN_SET(m->config.storage, STORAGE_VOLATILE, STORAGE_NONE))
                m->runtime_journal = journal_file_offline_close(m->runtime_journal);

        /* Close other journals unconditionally to make the new settings applied. */
        m->system_journal = journal_file_offline_close(m->system_journal);
        ordered_hashmap_clear(m->user_journals);
        set_clear(m->deferred_closes);

        (void) manager_system_journal_open(m, /* flush_requested = */ false, /* relinquish_requested = */ false);

        /* To make the storage related settings applied, vacuum the storage. */
        cache_space_invalidate(&m->system_storage.space);
        cache_space_invalidate(&m->runtime_storage.space);
        manager_vacuum(m, /* verbose = */ false);
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .syslog_fd = -EBADF,
                .native_fd = -EBADF,
                .stdout_fd = -EBADF,
                .dev_kmsg_fd = -EBADF,
                .audit_fd = -EBADF,
                .hostname_fd = -EBADF,
                .notify_fd = -EBADF,
                .forward_socket_fd = -EBADF,

                .system_storage.name = "System Journal",
                .runtime_storage.name = "Runtime Journal",

                .watchdog_usec = USEC_INFINITY,

                .sync_scheduled = false,

                .kmsg_own_ratelimit = {
                        .interval = DEFAULT_KMSG_OWN_INTERVAL,
                        .burst = DEFAULT_KMSG_OWN_BURST,
                },

                .sigrtmin18_info.memory_pressure_handler = manager_memory_pressure,
                .sigrtmin18_info.memory_pressure_userdata = m,
        };

        journal_config_set_defaults(&m->config_by_conf);
        journal_config_set_defaults(&m->config_by_cred);
        journal_config_set_defaults(&m->config_by_cmdline);

        *ret = TAKE_PTR(m);
        return 0;
}

int manager_init(Manager *m) {
        const char *native_socket, *syslog_socket, *stdout_socket, *varlink_socket, *e;
        _cleanup_fdset_free_ FDSet *fds = NULL;
        int n, r, varlink_fd = -EBADF;
        bool no_sockets;

        assert(m);

        e = getenv("RUNTIME_DIRECTORY");
        if (e)
                m->runtime_directory = strdup(e);
        else if (m->namespace)
                m->runtime_directory = strjoin("/run/systemd/journal.", m->namespace);
        else
                m->runtime_directory = strdup("/run/systemd/journal");
        if (!m->runtime_directory)
                return log_oom();

        (void) mkdir_p(m->runtime_directory, 0755);

        m->user_journals = ordered_hashmap_new(&journal_file_hash_ops_offline_close);
        if (!m->user_journals)
                return log_oom();

        m->mmap = mmap_cache_new();
        if (!m->mmap)
                return log_oom();

        m->deferred_closes = set_new(&journal_file_hash_ops_offline_close);
        if (!m->deferred_closes)
                return log_oom();

        r = sd_event_default(&m->event);
        if (r < 0)
                return log_error_errno(r, "Failed to create event loop: %m");

        n = sd_listen_fds(true);
        if (n < 0)
                return log_error_errno(n, "Failed to read listening file descriptors from environment: %m");

        native_socket = strjoina(m->runtime_directory, "/socket");
        stdout_socket = strjoina(m->runtime_directory, "/stdout");
        syslog_socket = strjoina(m->runtime_directory, "/dev-log");
        varlink_socket = strjoina(m->runtime_directory, "/io.systemd.journal");

        for (int fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++)

                if (sd_is_socket_unix(fd, SOCK_DGRAM, -1, native_socket, 0) > 0) {

                        if (m->native_fd >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Too many native sockets passed.");

                        m->native_fd = fd;

                } else if (sd_is_socket_unix(fd, SOCK_STREAM, 1, stdout_socket, 0) > 0) {

                        if (m->stdout_fd >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Too many stdout sockets passed.");

                        m->stdout_fd = fd;

                } else if (sd_is_socket_unix(fd, SOCK_DGRAM, -1, syslog_socket, 0) > 0) {

                        if (m->syslog_fd >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Too many /dev/log sockets passed.");

                        m->syslog_fd = fd;

                } else if (sd_is_socket_unix(fd, SOCK_STREAM, 1, varlink_socket, 0) > 0) {

                        if (varlink_fd >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Too many varlink sockets passed.");

                        varlink_fd = fd;
                } else if (sd_is_socket(fd, AF_NETLINK, SOCK_RAW, -1) > 0) {

                        if (m->audit_fd >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Too many audit sockets passed.");

                        m->audit_fd = fd;

                } else {

                        if (!fds) {
                                fds = fdset_new();
                                if (!fds)
                                        return log_oom();
                        }

                        r = fdset_put(fds, fd);
                        if (r < 0)
                                return log_oom();
                }

        /* Try to restore streams, but don't bother if this fails */
        (void) manager_restore_streams(m, fds);

        if (!fdset_isempty(fds)) {
                log_warning("%u unknown file descriptors passed, closing.", fdset_size(fds));
                fds = fdset_free(fds);
        }

        no_sockets = m->native_fd < 0 && m->stdout_fd < 0 && m->syslog_fd < 0 && m->audit_fd < 0 && varlink_fd < 0;

        /* always open stdout, syslog, native, and kmsg sockets */

        /* systemd-journald.socket: /run/systemd/journal/stdout */
        r = manager_open_stdout_socket(m, stdout_socket);
        if (r < 0)
                return r;

        /* systemd-journald-dev-log.socket: /run/systemd/journal/dev-log */
        r = manager_open_syslog_socket(m, syslog_socket);
        if (r < 0)
                return r;

        /* systemd-journald.socket: /run/systemd/journal/socket */
        r = manager_open_native_socket(m, native_socket);
        if (r < 0)
                return r;

        /* /dev/kmsg */
        r = manager_open_dev_kmsg(m);
        if (r < 0)
                return r;

        /* Unless we got *some* sockets and not audit, open audit socket */
        if (m->audit_fd >= 0 || no_sockets) {
                log_info("Collecting audit messages is enabled.");

                r = manager_open_audit(m);
                if (r < 0)
                        return r;
        } else
                log_info("Collecting audit messages is disabled.");

        r = manager_open_varlink(m, varlink_socket, varlink_fd);
        if (r < 0)
                return r;

        r = manager_map_seqnum_file(m, "seqnum", sizeof(SeqnumData), (void**) &m->seqnum);
        if (r < 0)
                return log_error_errno(r, "Failed to map main seqnum file: %m");

        r = manager_open_kernel_seqnum(m);
        if (r < 0)
                return r;

        r = manager_open_hostname(m);
        if (r < 0)
                return r;

        r = manager_setup_signals(m);
        if (r < 0)
                return r;

        r = manager_setup_memory_pressure(m);
        if (r < 0)
                return r;

        r = cg_get_root_path(&m->cgroup_root);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire cgroup root path: %m");

        manager_cache_hostname(m);
        manager_cache_boot_id(m);
        manager_cache_machine_id(m);

        if (m->namespace)
                m->runtime_storage.path = strjoin("/run/log/journal/", MANAGER_MACHINE_ID(m), ".", m->namespace);
        else
                m->runtime_storage.path = strjoin("/run/log/journal/", MANAGER_MACHINE_ID(m));
        if (!m->runtime_storage.path)
                return log_oom();

        e = getenv("LOGS_DIRECTORY");
        if (e)
                m->system_storage.path = strdup(e);
        else if (m->namespace)
                m->system_storage.path = strjoin("/var/log/journal/", MANAGER_MACHINE_ID(m), ".", m->namespace);
        else
                m->system_storage.path = strjoin("/var/log/journal/", MANAGER_MACHINE_ID(m));
        if (!m->system_storage.path)
                return log_oom();

        (void) manager_connect_notify(m);

        (void) client_context_acquire_default(m);

        r = manager_system_journal_open(m, /* flush_requested= */ false, /* relinquish_requested= */ false);
        if (r < 0)
                return r;

        manager_start_or_stop_idle_timer(m);

        return 0;
}

void manager_maybe_append_tags(Manager *m) {
#if HAVE_GCRYPT
        JournalFile *f;
        usec_t n;

        n = now(CLOCK_REALTIME);

        if (m->system_journal)
                journal_file_maybe_append_tag(m->system_journal, n);

        ORDERED_HASHMAP_FOREACH(f, m->user_journals)
                journal_file_maybe_append_tag(f, n);
#endif
}

Manager* manager_free(Manager *m) {
        if (!m)
                return NULL;

        free(m->namespace);
        free(m->namespace_field);

        set_free(m->deferred_closes);

        while (m->stdout_streams)
                stdout_stream_free(m->stdout_streams);

        client_context_flush_all(m);

        (void) journal_file_offline_close(m->system_journal);
        (void) journal_file_offline_close(m->runtime_journal);

        ordered_hashmap_free(m->user_journals);

        sd_varlink_server_unref(m->varlink_server);

        sd_event_source_unref(m->syslog_event_source);
        sd_event_source_unref(m->native_event_source);
        sd_event_source_unref(m->stdout_event_source);
        sd_event_source_unref(m->dev_kmsg_event_source);
        sd_event_source_unref(m->audit_event_source);
        sd_event_source_unref(m->sync_event_source);
        sd_event_source_unref(m->sigusr1_event_source);
        sd_event_source_unref(m->sigusr2_event_source);
        sd_event_source_unref(m->sigterm_event_source);
        sd_event_source_unref(m->sigint_event_source);
        sd_event_source_unref(m->sigrtmin1_event_source);
        sd_event_source_unref(m->hostname_event_source);
        sd_event_source_unref(m->notify_event_source);
        sd_event_source_unref(m->watchdog_event_source);
        sd_event_source_unref(m->idle_event_source);
        sd_event_unref(m->event);

        safe_close(m->syslog_fd);
        safe_close(m->native_fd);
        safe_close(m->stdout_fd);
        safe_close(m->dev_kmsg_fd);
        safe_close(m->audit_fd);
        safe_close(m->hostname_fd);
        safe_close(m->notify_fd);
        safe_close(m->forward_socket_fd);

        ordered_hashmap_free(m->ratelimit_groups_by_id);

        manager_unmap_seqnum_file(m->seqnum, sizeof(*m->seqnum));
        manager_close_kernel_seqnum(m);

        free(m->buffer);
        free(m->cgroup_root);
        free(m->hostname_field);
        free(m->runtime_storage.path);
        free(m->system_storage.path);
        free(m->runtime_directory);

        mmap_cache_unref(m->mmap);

        SyncReq *req;
        while ((req = prioq_peek(m->sync_req_realtime_prioq)))
                sync_req_free(req);
        prioq_free(m->sync_req_realtime_prioq);

        while ((req = prioq_peek(m->sync_req_boottime_prioq)))
                sync_req_free(req);
        prioq_free(m->sync_req_boottime_prioq);

        journal_config_done(&m->config);
        journal_config_done(&m->config_by_cred);
        journal_config_done(&m->config_by_conf);
        journal_config_done(&m->config_by_cmdline);

        return mfree(m);
}
