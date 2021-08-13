/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/statvfs.h>
#include <linux/sockios.h>

#include "sd-daemon.h"
#include "sd-journal.h"
#include "sd-messages.h"

#include "acl-util.h"
#include "alloc-util.h"
#include "audit-util.h"
#include "cgroup-util.h"
#include "conf-parser.h"
#include "dirent-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "io-util.h"
#include "journal-authenticate.h"
#include "journal-file.h"
#include "journal-internal.h"
#include "journal-vacuum.h"
#include "journald-audit.h"
#include "journald-context.h"
#include "journald-kmsg.h"
#include "journald-native.h"
#include "journald-rate-limit.h"
#include "journald-server.h"
#include "journald-stream.h"
#include "journald-syslog.h"
#include "log.h"
#include "missing_audit.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "rm-rf.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "syslog-util.h"
#include "user-record.h"
#include "user-util.h"

#define USER_JOURNALS_MAX 1024

#define DEFAULT_SYNC_INTERVAL_USEC (5*USEC_PER_MINUTE)
#define DEFAULT_RATE_LIMIT_INTERVAL (30*USEC_PER_SEC)
#define DEFAULT_RATE_LIMIT_BURST 10000
#define DEFAULT_MAX_FILE_USEC USEC_PER_MONTH

#define RECHECK_SPACE_USEC (30*USEC_PER_SEC)

#define NOTIFY_SNDBUF_SIZE (8*1024*1024)

/* The period to insert between posting changes for coalescing */
#define POST_CHANGE_TIMER_INTERVAL_USEC (250*USEC_PER_MSEC)

/* Pick a good default that is likely to fit into AF_UNIX and AF_INET SOCK_DGRAM datagrams, and even leaves some room
 * for a bit of additional metadata. */
#define DEFAULT_LINE_MAX (48*1024)

#define DEFERRED_CLOSES_MAX (4096)

#define IDLE_TIMEOUT_USEC (30*USEC_PER_SEC)

static int determine_path_usage(
                Server *s,
                const char *path,
                uint64_t *ret_used,
                uint64_t *ret_free) {

        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        struct statvfs ss;

        assert(s);
        assert(path);
        assert(ret_used);
        assert(ret_free);

        d = opendir(path);
        if (!d)
                return log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR,
                                      errno, "Failed to open %s: %m", path);

        if (fstatvfs(dirfd(d), &ss) < 0)
                return log_error_errno(errno, "Failed to fstatvfs(%s): %m", path);

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

static int cache_space_refresh(Server *s, JournalStorage *storage) {
        JournalStorageSpace *space;
        JournalMetrics *metrics;
        uint64_t vfs_used, vfs_avail, avail;
        usec_t ts;
        int r;

        assert(s);

        metrics = &storage->metrics;
        space = &storage->space;

        ts = now(CLOCK_MONOTONIC);

        if (space->timestamp != 0 && usec_add(space->timestamp, RECHECK_SPACE_USEC) > ts)
                return 0;

        r = determine_path_usage(s, storage->path, &vfs_used, &vfs_avail);
        if (r < 0)
                return r;

        space->vfs_used = vfs_used;
        space->vfs_available = vfs_avail;

        avail = LESS_BY(vfs_avail, metrics->keep_free);

        space->limit = MIN(MAX(vfs_used + avail, metrics->min_use), metrics->max_use);
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

static JournalStorage* server_current_storage(Server *s) {
        assert(s);

        return s->system_journal ? &s->system_storage : &s->runtime_storage;
}

static int determine_space(Server *s, uint64_t *available, uint64_t *limit) {
        JournalStorage *js;
        int r;

        assert(s);

        js = server_current_storage(s);

        r = cache_space_refresh(s, js);
        if (r >= 0) {
                if (available)
                        *available = js->space.available;
                if (limit)
                        *limit = js->space.limit;
        }
        return r;
}

void server_space_usage_message(Server *s, JournalStorage *storage) {
        char fb1[FORMAT_BYTES_MAX], fb2[FORMAT_BYTES_MAX], fb3[FORMAT_BYTES_MAX],
             fb4[FORMAT_BYTES_MAX], fb5[FORMAT_BYTES_MAX], fb6[FORMAT_BYTES_MAX];
        JournalMetrics *metrics;

        assert(s);

        if (!storage)
                storage = server_current_storage(s);

        if (cache_space_refresh(s, storage) < 0)
                return;

        metrics = &storage->metrics;
        format_bytes(fb1, sizeof(fb1), storage->space.vfs_used);
        format_bytes(fb2, sizeof(fb2), metrics->max_use);
        format_bytes(fb3, sizeof(fb3), metrics->keep_free);
        format_bytes(fb4, sizeof(fb4), storage->space.vfs_available);
        format_bytes(fb5, sizeof(fb5), storage->space.limit);
        format_bytes(fb6, sizeof(fb6), storage->space.available);

        server_driver_message(s, 0,
                              "MESSAGE_ID=" SD_MESSAGE_JOURNAL_USAGE_STR,
                              LOG_MESSAGE("%s (%s) is %s, max %s, %s free.",
                                          storage->name, storage->path, fb1, fb5, fb6),
                              "JOURNAL_NAME=%s", storage->name,
                              "JOURNAL_PATH=%s", storage->path,
                              "CURRENT_USE=%"PRIu64, storage->space.vfs_used,
                              "CURRENT_USE_PRETTY=%s", fb1,
                              "MAX_USE=%"PRIu64, metrics->max_use,
                              "MAX_USE_PRETTY=%s", fb2,
                              "DISK_KEEP_FREE=%"PRIu64, metrics->keep_free,
                              "DISK_KEEP_FREE_PRETTY=%s", fb3,
                              "DISK_AVAILABLE=%"PRIu64, storage->space.vfs_available,
                              "DISK_AVAILABLE_PRETTY=%s", fb4,
                              "LIMIT=%"PRIu64, storage->space.limit,
                              "LIMIT_PRETTY=%s", fb5,
                              "AVAILABLE=%"PRIu64, storage->space.available,
                              "AVAILABLE_PRETTY=%s", fb6,
                              NULL);
}

static bool uid_for_system_journal(uid_t uid) {

        /* Returns true if the specified UID shall get its data stored in the system journal. */

        return uid_is_system(uid) || uid_is_dynamic(uid) || uid == UID_NOBODY;
}

static void server_add_acls(JournalFile *f, uid_t uid) {
        assert(f);

#if HAVE_ACL
        int r;

        if (uid_for_system_journal(uid))
                return;

        r = fd_add_uid_acl_permission(f->fd, uid, ACL_READ);
        if (r < 0)
                log_warning_errno(r, "Failed to set ACL on %s, ignoring: %m", f->path);
#endif
}

static int open_journal(
                Server *s,
                bool reliably,
                const char *fname,
                int flags,
                bool seal,
                JournalMetrics *metrics,
                JournalFile **ret) {

        _cleanup_(journal_file_closep) JournalFile *f = NULL;
        int r;

        assert(s);
        assert(fname);
        assert(ret);

        if (reliably)
                r = journal_file_open_reliably(fname, flags, 0640, s->compress.enabled, s->compress.threshold_bytes,
                                               seal, metrics, s->mmap, s->deferred_closes, NULL, &f);
        else
                r = journal_file_open(-1, fname, flags, 0640, s->compress.enabled, s->compress.threshold_bytes, seal,
                                      metrics, s->mmap, s->deferred_closes, NULL, &f);

        if (r < 0)
                return r;

        r = journal_file_enable_post_change_timer(f, s->event, POST_CHANGE_TIMER_INTERVAL_USEC);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return r;
}

static bool flushed_flag_is_set(Server *s) {
        const char *fn;

        assert(s);

        /* We don't support the "flushing" concept for namespace instances, we assume them to always have
         * access to /var */
        if (s->namespace)
                return true;

        fn = strjoina(s->runtime_directory, "/flushed");
        return access(fn, F_OK) >= 0;
}

static int system_journal_open(Server *s, bool flush_requested, bool relinquish_requested) {
        const char *fn;
        int r = 0;

        if (!s->system_journal &&
            IN_SET(s->storage, STORAGE_PERSISTENT, STORAGE_AUTO) &&
            (flush_requested || flushed_flag_is_set(s)) &&
            !relinquish_requested) {

                /* If in auto mode: first try to create the machine path, but not the prefix.
                 *
                 * If in persistent mode: create /var/log/journal and the machine path */

                if (s->storage == STORAGE_PERSISTENT)
                        (void) mkdir_parents(s->system_storage.path, 0755);

                (void) mkdir(s->system_storage.path, 0755);

                fn = strjoina(s->system_storage.path, "/system.journal");
                r = open_journal(s, true, fn, O_RDWR|O_CREAT, s->seal, &s->system_storage.metrics, &s->system_journal);
                if (r >= 0) {
                        server_add_acls(s->system_journal, 0);
                        (void) cache_space_refresh(s, &s->system_storage);
                        patch_min_use(&s->system_storage);
                } else {
                        if (!IN_SET(r, -ENOENT, -EROFS))
                                log_warning_errno(r, "Failed to open system journal: %m");

                        r = 0;
                }

                /* If the runtime journal is open, and we're post-flush, we're recovering from a failed
                 * system journal rotate (ENOSPC) for which the runtime journal was reopened.
                 *
                 * Perform an implicit flush to var, leaving the runtime journal closed, now that the system
                 * journal is back.
                 */
                if (!flush_requested)
                        (void) server_flush_to_var(s, true);
        }

        if (!s->runtime_journal &&
            (s->storage != STORAGE_NONE)) {

                fn = strjoina(s->runtime_storage.path, "/system.journal");

                if (s->system_journal && !relinquish_requested) {

                        /* Try to open the runtime journal, but only
                         * if it already exists, so that we can flush
                         * it into the system journal */

                        r = open_journal(s, false, fn, O_RDWR, false, &s->runtime_storage.metrics, &s->runtime_journal);
                        if (r < 0) {
                                if (r != -ENOENT)
                                        log_warning_errno(r, "Failed to open runtime journal: %m");

                                r = 0;
                        }

                } else {

                        /* OK, we really need the runtime journal, so create it if necessary. */

                        (void) mkdir_parents(s->runtime_storage.path, 0755);
                        (void) mkdir(s->runtime_storage.path, 0750);

                        r = open_journal(s, true, fn, O_RDWR|O_CREAT, false, &s->runtime_storage.metrics, &s->runtime_journal);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open runtime journal: %m");
                }

                if (s->runtime_journal) {
                        server_add_acls(s->runtime_journal, 0);
                        (void) cache_space_refresh(s, &s->runtime_storage);
                        patch_min_use(&s->runtime_storage);
                }
        }

        return r;
}

static JournalFile* find_journal(Server *s, uid_t uid) {
        _cleanup_free_ char *p = NULL;
        JournalFile *f;
        int r;

        assert(s);

        /* A rotate that fails to create the new journal (ENOSPC) leaves the rotated journal as NULL.  Unless
         * we revisit opening, even after space is made available we'll continue to return NULL indefinitely.
         *
         * system_journal_open() is a noop if the journals are already open, so we can just call it here to
         * recover from failed rotates (or anything else that's left the journals as NULL).
         *
         * Fixes https://github.com/systemd/systemd/issues/3968 */
        (void) system_journal_open(s, false, false);

        /* We split up user logs only on /var, not on /run. If the runtime file is open, we write to it
         * exclusively, in order to guarantee proper order as soon as we flush /run to /var and close the
         * runtime file. */

        if (s->runtime_journal)
                return s->runtime_journal;

        /* If we are not in persistent mode, then we need return NULL immediately rather than opening a
         * persistent journal of any sort.
         *
         * Fixes https://github.com/systemd/systemd/issues/20390 */
        if (!IN_SET(s->storage, STORAGE_AUTO, STORAGE_PERSISTENT))
                return NULL;

        if (uid_for_system_journal(uid))
                return s->system_journal;

        f = ordered_hashmap_get(s->user_journals, UID_TO_PTR(uid));
        if (f)
                return f;

        if (asprintf(&p, "%s/user-" UID_FMT ".journal", s->system_storage.path, uid) < 0) {
                log_oom();
                return s->system_journal;
        }

        /* Too many open? Then let's close one (or more) */
        while (ordered_hashmap_size(s->user_journals) >= USER_JOURNALS_MAX) {
                assert_se(f = ordered_hashmap_steal_first(s->user_journals));
                (void) journal_file_close(f);
        }

        r = open_journal(s, true, p, O_RDWR|O_CREAT, s->seal, &s->system_storage.metrics, &f);
        if (r < 0)
                return s->system_journal;

        r = ordered_hashmap_put(s->user_journals, UID_TO_PTR(uid), f);
        if (r < 0) {
                (void) journal_file_close(f);
                return s->system_journal;
        }

        server_add_acls(f, uid);
        return f;
}

static int do_rotate(
                Server *s,
                JournalFile **f,
                const char* name,
                bool seal,
                uint32_t uid) {

        int r;
        assert(s);

        if (!*f)
                return -EINVAL;

        r = journal_file_rotate(f, s->compress.enabled, s->compress.threshold_bytes, seal, s->deferred_closes);
        if (r < 0) {
                if (*f)
                        return log_error_errno(r, "Failed to rotate %s: %m", (*f)->path);
                else
                        return log_error_errno(r, "Failed to create new %s journal: %m", name);
        }

        server_add_acls(*f, uid);
        return r;
}

static void server_process_deferred_closes(Server *s) {
        JournalFile *f;

        /* Perform any deferred closes which aren't still offlining. */
        SET_FOREACH(f, s->deferred_closes) {
                if (journal_file_is_offlining(f))
                        continue;

                (void) set_remove(s->deferred_closes, f);
                (void) journal_file_close(f);
        }
}

static void server_vacuum_deferred_closes(Server *s) {
        assert(s);

        /* Make some room in the deferred closes list, so that it doesn't grow without bounds */
        if (set_size(s->deferred_closes) < DEFERRED_CLOSES_MAX)
                return;

        /* Let's first remove all journal files that might already have completed closing */
        server_process_deferred_closes(s);

        /* And now, let's close some more until we reach the limit again. */
        while (set_size(s->deferred_closes) >= DEFERRED_CLOSES_MAX) {
                JournalFile *f;

                assert_se(f = set_steal_first(s->deferred_closes));
                journal_file_close(f);
        }
}

static int vacuum_offline_user_journals(Server *s) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(s);

        d = opendir(s->system_storage.path);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", s->system_storage.path);
        }

        for (;;) {
                _cleanup_free_ char *u = NULL, *full = NULL;
                _cleanup_close_ int fd = -1;
                const char *a, *b;
                struct dirent *de;
                JournalFile *f;
                uid_t uid;

                errno = 0;
                de = readdir_no_dot(d);
                if (!de) {
                        if (errno != 0)
                                log_warning_errno(errno, "Failed to enumerate %s, ignoring: %m", s->system_storage.path);

                        break;
                }

                a = startswith(de->d_name, "user-");
                if (!a)
                        continue;
                b = endswith(de->d_name, ".journal");
                if (!b)
                        continue;

                u = strndup(a, b-a);
                if (!u)
                        return log_oom();

                r = parse_uid(u, &uid);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse UID from file name '%s', ignoring: %m", de->d_name);
                        continue;
                }

                /* Already rotated in the above loop? i.e. is it an open user journal? */
                if (ordered_hashmap_contains(s->user_journals, UID_TO_PTR(uid)))
                        continue;

                full = path_join(s->system_storage.path, de->d_name);
                if (!full)
                        return log_oom();

                fd = openat(dirfd(d), de->d_name, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW|O_NONBLOCK);
                if (fd < 0) {
                        log_full_errno(IN_SET(errno, ELOOP, ENOENT) ? LOG_DEBUG : LOG_WARNING, errno,
                                       "Failed to open journal file '%s' for rotation: %m", full);
                        continue;
                }

                /* Make some room in the set of deferred close()s */
                server_vacuum_deferred_closes(s);

                /* Open the file briefly, so that we can archive it */
                r = journal_file_open(fd,
                                      full,
                                      O_RDWR,
                                      0640,
                                      s->compress.enabled,
                                      s->compress.threshold_bytes,
                                      s->seal,
                                      &s->system_storage.metrics,
                                      s->mmap,
                                      s->deferred_closes,
                                      NULL,
                                      &f);
                if (r < 0) {
                        log_warning_errno(r, "Failed to read journal file %s for rotation, trying to move it out of the way: %m", full);

                        r = journal_file_dispose(dirfd(d), de->d_name);
                        if (r < 0)
                                log_warning_errno(r, "Failed to move %s out of the way, ignoring: %m", full);
                        else
                                log_debug("Successfully moved %s out of the way.", full);

                        continue;
                }

                TAKE_FD(fd); /* Donated to journal_file_open() */

                r = journal_file_archive(f);
                if (r < 0)
                        log_debug_errno(r, "Failed to archive journal file '%s', ignoring: %m", full);

                f = journal_initiate_close(f, s->deferred_closes);
        }

        return 0;
}

void server_rotate(Server *s) {
        JournalFile *f;
        void *k;
        int r;

        log_debug("Rotating...");

        /* First, rotate the system journal (either in its runtime flavour or in its runtime flavour) */
        (void) do_rotate(s, &s->runtime_journal, "runtime", false, 0);
        (void) do_rotate(s, &s->system_journal, "system", s->seal, 0);

        /* Then, rotate all user journals we have open (keeping them open) */
        ORDERED_HASHMAP_FOREACH_KEY(f, k, s->user_journals) {
                r = do_rotate(s, &f, "user", s->seal, PTR_TO_UID(k));
                if (r >= 0)
                        ordered_hashmap_replace(s->user_journals, k, f);
                else if (!f)
                        /* Old file has been closed and deallocated */
                        ordered_hashmap_remove(s->user_journals, k);
        }

        /* Finally, also rotate all user journals we currently do not have open. (But do so only if we
         * actually have access to /var, i.e. are not in the log-to-runtime-journal mode). */
        if (!s->runtime_journal)
                (void) vacuum_offline_user_journals(s);

        server_process_deferred_closes(s);
}

void server_sync(Server *s) {
        JournalFile *f;
        int r;

        if (s->system_journal) {
                r = journal_file_set_offline(s->system_journal, false);
                if (r < 0)
                        log_warning_errno(r, "Failed to sync system journal, ignoring: %m");
        }

        ORDERED_HASHMAP_FOREACH(f, s->user_journals) {
                r = journal_file_set_offline(f, false);
                if (r < 0)
                        log_warning_errno(r, "Failed to sync user journal, ignoring: %m");
        }

        if (s->sync_event_source) {
                r = sd_event_source_set_enabled(s->sync_event_source, SD_EVENT_OFF);
                if (r < 0)
                        log_error_errno(r, "Failed to disable sync timer source: %m");
        }

        s->sync_scheduled = false;
}

static void do_vacuum(Server *s, JournalStorage *storage, bool verbose) {

        int r;

        assert(s);
        assert(storage);

        (void) cache_space_refresh(s, storage);

        if (verbose)
                server_space_usage_message(s, storage);

        r = journal_directory_vacuum(storage->path, storage->space.limit,
                                     storage->metrics.n_max_files, s->max_retention_usec,
                                     &s->oldest_file_usec, verbose);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to vacuum %s, ignoring: %m", storage->path);

        cache_space_invalidate(&storage->space);
}

int server_vacuum(Server *s, bool verbose) {
        assert(s);

        log_debug("Vacuuming...");

        s->oldest_file_usec = 0;

        if (s->system_journal)
                do_vacuum(s, &s->system_storage, verbose);
        if (s->runtime_journal)
                do_vacuum(s, &s->runtime_storage, verbose);

        return 0;
}

static void server_cache_machine_id(Server *s) {
        sd_id128_t id;
        int r;

        assert(s);

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return;

        sd_id128_to_string(id, stpcpy(s->machine_id_field, "_MACHINE_ID="));
}

static void server_cache_boot_id(Server *s) {
        sd_id128_t id;
        int r;

        assert(s);

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return;

        sd_id128_to_string(id, stpcpy(s->boot_id_field, "_BOOT_ID="));
}

static void server_cache_hostname(Server *s) {
        _cleanup_free_ char *t = NULL;
        char *x;

        assert(s);

        t = gethostname_malloc();
        if (!t)
                return;

        x = strjoin("_HOSTNAME=", t);
        if (!x)
                return;

        free_and_replace(s->hostname_field, x);
}

static bool shall_try_append_again(JournalFile *f, int r) {
        switch(r) {

        case -E2BIG:           /* Hit configured limit          */
        case -EFBIG:           /* Hit fs limit                  */
        case -EDQUOT:          /* Quota limit hit               */
        case -ENOSPC:          /* Disk full                     */
                log_debug("%s: Allocation limit reached, rotating.", f->path);
                return true;

        case -EIO:             /* I/O error of some kind (mmap) */
                log_warning("%s: IO error, rotating.", f->path);
                return true;

        case -EHOSTDOWN:       /* Other machine                 */
                log_info("%s: Journal file from other machine, rotating.", f->path);
                return true;

        case -EBUSY:           /* Unclean shutdown              */
                log_info("%s: Unclean shutdown, rotating.", f->path);
                return true;

        case -EPROTONOSUPPORT: /* Unsupported feature           */
                log_info("%s: Unsupported feature, rotating.", f->path);
                return true;

        case -EBADMSG:         /* Corrupted                     */
        case -ENODATA:         /* Truncated                     */
        case -ESHUTDOWN:       /* Already archived              */
                log_warning("%s: Journal file corrupted, rotating.", f->path);
                return true;

        case -EIDRM:           /* Journal file has been deleted */
                log_warning("%s: Journal file has been deleted, rotating.", f->path);
                return true;

        case -ETXTBSY:         /* Journal file is from the future */
                log_warning("%s: Journal file is from the future, rotating.", f->path);
                return true;

        case -EAFNOSUPPORT:
                log_warning("%s: underlying file system does not support memory mapping or another required file system feature.", f->path);
                return false;

        default:
                return false;
        }
}

static void write_to_journal(Server *s, uid_t uid, struct iovec *iovec, size_t n, int priority) {
        bool vacuumed = false, rotate = false;
        struct dual_timestamp ts;
        JournalFile *f;
        int r;

        assert(s);
        assert(iovec);
        assert(n > 0);

        /* Get the closest, linearized time we have for this log event from the event loop. (Note that we do not use
         * the source time, and not even the time the event was originally seen, but instead simply the time we started
         * processing it, as we want strictly linear ordering in what we write out.) */
        assert_se(sd_event_now(s->event, CLOCK_REALTIME, &ts.realtime) >= 0);
        assert_se(sd_event_now(s->event, CLOCK_MONOTONIC, &ts.monotonic) >= 0);

        if (ts.realtime < s->last_realtime_clock) {
                /* When the time jumps backwards, let's immediately rotate. Of course, this should not happen during
                 * regular operation. However, when it does happen, then we should make sure that we start fresh files
                 * to ensure that the entries in the journal files are strictly ordered by time, in order to ensure
                 * bisection works correctly. */

                log_debug("Time jumped backwards, rotating.");
                rotate = true;
        } else {

                f = find_journal(s, uid);
                if (!f)
                        return;

                if (journal_file_rotate_suggested(f, s->max_file_usec)) {
                        log_debug("%s: Journal header limits reached or header out-of-date, rotating.", f->path);
                        rotate = true;
                }
        }

        if (rotate) {
                server_rotate(s);
                server_vacuum(s, false);
                vacuumed = true;

                f = find_journal(s, uid);
                if (!f)
                        return;
        }

        s->last_realtime_clock = ts.realtime;

        r = journal_file_append_entry(f, &ts, NULL, iovec, n, &s->seqnum, NULL, NULL);
        if (r >= 0) {
                server_schedule_sync(s, priority);
                return;
        }

        if (vacuumed || !shall_try_append_again(f, r)) {
                log_error_errno(r, "Failed to write entry (%zu items, %zu bytes), ignoring: %m", n, IOVEC_TOTAL_SIZE(iovec, n));
                return;
        }

        server_rotate(s);
        server_vacuum(s, false);

        f = find_journal(s, uid);
        if (!f)
                return;

        log_debug("Retrying write.");
        r = journal_file_append_entry(f, &ts, NULL, iovec, n, &s->seqnum, NULL, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to write entry (%zu items, %zu bytes) despite vacuuming, ignoring: %m", n, IOVEC_TOTAL_SIZE(iovec, n));
        else
                server_schedule_sync(s, priority);
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

#define IOVEC_ADD_SIZED_FIELD(iovec, n, value, value_size, field)       \
        if (value_size > 0) {                                           \
                char *k;                                                \
                k = newa(char, STRLEN(field "=") + value_size + 1);     \
                *((char*) mempcpy(stpcpy(k, field "="), value, value_size)) = 0; \
                iovec[n++] = IOVEC_MAKE_STRING(k);                      \
        }                                                               \

static void dispatch_message_real(
                Server *s,
                struct iovec *iovec, size_t n, size_t m,
                const ClientContext *c,
                const struct timeval *tv,
                int priority,
                pid_t object_pid) {

        char source_time[sizeof("_SOURCE_REALTIME_TIMESTAMP=") + DECIMAL_STR_MAX(usec_t)];
        _cleanup_free_ char *cmdline1 = NULL, *cmdline2 = NULL;
        uid_t journal_uid;
        ClientContext *o;

        assert(s);
        assert(iovec);
        assert(n > 0);
        assert(n +
               N_IOVEC_META_FIELDS +
               (pid_is_valid(object_pid) ? N_IOVEC_OBJECT_FIELDS : 0) +
               client_context_extra_fields_n_iovec(c) <= m);

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

                IOVEC_ADD_STRING_FIELD(iovec, n, c->capeff, "_CAP_EFFECTIVE"); /* Read from /proc/.../status */
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

        assert(n <= m);

        if (pid_is_valid(object_pid) && client_context_get(s, object_pid, NULL, NULL, 0, NULL, &o) >= 0) {

                IOVEC_ADD_NUMERIC_FIELD(iovec, n, o->pid, pid_t, pid_is_valid, PID_FMT, "OBJECT_PID");
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, o->uid, uid_t, uid_is_valid, UID_FMT, "OBJECT_UID");
                IOVEC_ADD_NUMERIC_FIELD(iovec, n, o->gid, gid_t, gid_is_valid, GID_FMT, "OBJECT_GID");

                /* See above for size limits, only ->cmdline may be large, so use a heap allocation for it. */
                IOVEC_ADD_STRING_FIELD(iovec, n, o->comm, "OBJECT_COMM");
                IOVEC_ADD_STRING_FIELD(iovec, n, o->exe, "OBJECT_EXE");
                if (o->cmdline)
                        cmdline2 = set_iovec_string_field(iovec, &n, "OBJECT_CMDLINE=", o->cmdline);

                IOVEC_ADD_STRING_FIELD(iovec, n, o->capeff, "OBJECT_CAP_EFFECTIVE");
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

                IOVEC_ADD_ID128_FIELD(iovec, n, o->invocation_id, "OBJECT_SYSTEMD_INVOCATION_ID=");
        }

        assert(n <= m);

        if (tv) {
                sprintf(source_time, "_SOURCE_REALTIME_TIMESTAMP=" USEC_FMT, timeval_load(tv));
                iovec[n++] = IOVEC_MAKE_STRING(source_time);
        }

        /* Note that strictly speaking storing the boot id here is
         * redundant since the entry includes this in-line
         * anyway. However, we need this indexed, too. */
        if (!isempty(s->boot_id_field))
                iovec[n++] = IOVEC_MAKE_STRING(s->boot_id_field);

        if (!isempty(s->machine_id_field))
                iovec[n++] = IOVEC_MAKE_STRING(s->machine_id_field);

        if (!isempty(s->hostname_field))
                iovec[n++] = IOVEC_MAKE_STRING(s->hostname_field);

        if (!isempty(s->namespace_field))
                iovec[n++] = IOVEC_MAKE_STRING(s->namespace_field);

        assert(n <= m);

        if (s->split_mode == SPLIT_UID && c && uid_is_valid(c->uid))
                /* Split up strictly by (non-root) UID */
                journal_uid = c->uid;
        else if (s->split_mode == SPLIT_LOGIN && c && c->uid > 0 && uid_is_valid(c->owner_uid))
                /* Split up by login UIDs.  We do this only if the
                 * realuid is not root, in order not to accidentally
                 * leak privileged information to the user that is
                 * logged by a privileged process that is part of an
                 * unprivileged session. */
                journal_uid = c->owner_uid;
        else
                journal_uid = 0;

        write_to_journal(s, journal_uid, iovec, n, priority);
}

void server_driver_message(Server *s, pid_t object_pid, const char *message_id, const char *format, ...) {

        struct iovec *iovec;
        size_t n = 0, k, m;
        va_list ap;
        int r;

        assert(s);
        assert(format);

        m = N_IOVEC_META_FIELDS + 5 + N_IOVEC_PAYLOAD_FIELDS + client_context_extra_fields_n_iovec(s->my_context) + N_IOVEC_OBJECT_FIELDS;
        iovec = newa(struct iovec, m);

        assert_cc(3 == LOG_FAC(LOG_DAEMON));
        iovec[n++] = IOVEC_MAKE_STRING("SYSLOG_FACILITY=3");
        iovec[n++] = IOVEC_MAKE_STRING("SYSLOG_IDENTIFIER=systemd-journald");

        iovec[n++] = IOVEC_MAKE_STRING("_TRANSPORT=driver");
        assert_cc(6 == LOG_INFO);
        iovec[n++] = IOVEC_MAKE_STRING("PRIORITY=6");

        if (message_id)
                iovec[n++] = IOVEC_MAKE_STRING(message_id);
        k = n;

        va_start(ap, format);
        r = log_format_iovec(iovec, m, &n, false, 0, format, ap);
        /* Error handling below */
        va_end(ap);

        if (r >= 0)
                dispatch_message_real(s, iovec, n, m, s->my_context, NULL, LOG_INFO, object_pid);

        while (k < n)
                free(iovec[k++].iov_base);

        if (r < 0) {
                /* We failed to format the message. Emit a warning instead. */
                char buf[LINE_MAX];

                xsprintf(buf, "MESSAGE=Entry printing failed: %s", strerror_safe(r));

                n = 3;
                iovec[n++] = IOVEC_MAKE_STRING("PRIORITY=4");
                iovec[n++] = IOVEC_MAKE_STRING(buf);
                dispatch_message_real(s, iovec, n, m, s->my_context, NULL, LOG_INFO, object_pid);
        }
}

void server_dispatch_message(
                Server *s,
                struct iovec *iovec, size_t n, size_t m,
                ClientContext *c,
                const struct timeval *tv,
                int priority,
                pid_t object_pid) {

        uint64_t available = 0;
        int rl;

        assert(s);
        assert(iovec || n == 0);

        if (n == 0)
                return;

        if (LOG_PRI(priority) > s->max_level_store)
                return;

        /* Stop early in case the information will not be stored
         * in a journal. */
        if (s->storage == STORAGE_NONE)
                return;

        if (c && c->unit) {
                (void) determine_space(s, &available, NULL);

                rl = journal_ratelimit_test(s->ratelimit, c->unit, c->log_ratelimit_interval, c->log_ratelimit_burst, priority & LOG_PRIMASK, available);
                if (rl == 0)
                        return;

                /* Write a suppression message if we suppressed something */
                if (rl > 1)
                        server_driver_message(s, c->pid,
                                              "MESSAGE_ID=" SD_MESSAGE_JOURNAL_DROPPED_STR,
                                              LOG_MESSAGE("Suppressed %i messages from %s", rl - 1, c->unit),
                                              "N_DROPPED=%i", rl - 1,
                                              NULL);
        }

        dispatch_message_real(s, iovec, n, m, c, tv, priority, object_pid);
}

int server_flush_to_var(Server *s, bool require_flag_file) {
        char ts[FORMAT_TIMESPAN_MAX];
        sd_journal *j = NULL;
        const char *fn;
        unsigned n = 0;
        usec_t start;
        int r, k;

        assert(s);

        if (!IN_SET(s->storage, STORAGE_AUTO, STORAGE_PERSISTENT))
                return 0;

        if (s->namespace) /* Flushing concept does not exist for namespace instances */
                return 0;

        if (!s->runtime_journal) /* Nothing to flush? */
                return 0;

        if (require_flag_file && !flushed_flag_is_set(s))
                return 0;

        (void) system_journal_open(s, true, false);

        if (!s->system_journal)
                return 0;

        log_debug("Flushing to %s...", s->system_storage.path);

        start = now(CLOCK_MONOTONIC);

        r = sd_journal_open(&j, SD_JOURNAL_RUNTIME_ONLY);
        if (r < 0)
                return log_error_errno(r, "Failed to read runtime journal: %m");

        sd_journal_set_data_threshold(j, 0);

        SD_JOURNAL_FOREACH(j) {
                Object *o = NULL;
                JournalFile *f;

                f = j->current_file;
                assert(f && f->current_offset > 0);

                n++;

                r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
                if (r < 0) {
                        log_error_errno(r, "Can't read entry: %m");
                        goto finish;
                }

                r = journal_file_copy_entry(f, s->system_journal, o, f->current_offset);
                if (r >= 0)
                        continue;

                if (!shall_try_append_again(s->system_journal, r)) {
                        log_error_errno(r, "Can't write entry: %m");
                        goto finish;
                }

                server_rotate(s);
                server_vacuum(s, false);

                if (!s->system_journal) {
                        log_notice("Didn't flush runtime journal since rotation of system journal wasn't successful.");
                        r = -EIO;
                        goto finish;
                }

                log_debug("Retrying write.");
                r = journal_file_copy_entry(f, s->system_journal, o, f->current_offset);
                if (r < 0) {
                        log_error_errno(r, "Can't write entry: %m");
                        goto finish;
                }
        }

        r = 0;

finish:
        if (s->system_journal)
                journal_file_post_change(s->system_journal);

        s->runtime_journal = journal_file_close(s->runtime_journal);

        if (r >= 0)
                (void) rm_rf(s->runtime_storage.path, REMOVE_ROOT);

        sd_journal_close(j);

        server_driver_message(s, 0, NULL,
                              LOG_MESSAGE("Time spent on flushing to %s is %s for %u entries.",
                                          s->system_storage.path,
                                          format_timespan(ts, sizeof(ts), usec_sub_unsigned(now(CLOCK_MONOTONIC), start), 0),
                                          n),
                              NULL);

        fn = strjoina(s->runtime_directory, "/flushed");
        k = touch(fn);
        if (k < 0)
                log_warning_errno(k, "Failed to touch %s, ignoring: %m", fn);

        server_refresh_idle_timer(s);
        return r;
}

static int server_relinquish_var(Server *s) {
        const char *fn;
        assert(s);

        if (s->storage == STORAGE_NONE)
                return 0;

        if (s->namespace) /* Concept does not exist for namespaced instances */
                return -EOPNOTSUPP;

        if (s->runtime_journal && !s->system_journal)
                return 0;

        log_debug("Relinquishing %s...", s->system_storage.path);

        (void) system_journal_open(s, false, true);

        s->system_journal = journal_file_close(s->system_journal);
        ordered_hashmap_clear_with_destructor(s->user_journals, journal_file_close);
        set_clear_with_destructor(s->deferred_closes, journal_file_close);

        fn = strjoina(s->runtime_directory, "/flushed");
        if (unlink(fn) < 0 && errno != ENOENT)
                log_warning_errno(errno, "Failed to unlink %s, ignoring: %m", fn);

        server_refresh_idle_timer(s);
        return 0;
}

int server_process_datagram(
                sd_event_source *es,
                int fd,
                uint32_t revents,
                void *userdata) {

        size_t label_len = 0, m;
        Server *s = userdata;
        struct ucred *ucred = NULL;
        struct timeval *tv = NULL;
        struct cmsghdr *cmsg;
        char *label = NULL;
        struct iovec iovec;
        ssize_t n;
        int *fds = NULL, v = 0;
        size_t n_fds = 0;

        /* We use NAME_MAX space for the SELinux label here. The kernel currently enforces no limit, but
         * according to suggestions from the SELinux people this will change and it will probably be
         * identical to NAME_MAX. For now we use that, but this should be updated one day when the final
         * limit is known. */
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred)) +
                         CMSG_SPACE(sizeof(struct timeval)) +
                         CMSG_SPACE(sizeof(int)) + /* fd */
                         CMSG_SPACE(NAME_MAX) /* selinux label */) control;

        union sockaddr_union sa = {};

        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
                .msg_name = &sa,
                .msg_namelen = sizeof(sa),
        };

        assert(s);
        assert(fd == s->native_fd || fd == s->syslog_fd || fd == s->audit_fd);

        if (revents != EPOLLIN)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Got invalid event from epoll for datagram fd: %" PRIx32,
                                       revents);

        /* Try to get the right size, if we can. (Not all sockets support SIOCINQ, hence we just try, but don't rely on
         * it.) */
        (void) ioctl(fd, SIOCINQ, &v);

        /* Fix it up, if it is too small. We use the same fixed value as auditd here. Awful! */
        m = PAGE_ALIGN(MAX3((size_t) v + 1,
                            (size_t) LINE_MAX,
                            ALIGN(sizeof(struct nlmsghdr)) + ALIGN((size_t) MAX_AUDIT_MESSAGE_LENGTH)) + 1);

        if (!GREEDY_REALLOC(s->buffer, m))
                return log_oom();

        iovec = IOVEC_MAKE(s->buffer, MALLOC_ELEMENTSOF(s->buffer) - 1); /* Leave room for trailing NUL we add later */

        n = recvmsg_safe(fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if (IN_SET(n, -EINTR, -EAGAIN))
                return 0;
        if (n == -EXFULL) {
                log_warning("Got message with truncated control data (too many fds sent?), ignoring.");
                return 0;
        }
        if (n < 0)
                return log_error_errno(n, "recvmsg() failed: %m");

        CMSG_FOREACH(cmsg, &msghdr)
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_CREDENTIALS &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
                        assert(!ucred);
                        ucred = (struct ucred*) CMSG_DATA(cmsg);
                } else if (cmsg->cmsg_level == SOL_SOCKET &&
                         cmsg->cmsg_type == SCM_SECURITY) {
                        assert(!label);
                        label = (char*) CMSG_DATA(cmsg);
                        label_len = cmsg->cmsg_len - CMSG_LEN(0);
                } else if (cmsg->cmsg_level == SOL_SOCKET &&
                           cmsg->cmsg_type == SO_TIMESTAMP &&
                           cmsg->cmsg_len == CMSG_LEN(sizeof(struct timeval))) {
                        assert(!tv);
                        tv = (struct timeval*) CMSG_DATA(cmsg);
                } else if (cmsg->cmsg_level == SOL_SOCKET &&
                         cmsg->cmsg_type == SCM_RIGHTS) {
                        assert(!fds);
                        fds = (int*) CMSG_DATA(cmsg);
                        n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                }

        /* And a trailing NUL, just in case */
        s->buffer[n] = 0;

        if (fd == s->syslog_fd) {
                if (n > 0 && n_fds == 0)
                        server_process_syslog_message(s, s->buffer, n, ucred, tv, label, label_len);
                else if (n_fds > 0)
                        log_warning("Got file descriptors via syslog socket. Ignoring.");

        } else if (fd == s->native_fd) {
                if (n > 0 && n_fds == 0)
                        server_process_native_message(s, s->buffer, n, ucred, tv, label, label_len);
                else if (n == 0 && n_fds == 1)
                        server_process_native_file(s, fds[0], ucred, tv, label, label_len);
                else if (n_fds > 0)
                        log_warning("Got too many file descriptors via native socket. Ignoring.");

        } else {
                assert(fd == s->audit_fd);

                if (n > 0 && n_fds == 0)
                        server_process_audit_message(s, s->buffer, n, ucred, &sa, msghdr.msg_namelen);
                else if (n_fds > 0)
                        log_warning("Got file descriptors via audit socket. Ignoring.");
        }

        close_many(fds, n_fds);

        server_refresh_idle_timer(s);
        return 0;
}

static void server_full_flush(Server *s) {
        assert(s);

        (void) server_flush_to_var(s, false);
        server_sync(s);
        server_vacuum(s, false);

        server_space_usage_message(s, NULL);

        server_refresh_idle_timer(s);
}

static int dispatch_sigusr1(sd_event_source *es, const struct signalfd_siginfo *si, void *userdata) {
        Server *s = userdata;

        assert(s);

        if (s->namespace) {
                log_error("Received SIGUSR1 signal from PID " PID_FMT ", but flushing runtime journals not supported for namespaced instances.", si->ssi_pid);
                return 0;
        }

        log_info("Received SIGUSR1 signal from PID " PID_FMT ", as request to flush runtime journal.", si->ssi_pid);
        server_full_flush(s);

        return 0;
}

static void server_full_rotate(Server *s) {
        const char *fn;
        int r;

        assert(s);

        server_rotate(s);
        server_vacuum(s, true);

        if (s->system_journal)
                patch_min_use(&s->system_storage);
        if (s->runtime_journal)
                patch_min_use(&s->runtime_storage);

        /* Let clients know when the most recent rotation happened. */
        fn = strjoina(s->runtime_directory, "/rotated");
        r = write_timestamp_file_atomic(fn, now(CLOCK_MONOTONIC));
        if (r < 0)
                log_warning_errno(r, "Failed to write %s, ignoring: %m", fn);
}

static int dispatch_sigusr2(sd_event_source *es, const struct signalfd_siginfo *si, void *userdata) {
        Server *s = userdata;

        assert(s);

        log_info("Received SIGUSR2 signal from PID " PID_FMT ", as request to rotate journal.", si->ssi_pid);
        server_full_rotate(s);

        return 0;
}

static int dispatch_sigterm(sd_event_source *es, const struct signalfd_siginfo *si, void *userdata) {
        Server *s = userdata;

        assert(s);

        log_received_signal(LOG_INFO, si);

        sd_event_exit(s->event, 0);
        return 0;
}

static void server_full_sync(Server *s) {
        const char *fn;
        int r;

        assert(s);

        server_sync(s);

        /* Let clients know when the most recent sync happened. */
        fn = strjoina(s->runtime_directory, "/synced");
        r = write_timestamp_file_atomic(fn, now(CLOCK_MONOTONIC));
        if (r < 0)
                log_warning_errno(r, "Failed to write %s, ignoring: %m", fn);

        return;
}

static int dispatch_sigrtmin1(sd_event_source *es, const struct signalfd_siginfo *si, void *userdata) {
        Server *s = userdata;

        assert(s);

        log_debug("Received SIGRTMIN1 signal from PID " PID_FMT ", as request to sync.", si->ssi_pid );
        server_full_sync(s);

        return 0;
}

static int setup_signals(Server *s) {
        int r;

        assert(s);

        assert_se(sigprocmask_many(SIG_SETMASK, NULL, SIGINT, SIGTERM, SIGUSR1, SIGUSR2, SIGRTMIN+1, -1) >= 0);

        r = sd_event_add_signal(s->event, &s->sigusr1_event_source, SIGUSR1, dispatch_sigusr1, s);
        if (r < 0)
                return r;

        r = sd_event_add_signal(s->event, &s->sigusr2_event_source, SIGUSR2, dispatch_sigusr2, s);
        if (r < 0)
                return r;

        r = sd_event_add_signal(s->event, &s->sigterm_event_source, SIGTERM, dispatch_sigterm, s);
        if (r < 0)
                return r;

        /* Let's process SIGTERM late, so that we flush all queued messages to disk before we exit */
        r = sd_event_source_set_priority(s->sigterm_event_source, SD_EVENT_PRIORITY_NORMAL+20);
        if (r < 0)
                return r;

        /* When journald is invoked on the terminal (when debugging), it's useful if C-c is handled
         * equivalent to SIGTERM. */
        r = sd_event_add_signal(s->event, &s->sigint_event_source, SIGINT, dispatch_sigterm, s);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(s->sigint_event_source, SD_EVENT_PRIORITY_NORMAL+20);
        if (r < 0)
                return r;

        /* SIGRTMIN+1 causes an immediate sync. We process this very late, so that everything else queued at
         * this point is really written to disk. Clients can watch /run/systemd/journal/synced with inotify
         * until its mtime changes to see when a sync happened. */
        r = sd_event_add_signal(s->event, &s->sigrtmin1_event_source, SIGRTMIN+1, dispatch_sigrtmin1, s);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(s->sigrtmin1_event_source, SD_EVENT_PRIORITY_NORMAL+15);
        if (r < 0)
                return r;

        return 0;
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        Server *s = data;
        int r;

        assert(s);

        if (proc_cmdline_key_streq(key, "systemd.journald.forward_to_syslog")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning("Failed to parse forward to syslog switch \"%s\". Ignoring.", value);
                else
                        s->forward_to_syslog = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.forward_to_kmsg")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning("Failed to parse forward to kmsg switch \"%s\". Ignoring.", value);
                else
                        s->forward_to_kmsg = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.forward_to_console")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning("Failed to parse forward to console switch \"%s\". Ignoring.", value);
                else
                        s->forward_to_console = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.forward_to_wall")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning("Failed to parse forward to wall switch \"%s\". Ignoring.", value);
                else
                        s->forward_to_wall = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_console")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level console value \"%s\". Ignoring.", value);
                else
                        s->max_level_console = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_store")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level store value \"%s\". Ignoring.", value);
                else
                        s->max_level_store = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_syslog")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level syslog value \"%s\". Ignoring.", value);
                else
                        s->max_level_syslog = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_kmsg")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level kmsg value \"%s\". Ignoring.", value);
                else
                        s->max_level_kmsg = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_wall")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level wall value \"%s\". Ignoring.", value);
                else
                        s->max_level_wall = r;

        } else if (startswith(key, "systemd.journald"))
                log_warning("Unknown journald kernel command line option \"%s\". Ignoring.", key);

        /* do not warn about state here, since probably systemd already did */
        return 0;
}

static int server_parse_config_file(Server *s) {
        int r;

        assert(s);

        if (s->namespace) {
                const char *namespaced, *dropin_dirname;

                /* If we are running in namespace mode, load the namespace specific configuration file, and nothing else */
                namespaced = strjoina(PKGSYSCONFDIR "/journald@", s->namespace, ".conf");
                dropin_dirname = strjoina("journald@", s->namespace, ".conf.d");

                r = config_parse_many(
                                STRV_MAKE_CONST(namespaced),
                                (const char* const*) CONF_PATHS_STRV("systemd"),
                                dropin_dirname,
                                "Journal\0",
                                config_item_perf_lookup, journald_gperf_lookup,
                                CONFIG_PARSE_WARN, s, NULL);
                if (r < 0)
                        return r;

                return 0;
        }

        return config_parse_many_nulstr(
                        PKGSYSCONFDIR "/journald.conf",
                        CONF_PATHS_NULSTR("systemd/journald.conf.d"),
                        "Journal\0",
                        config_item_perf_lookup, journald_gperf_lookup,
                        CONFIG_PARSE_WARN, s, NULL);
}

static int server_dispatch_sync(sd_event_source *es, usec_t t, void *userdata) {
        Server *s = userdata;

        assert(s);

        server_sync(s);
        return 0;
}

int server_schedule_sync(Server *s, int priority) {
        int r;

        assert(s);

        if (priority <= LOG_CRIT) {
                /* Immediately sync to disk when this is of priority CRIT, ALERT, EMERG */
                server_sync(s);
                return 0;
        }

        if (s->sync_scheduled)
                return 0;

        if (s->sync_interval_usec > 0) {

                if (!s->sync_event_source) {
                        r = sd_event_add_time_relative(
                                        s->event,
                                        &s->sync_event_source,
                                        CLOCK_MONOTONIC,
                                        s->sync_interval_usec, 0,
                                        server_dispatch_sync, s);
                        if (r < 0)
                                return r;

                        r = sd_event_source_set_priority(s->sync_event_source, SD_EVENT_PRIORITY_IMPORTANT);
                } else {
                        r = sd_event_source_set_time_relative(s->sync_event_source, s->sync_interval_usec);
                        if (r < 0)
                                return r;

                        r = sd_event_source_set_enabled(s->sync_event_source, SD_EVENT_ONESHOT);
                }
                if (r < 0)
                        return r;

                s->sync_scheduled = true;
        }

        return 0;
}

static int dispatch_hostname_change(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        Server *s = userdata;

        assert(s);

        server_cache_hostname(s);
        return 0;
}

static int server_open_hostname(Server *s) {
        int r;

        assert(s);

        s->hostname_fd = open("/proc/sys/kernel/hostname",
                              O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (s->hostname_fd < 0)
                return log_error_errno(errno, "Failed to open /proc/sys/kernel/hostname: %m");

        r = sd_event_add_io(s->event, &s->hostname_event_source, s->hostname_fd, 0, dispatch_hostname_change, s);
        if (r < 0) {
                /* kernels prior to 3.2 don't support polling this file. Ignore
                 * the failure. */
                if (r == -EPERM) {
                        log_warning_errno(r, "Failed to register hostname fd in event loop, ignoring: %m");
                        s->hostname_fd = safe_close(s->hostname_fd);
                        return 0;
                }

                return log_error_errno(r, "Failed to register hostname fd in event loop: %m");
        }

        r = sd_event_source_set_priority(s->hostname_event_source, SD_EVENT_PRIORITY_IMPORTANT-10);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust priority of hostname event source: %m");

        return 0;
}

static int dispatch_notify_event(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        Server *s = userdata;
        int r;

        assert(s);
        assert(s->notify_event_source == es);
        assert(s->notify_fd == fd);

        /* The $NOTIFY_SOCKET is writable again, now send exactly one
         * message on it. Either it's the watchdog event, the initial
         * READY=1 event or an stdout stream event. If there's nothing
         * to write anymore, turn our event source off. The next time
         * there's something to send it will be turned on again. */

        if (!s->sent_notify_ready) {
                static const char p[] =
                        "READY=1\n"
                        "STATUS=Processing requests...";
                ssize_t l;

                l = send(s->notify_fd, p, strlen(p), MSG_DONTWAIT);
                if (l < 0) {
                        if (errno == EAGAIN)
                                return 0;

                        return log_error_errno(errno, "Failed to send READY=1 notification message: %m");
                }

                s->sent_notify_ready = true;
                log_debug("Sent READY=1 notification.");

        } else if (s->send_watchdog) {

                static const char p[] =
                        "WATCHDOG=1";

                ssize_t l;

                l = send(s->notify_fd, p, strlen(p), MSG_DONTWAIT);
                if (l < 0) {
                        if (errno == EAGAIN)
                                return 0;

                        return log_error_errno(errno, "Failed to send WATCHDOG=1 notification message: %m");
                }

                s->send_watchdog = false;
                log_debug("Sent WATCHDOG=1 notification.");

        } else if (s->stdout_streams_notify_queue)
                /* Dispatch one stream notification event */
                stdout_stream_send_notify(s->stdout_streams_notify_queue);

        /* Leave us enabled if there's still more to do. */
        if (s->send_watchdog || s->stdout_streams_notify_queue)
                return 0;

        /* There was nothing to do anymore, let's turn ourselves off. */
        r = sd_event_source_set_enabled(es, SD_EVENT_OFF);
        if (r < 0)
                return log_error_errno(r, "Failed to turn off notify event source: %m");

        return 0;
}

static int dispatch_watchdog(sd_event_source *es, uint64_t usec, void *userdata) {
        Server *s = userdata;
        int r;

        assert(s);

        s->send_watchdog = true;

        r = sd_event_source_set_enabled(s->notify_event_source, SD_EVENT_ON);
        if (r < 0)
                log_warning_errno(r, "Failed to turn on notify event source: %m");

        r = sd_event_source_set_time(s->watchdog_event_source, usec + s->watchdog_usec / 2);
        if (r < 0)
                return log_error_errno(r, "Failed to restart watchdog event source: %m");

        r = sd_event_source_set_enabled(s->watchdog_event_source, SD_EVENT_ON);
        if (r < 0)
                return log_error_errno(r, "Failed to enable watchdog event source: %m");

        return 0;
}

static int server_connect_notify(Server *s) {
        union sockaddr_union sa;
        socklen_t sa_len;
        const char *e;
        int r;

        assert(s);
        assert(s->notify_fd < 0);
        assert(!s->notify_event_source);

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

        s->notify_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (s->notify_fd < 0)
                return log_error_errno(errno, "Failed to create notify socket: %m");

        (void) fd_inc_sndbuf(s->notify_fd, NOTIFY_SNDBUF_SIZE);

        r = connect(s->notify_fd, &sa.sa, sa_len);
        if (r < 0)
                return log_error_errno(errno, "Failed to connect to notify socket: %m");

        r = sd_event_add_io(s->event, &s->notify_event_source, s->notify_fd, EPOLLOUT, dispatch_notify_event, s);
        if (r < 0)
                return log_error_errno(r, "Failed to watch notification socket: %m");

        if (sd_watchdog_enabled(false, &s->watchdog_usec) > 0) {
                s->send_watchdog = true;

                r = sd_event_add_time_relative(s->event, &s->watchdog_event_source, CLOCK_MONOTONIC, s->watchdog_usec/2, s->watchdog_usec/4, dispatch_watchdog, s);
                if (r < 0)
                        return log_error_errno(r, "Failed to add watchdog time event: %m");
        }

        /* This should fire pretty soon, which we'll use to send the READY=1 event. */

        return 0;
}

static int synchronize_second_half(sd_event_source *event_source, void *userdata) {
        Varlink *link = userdata;
        Server *s;
        int r;

        assert(link);
        assert_se(s = varlink_get_userdata(link));

        /* This is the "second half" of the Synchronize() varlink method. This function is called as deferred
         * event source at a low priority to ensure the synchronization completes after all queued log
         * messages are processed. */
        server_full_sync(s);

        /* Let's get rid of the event source now, by marking it as non-floating again. It then has no ref
         * anymore and is immediately destroyed after we return from this function, i.e. from this event
         * source handler at the end. */
        r = sd_event_source_set_floating(event_source, false);
        if (r < 0)
                return log_error_errno(r, "Failed to mark event source as non-floating: %m");

        return varlink_reply(link, NULL);
}

static void synchronize_destroy(void *userdata) {
        varlink_unref(userdata);
}

static int vl_method_synchronize(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *event_source = NULL;
        Server *s = userdata;
        int r;

        assert(link);
        assert(s);

        if (json_variant_elements(parameters) > 0)
                return varlink_error_invalid_parameter(link, parameters);

        log_info("Received client request to rotate journal.");

        /* We don't do the main work now, but instead enqueue a deferred event loop job which will do
         * it. That job is scheduled at low priority, so that we return from this method call only after all
         * queued but not processed log messages are written to disk, so that this method call returning can
         * be used as nice synchronization point. */
        r = sd_event_add_defer(s->event, &event_source, synchronize_second_half, link);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate defer event source: %m");

        r = sd_event_source_set_destroy_callback(event_source, synchronize_destroy);
        if (r < 0)
                return log_error_errno(r, "Failed to set event source destroy callback: %m");

        varlink_ref(link); /* The varlink object is now left to the destroy callback to unref */

        r = sd_event_source_set_priority(event_source, SD_EVENT_PRIORITY_NORMAL+15);
        if (r < 0)
                return log_error_errno(r, "Failed to set defer event source priority: %m");

        /* Give up ownership of this event source. It will now be destroyed along with event loop itself,
         * unless it destroys itself earlier. */
        r = sd_event_source_set_floating(event_source, true);
        if (r < 0)
                return log_error_errno(r, "Failed to mark event source as floating: %m");

        (void) sd_event_source_set_description(event_source, "deferred-sync");

        return 0;
}

static int vl_method_rotate(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        Server *s = userdata;

        assert(link);
        assert(s);

        if (json_variant_elements(parameters) > 0)
                return varlink_error_invalid_parameter(link, parameters);

        log_info("Received client request to rotate journal.");
        server_full_rotate(s);

        return varlink_reply(link, NULL);
}

static int vl_method_flush_to_var(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        Server *s = userdata;

        assert(link);
        assert(s);

        if (json_variant_elements(parameters) > 0)
                return varlink_error_invalid_parameter(link, parameters);
        if (s->namespace)
                return varlink_error(link, "io.systemd.Journal.NotSupportedByNamespaces", NULL);

        log_info("Received client request to flush runtime journal.");
        server_full_flush(s);

        return varlink_reply(link, NULL);
}

static int vl_method_relinquish_var(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        Server *s = userdata;

        assert(link);
        assert(s);

        if (json_variant_elements(parameters) > 0)
                return varlink_error_invalid_parameter(link, parameters);
        if (s->namespace)
                return varlink_error(link, "io.systemd.Journal.NotSupportedByNamespaces", NULL);

        log_info("Received client request to relinquish %s access.", s->system_storage.path);
        server_relinquish_var(s);

        return varlink_reply(link, NULL);
}

static int vl_connect(VarlinkServer *server, Varlink *link, void *userdata) {
        Server *s = userdata;

        assert(server);
        assert(link);
        assert(s);

        (void) server_start_or_stop_idle_timer(s); /* maybe we are no longer idle */

        return 0;
}

static void vl_disconnect(VarlinkServer *server, Varlink *link, void *userdata) {
        Server *s = userdata;

        assert(server);
        assert(link);
        assert(s);

        (void) server_start_or_stop_idle_timer(s); /* maybe we are idle now */
}

static int server_open_varlink(Server *s, const char *socket, int fd) {
        int r;

        assert(s);

        r = varlink_server_new(&s->varlink_server, VARLINK_SERVER_ROOT_ONLY|VARLINK_SERVER_INHERIT_USERDATA);
        if (r < 0)
                return r;

        varlink_server_set_userdata(s->varlink_server, s);

        r = varlink_server_bind_method_many(
                        s->varlink_server,
                        "io.systemd.Journal.Synchronize",   vl_method_synchronize,
                        "io.systemd.Journal.Rotate",        vl_method_rotate,
                        "io.systemd.Journal.FlushToVar",    vl_method_flush_to_var,
                        "io.systemd.Journal.RelinquishVar", vl_method_relinquish_var);
        if (r < 0)
                return r;

        r = varlink_server_bind_connect(s->varlink_server, vl_connect);
        if (r < 0)
                return r;

        r = varlink_server_bind_disconnect(s->varlink_server, vl_disconnect);
        if (r < 0)
                return r;

        if (fd < 0)
                r = varlink_server_listen_address(s->varlink_server, socket, 0600);
        else
                r = varlink_server_listen_fd(s->varlink_server, fd);
        if (r < 0)
                return r;

        r = varlink_server_attach_event(s->varlink_server, s->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        return 0;
}

static bool server_is_idle(Server *s) {
        assert(s);

        /* The server for the main namespace is never idle */
        if (!s->namespace)
                return false;

        /* If a retention maximum is set larger than the idle time we need to be running to enforce it, hence
         * turn off the idle logic. */
        if (s->max_retention_usec > IDLE_TIMEOUT_USEC)
                return false;

        /* We aren't idle if we have a varlink client */
        if (varlink_server_current_connections(s->varlink_server) > 0)
                return false;

        /* If we have stdout streams we aren't idle */
        if (s->n_stdout_streams > 0)
                return false;

        return true;
}

static int server_idle_handler(sd_event_source *source, uint64_t usec, void *userdata) {
        Server *s = userdata;

        assert(source);
        assert(s);

        log_debug("Server is idle, exiting.");
        sd_event_exit(s->event, 0);
        return 0;
}

int server_start_or_stop_idle_timer(Server *s) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
        int r;

        assert(s);

        if (!server_is_idle(s)) {
                s->idle_event_source = sd_event_source_disable_unref(s->idle_event_source);
                return 0;
        }

        if (s->idle_event_source)
                return 1;

        r = sd_event_add_time_relative(s->event, &source, CLOCK_MONOTONIC, IDLE_TIMEOUT_USEC, 0, server_idle_handler, s);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate idle timer: %m");

        r = sd_event_source_set_priority(source, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                return log_error_errno(r, "Failed to set idle timer priority: %m");

        (void) sd_event_source_set_description(source, "idle-timer");

        s->idle_event_source = TAKE_PTR(source);
        return 1;
}

int server_refresh_idle_timer(Server *s) {
        int r;

        assert(s);

        if (!s->idle_event_source)
                return 0;

        r = sd_event_source_set_time_relative(s->idle_event_source, IDLE_TIMEOUT_USEC);
        if (r < 0)
                return log_error_errno(r, "Failed to refresh idle timer: %m");

        return 1;
}

static int set_namespace(Server *s, const char *namespace) {
        assert(s);

        if (!namespace)
                return 0;

        if (!log_namespace_name_valid(namespace))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified namespace name not valid, refusing: %s", namespace);

        s->namespace = strdup(namespace);
        if (!s->namespace)
                return log_oom();

        s->namespace_field = strjoin("_NAMESPACE=", namespace);
        if (!s->namespace_field)
                return log_oom();

        return 1;
}

int server_init(Server *s, const char *namespace) {
        const char *native_socket, *syslog_socket, *stdout_socket, *varlink_socket, *e;
        _cleanup_fdset_free_ FDSet *fds = NULL;
        int n, r, fd, varlink_fd = -1;
        bool no_sockets;

        assert(s);

        *s = (Server) {
                .syslog_fd = -1,
                .native_fd = -1,
                .stdout_fd = -1,
                .dev_kmsg_fd = -1,
                .audit_fd = -1,
                .hostname_fd = -1,
                .notify_fd = -1,

                .compress.enabled = true,
                .compress.threshold_bytes = UINT64_MAX,
                .seal = true,

                .set_audit = true,

                .watchdog_usec = USEC_INFINITY,

                .sync_interval_usec = DEFAULT_SYNC_INTERVAL_USEC,
                .sync_scheduled = false,

                .ratelimit_interval = DEFAULT_RATE_LIMIT_INTERVAL,
                .ratelimit_burst = DEFAULT_RATE_LIMIT_BURST,

                .forward_to_wall = true,

                .max_file_usec = DEFAULT_MAX_FILE_USEC,

                .max_level_store = LOG_DEBUG,
                .max_level_syslog = LOG_DEBUG,
                .max_level_kmsg = LOG_NOTICE,
                .max_level_console = LOG_INFO,
                .max_level_wall = LOG_EMERG,

                .line_max = DEFAULT_LINE_MAX,

                .runtime_storage.name = "Runtime Journal",
                .system_storage.name = "System Journal",
        };

        r = set_namespace(s, namespace);
        if (r < 0)
                return r;

        /* By default, only read from /dev/kmsg if are the main namespace */
        s->read_kmsg = !s->namespace;
        s->storage = s->namespace ? STORAGE_PERSISTENT : STORAGE_AUTO;

        journal_reset_metrics(&s->system_storage.metrics);
        journal_reset_metrics(&s->runtime_storage.metrics);

        server_parse_config_file(s);

        if (!s->namespace) {
                /* Parse kernel command line, but only if we are not a namespace instance */
                r = proc_cmdline_parse(parse_proc_cmdline_item, s, PROC_CMDLINE_STRIP_RD_PREFIX);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");
        }

        if (!!s->ratelimit_interval != !!s->ratelimit_burst) { /* One set to 0 and the other not? */
                log_debug("Setting both rate limit interval and burst from "USEC_FMT",%u to 0,0",
                          s->ratelimit_interval, s->ratelimit_burst);
                s->ratelimit_interval = s->ratelimit_burst = 0;
        }

        e = getenv("RUNTIME_DIRECTORY");
        if (e)
                s->runtime_directory = strdup(e);
        else if (s->namespace)
                s->runtime_directory = strjoin("/run/systemd/journal.", s->namespace);
        else
                s->runtime_directory = strdup("/run/systemd/journal");
        if (!s->runtime_directory)
                return log_oom();

        (void) mkdir_p(s->runtime_directory, 0755);

        s->user_journals = ordered_hashmap_new(NULL);
        if (!s->user_journals)
                return log_oom();

        s->mmap = mmap_cache_new();
        if (!s->mmap)
                return log_oom();

        s->deferred_closes = set_new(NULL);
        if (!s->deferred_closes)
                return log_oom();

        r = sd_event_default(&s->event);
        if (r < 0)
                return log_error_errno(r, "Failed to create event loop: %m");

        n = sd_listen_fds(true);
        if (n < 0)
                return log_error_errno(n, "Failed to read listening file descriptors from environment: %m");

        native_socket = strjoina(s->runtime_directory, "/socket");
        stdout_socket = strjoina(s->runtime_directory, "/stdout");
        syslog_socket = strjoina(s->runtime_directory, "/dev-log");
        varlink_socket = strjoina(s->runtime_directory, "/io.systemd.journal");

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {

                if (sd_is_socket_unix(fd, SOCK_DGRAM, -1, native_socket, 0) > 0) {

                        if (s->native_fd >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Too many native sockets passed.");

                        s->native_fd = fd;

                } else if (sd_is_socket_unix(fd, SOCK_STREAM, 1, stdout_socket, 0) > 0) {

                        if (s->stdout_fd >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Too many stdout sockets passed.");

                        s->stdout_fd = fd;

                } else if (sd_is_socket_unix(fd, SOCK_DGRAM, -1, syslog_socket, 0) > 0) {

                        if (s->syslog_fd >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Too many /dev/log sockets passed.");

                        s->syslog_fd = fd;

                } else if (sd_is_socket_unix(fd, SOCK_STREAM, 1, varlink_socket, 0) > 0) {

                        if (varlink_fd >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Too many varlink sockets passed.");

                        varlink_fd = fd;
                } else if (sd_is_socket(fd, AF_NETLINK, SOCK_RAW, -1) > 0) {

                        if (s->audit_fd >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Too many audit sockets passed.");

                        s->audit_fd = fd;

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
        }

        /* Try to restore streams, but don't bother if this fails */
        (void) server_restore_streams(s, fds);

        if (fdset_size(fds) > 0) {
                log_warning("%u unknown file descriptors passed, closing.", fdset_size(fds));
                fds = fdset_free(fds);
        }

        no_sockets = s->native_fd < 0 && s->stdout_fd < 0 && s->syslog_fd < 0 && s->audit_fd < 0 && varlink_fd < 0;

        /* always open stdout, syslog, native, and kmsg sockets */

        /* systemd-journald.socket: /run/systemd/journal/stdout */
        r = server_open_stdout_socket(s, stdout_socket);
        if (r < 0)
                return r;

        /* systemd-journald-dev-log.socket: /run/systemd/journal/dev-log */
        r = server_open_syslog_socket(s, syslog_socket);
        if (r < 0)
                return r;

        /* systemd-journald.socket: /run/systemd/journal/socket */
        r = server_open_native_socket(s, native_socket);
        if (r < 0)
                return r;

        /* /dev/kmsg */
        r = server_open_dev_kmsg(s);
        if (r < 0)
                return r;

        /* Unless we got *some* sockets and not audit, open audit socket */
        if (s->audit_fd >= 0 || no_sockets) {
                r = server_open_audit(s);
                if (r < 0)
                        return r;
        }

        r = server_open_varlink(s, varlink_socket, varlink_fd);
        if (r < 0)
                return r;

        r = server_open_kernel_seqnum(s);
        if (r < 0)
                return r;

        r = server_open_hostname(s);
        if (r < 0)
                return r;

        r = setup_signals(s);
        if (r < 0)
                return r;

        s->ratelimit = journal_ratelimit_new();
        if (!s->ratelimit)
                return log_oom();

        r = cg_get_root_path(&s->cgroup_root);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire cgroup root path: %m");

        server_cache_hostname(s);
        server_cache_boot_id(s);
        server_cache_machine_id(s);

        if (s->namespace)
                s->runtime_storage.path = strjoin("/run/log/journal/", SERVER_MACHINE_ID(s), ".", s->namespace);
        else
                s->runtime_storage.path = strjoin("/run/log/journal/", SERVER_MACHINE_ID(s));
        if (!s->runtime_storage.path)
                return log_oom();

        e = getenv("LOGS_DIRECTORY");
        if (e)
                s->system_storage.path = strdup(e);
        else if (s->namespace)
                s->system_storage.path = strjoin("/var/log/journal/", SERVER_MACHINE_ID(s), ".", s->namespace);
        else
                s->system_storage.path = strjoin("/var/log/journal/", SERVER_MACHINE_ID(s));
        if (!s->system_storage.path)
                return log_oom();

        (void) server_connect_notify(s);

        (void) client_context_acquire_default(s);

        r = system_journal_open(s, false, false);
        if (r < 0)
                return r;

        server_start_or_stop_idle_timer(s);
        return 0;
}

void server_maybe_append_tags(Server *s) {
#if HAVE_GCRYPT
        JournalFile *f;
        usec_t n;

        n = now(CLOCK_REALTIME);

        if (s->system_journal)
                journal_file_maybe_append_tag(s->system_journal, n);

        ORDERED_HASHMAP_FOREACH(f, s->user_journals)
                journal_file_maybe_append_tag(f, n);
#endif
}

void server_done(Server *s) {
        assert(s);

        free(s->namespace);
        free(s->namespace_field);

        set_free_with_destructor(s->deferred_closes, journal_file_close);

        while (s->stdout_streams)
                stdout_stream_free(s->stdout_streams);

        client_context_flush_all(s);

        (void) journal_file_close(s->system_journal);
        (void) journal_file_close(s->runtime_journal);

        ordered_hashmap_free_with_destructor(s->user_journals, journal_file_close);

        varlink_server_unref(s->varlink_server);

        sd_event_source_unref(s->syslog_event_source);
        sd_event_source_unref(s->native_event_source);
        sd_event_source_unref(s->stdout_event_source);
        sd_event_source_unref(s->dev_kmsg_event_source);
        sd_event_source_unref(s->audit_event_source);
        sd_event_source_unref(s->sync_event_source);
        sd_event_source_unref(s->sigusr1_event_source);
        sd_event_source_unref(s->sigusr2_event_source);
        sd_event_source_unref(s->sigterm_event_source);
        sd_event_source_unref(s->sigint_event_source);
        sd_event_source_unref(s->sigrtmin1_event_source);
        sd_event_source_unref(s->hostname_event_source);
        sd_event_source_unref(s->notify_event_source);
        sd_event_source_unref(s->watchdog_event_source);
        sd_event_source_unref(s->idle_event_source);
        sd_event_unref(s->event);

        safe_close(s->syslog_fd);
        safe_close(s->native_fd);
        safe_close(s->stdout_fd);
        safe_close(s->dev_kmsg_fd);
        safe_close(s->audit_fd);
        safe_close(s->hostname_fd);
        safe_close(s->notify_fd);

        if (s->ratelimit)
                journal_ratelimit_free(s->ratelimit);

        if (s->kernel_seqnum)
                munmap(s->kernel_seqnum, sizeof(uint64_t));

        free(s->buffer);
        free(s->tty_path);
        free(s->cgroup_root);
        free(s->hostname_field);
        free(s->runtime_storage.path);
        free(s->system_storage.path);
        free(s->runtime_directory);

        mmap_cache_unref(s->mmap);
}

static const char* const storage_table[_STORAGE_MAX] = {
        [STORAGE_AUTO] = "auto",
        [STORAGE_VOLATILE] = "volatile",
        [STORAGE_PERSISTENT] = "persistent",
        [STORAGE_NONE] = "none"
};

DEFINE_STRING_TABLE_LOOKUP(storage, Storage);
DEFINE_CONFIG_PARSE_ENUM(config_parse_storage, storage, Storage, "Failed to parse storage setting");

static const char* const split_mode_table[_SPLIT_MAX] = {
        [SPLIT_LOGIN] = "login",
        [SPLIT_UID] = "uid",
        [SPLIT_NONE] = "none",
};

DEFINE_STRING_TABLE_LOOKUP(split_mode, SplitMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_split_mode, split_mode, SplitMode, "Failed to parse split mode setting");

int config_parse_line_max(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        size_t *sz = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue))
                /* Empty assignment means default */
                *sz = DEFAULT_LINE_MAX;
        else {
                uint64_t v;

                r = parse_size(rvalue, 1024, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse LineMax= value, ignoring: %s", rvalue);
                        return 0;
                }

                if (v < 79) {
                        /* Why specify 79 here as minimum line length? Simply, because the most common traditional
                         * terminal size is 80ch, and it might make sense to break one character before the natural
                         * line break would occur on that. */
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "LineMax= too small, clamping to 79: %s", rvalue);
                        *sz = 79;
                } else if (v > (uint64_t) (SSIZE_MAX-1)) {
                        /* So, why specify SSIZE_MAX-1 here? Because that's one below the largest size value read()
                         * can return, and we need one extra byte for the trailing NUL byte. Of course IRL such large
                         * memory allocations will fail anyway, hence this limit is mostly theoretical anyway, as we'll
                         * fail much earlier anyway. */
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "LineMax= too large, clamping to %" PRIu64 ": %s", (uint64_t) (SSIZE_MAX-1), rvalue);
                        *sz = SSIZE_MAX-1;
                } else
                        *sz = (size_t) v;
        }

        return 0;
}

int config_parse_compress(
                const char* unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        JournalCompressOptions* compress = data;
        int r;

        if (isempty(rvalue)) {
                compress->enabled = true;
                compress->threshold_bytes = UINT64_MAX;
        } else if (streq(rvalue, "1")) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Compress= ambiguously specified as 1, enabling compression with default threshold");
                compress->enabled = true;
        } else if (streq(rvalue, "0")) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Compress= ambiguously specified as 0, disabling compression");
                compress->enabled = false;
        } else {
                r = parse_boolean(rvalue);
                if (r < 0) {
                        r = parse_size(rvalue, 1024, &compress->threshold_bytes);
                        if (r < 0)
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Failed to parse Compress= value, ignoring: %s", rvalue);
                        else
                                compress->enabled = true;
                } else
                        compress->enabled = r;
        }

        return 0;
}
