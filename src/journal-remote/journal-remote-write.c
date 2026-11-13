/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/xattr.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "journal-file-util.h"
#include "journal-remote.h"
#include "journal-vacuum.h"
#include "log.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "time-util.h"
#include "xattr-util.h"

#define FIRST_ENTRY_XATTR "user.journal_remote.first_entry_usec"

static usec_t file_rotation_usec(JournalFile *f, usec_t max_file_usec) {
        usec_t started;
        le64_t le;

        assert(f);

        if (max_file_usec == 0 || le64toh(f->header->n_entries) == 0)
                return USEC_INFINITY;

        if (fgetxattr(f->fd, FIRST_ENTRY_XATTR, &le, sizeof(le)) == sizeof(le) &&
            timestamp_is_set(le64toh(le)))
                started = le64toh(le);
        else if (fd_getcrtime(f->fd, &started) < 0)
                started = timespec_load(&f->last_stat.st_mtim);

        return usec_add(now(CLOCK_MONOTONIC),
                        usec_sub_unsigned(max_file_usec, usec_sub_unsigned(now(CLOCK_REALTIME), started)));
}

static void writer_start_file(Writer *w) {
        le64_t le;
        int r;

        assert(w);
        assert(w->journal);

        if (w->server->max_file_usec == 0 || le64toh(w->journal->header->n_entries) > 0)
                return;

        w->file_rotation_usec = usec_add(now(CLOCK_MONOTONIC), w->server->max_file_usec);
        le = htole64(now(CLOCK_REALTIME));
        r = xsetxattr_full(w->journal->fd, /* path= */ NULL, AT_EMPTY_PATH, FIRST_ENTRY_XATTR,
                          (const char*) &le, sizeof(le), /* xattr_flags= */ 0);
        if (r < 0)
                log_debug_errno(r, "Failed to save first entry time for '%s', ignoring: %m", w->journal->path);
}

static int writer_vacuum(Writer *w) {
        assert(w);

        return journal_directory_vacuum_full(w->output, w->metrics.max_use, w->metrics.n_max_files,
                                             w->server->max_retention_usec, /* oldest_usec= */ NULL,
                                             JOURNAL_VACUUM_VERBOSE |
                                             (w->server->max_retention_usec > 0 ? JOURNAL_VACUUM_USE_MTIME : 0));
}

static int do_rotate(Writer *w, JournalFileFlags file_flags) {
        int r;

        assert(w);

        _cleanup_free_ char *path = strdup(w->journal->path);
        if (!path)
                return log_oom();

        r = journal_file_rotate(&w->journal, w->mmap, file_flags, UINT64_MAX, /* seqnum_id= */ NULL, /* deferred_closes= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to rotate '%s': %m", path);

        w->file_rotation_usec = USEC_INFINITY;
        return 0;
}

int writer_new(RemoteServer *server, Writer **ret) {
        _cleanup_(writer_unrefp) Writer *w = NULL;
        int r;

        assert(server);
        assert(ret);

        w = new(Writer, 1);
        if (!w)
                return -ENOMEM;

        *w = (Writer) {
                .n_ref = 1,
                .metrics = server->metrics,
                .server = server,
        };

        w->mmap = mmap_cache_new();
        if (!w->mmap)
                return -ENOMEM;

        if (is_dir(server->output, /* follow= */ true) > 0) {
                w->output = strdup(server->output);
                if (!w->output)
                        return -ENOMEM;
        } else {
                r = path_extract_directory(server->output, &w->output);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(w);
        return 0;
}

static Writer* writer_free(Writer *w) {
        if (!w)
                return NULL;

        if (w->journal) {
                log_debug("Closing journal file %s.", w->journal->path);
                journal_file_offline_close(w->journal);
        }

        if (w->server && w->hashmap_key)
                hashmap_remove(w->server->writers, w->hashmap_key);

        free(w->hashmap_key);

        if (w->mmap)
                mmap_cache_unref(w->mmap);

        free(w->output);

        return mfree(w);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Writer, writer, writer_free);

int writer_open(Writer *w, const char *filename) {
        int r;

        assert(w);
        assert(filename);

        r = journal_file_open_reliably(filename, O_RDWR|O_CREAT, w->server->file_flags, 0640, UINT64_MAX,
                                       &w->metrics, w->mmap, /* seqnum_id= */ NULL, &w->journal);
        if (r < 0)
                return log_error_errno(r, "Failed to open output journal '%s': %m", filename);

        w->file_rotation_usec = file_rotation_usec(w->journal, w->server->max_file_usec);
        log_debug("Opened output file %s", w->journal->path);
        return 0;
}

static bool writer_file_age_reached(Writer *w) {
        assert(w);
        assert(w->journal);

        return w->server->max_file_usec > 0 &&
                le64toh(w->journal->header->n_entries) > 0 &&
                now(CLOCK_MONOTONIC) >= w->file_rotation_usec;
}

int writer_maintain(Writer *w) {
        int r;

        assert(w);

        if (!w->journal || !writer_file_age_reached(w))
                return 0;

        log_info("%s: File age limit reached, rotating", w->journal->path);
        r = do_rotate(w, w->server->file_flags);
        if (r < 0)
                return r;

        return writer_vacuum(w);
}

int writer_maintain_directory(RemoteServer *s) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(s);

        if (s->split_mode != JOURNAL_WRITE_SPLIT_HOST)
                return 0;

        d = opendir(s->output);
        if (!d)
                return -errno;

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_(writer_unrefp) Writer *w = NULL;
                _cleanup_free_ char *path = NULL;

                if (!dirent_is_file(de) || !startswith(de->d_name, "remote-") || !endswith(de->d_name, ".journal") ||
                    strchr(de->d_name, '@'))
                        continue;

                path = path_join(s->output, de->d_name);
                if (!path)
                        return -ENOMEM;

                r = writer_new(s, &w);
                if (r < 0)
                        return r;

                r = journal_file_open(/* fd= */ -EBADF, path, O_RDONLY|O_NOFOLLOW, /* file_flags= */ 0,
                                      /* mode= */ 0, UINT64_MAX, /* metrics= */ NULL, w->mmap,
                                      /* template= */ NULL, &w->journal);
                if (r < 0) {
                        log_warning_errno(r, "Failed to open idle journal '%s', ignoring: %m", path);
                        continue;
                }
                w->file_rotation_usec = file_rotation_usec(w->journal, s->max_file_usec);
                if (w->journal->header->state != STATE_OFFLINE || !writer_file_age_reached(w))
                        continue;

                w->journal = journal_file_close(w->journal);
                r = writer_open(w, path);
                if (r < 0)
                        continue;

                log_info("%s: File age limit reached, archiving", path);
                r = journal_file_archive(w->journal, /* ret_previous_path= */ NULL);
                if (r < 0) {
                        log_warning_errno(r, "Failed to archive idle journal '%s', ignoring: %m", path);
                        continue;
                }

                w->journal = journal_file_offline_close(w->journal);
                r = writer_vacuum(w);
                if (r < 0)
                        log_warning_errno(r, "Failed to vacuum journals in '%s', ignoring: %m", w->output);
        }

        return 0;
}

int writer_write(Writer *w,
                 const struct iovec_wrapper *iovw,
                 const dual_timestamp *ts,
                 const sd_id128_t *boot_id,
                 JournalFileFlags file_flags) {
        int r;

        assert(w);
        assert(!iovw_isempty(iovw));

        if (!w->journal)
                return -EIO;

        if (journal_file_rotate_suggested(w->journal, /* max_file_usec= */ 0, LOG_DEBUG) ||
            writer_file_age_reached(w)) {
                log_info("%s: Journal limits reached or header out-of-date, rotating",
                         w->journal->path);

                r = do_rotate(w, file_flags);
                if (r < 0)
                        return r;

                r = writer_vacuum(w);
                if (r < 0)
                        return r;
        }

        writer_start_file(w);
        r = journal_file_append_entry(
                        w->journal,
                        ts,
                        boot_id,
                        iovw->iovec,
                        iovw->count,
                        &w->seqnum,
                        /* seqnum_id= */ NULL,
                        /* ret_object= */ NULL,
                        /* ret_offset= */ NULL);
        if (r >= 0) {
                if (w->server)
                        w->server->event_count += 1;
                return 0;
        }
        if (r == -EBADMSG)
                return r;

        log_debug_errno(r, "%s: Write failed, rotating: %m", w->journal->path);
        r = do_rotate(w, file_flags);
        if (r < 0)
                return r;

        log_debug("%s: Successfully rotated journal", w->journal->path);
        r = writer_vacuum(w);
        if (r < 0)
                return r;

        log_debug("Retrying write.");
        writer_start_file(w);
        r = journal_file_append_entry(
                        w->journal,
                        ts,
                        boot_id,
                        iovw->iovec, iovw->count,
                        &w->seqnum,
                        /* seqnum_id= */ NULL,
                        /* ret_object= */ NULL,
                        /* ret_offset= */ NULL);
        if (r < 0)
                return r;

        if (w->server)
                w->server->event_count += 1;
        return 0;
}
