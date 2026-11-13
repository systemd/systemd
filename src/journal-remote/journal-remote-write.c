/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hashmap.h"
#include "journal-file-util.h"
#include "journal-remote.h"
#include "journal-vacuum.h"
#include "log.h"
#include "path-util.h"
#include "stat-util.h"
#include "time-util.h"

static int do_rotate(Writer *w, JournalFileFlags file_flags) {
        int r;

        assert(w);

        r = journal_file_rotate(&w->journal, w->mmap, file_flags, UINT64_MAX, /* seqnum_id= */ NULL, /* deferred_closes= */ NULL);
        if (r < 0)
                return r;

        w->file_opened_usec = now(CLOCK_MONOTONIC);
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

static bool writer_file_age_reached(Writer *w) {
        assert(w);
        assert(w->journal);

        return w->server->max_file_usec > 0 &&
                le64toh(w->journal->header->n_entries) > 0 &&
                now(CLOCK_MONOTONIC) >= usec_add(w->file_opened_usec, w->server->max_file_usec);
}

int writer_maintain(Writer *w) {
        bool idle;
        int r;

        assert(w);
        assert(w->server);

        idle = w->server->split_mode == JOURNAL_WRITE_SPLIT_HOST && w->n_ref == 1;
        if (!w->journal || le64toh(w->journal->header->n_entries) == 0)
                return idle;
        if (!writer_file_age_reached(w))
                return 0;

        log_info("%s: File age limit reached, %s", w->journal->path, idle ? "archiving" : "rotating");
        if (idle) {
                r = journal_file_archive(w->journal, /* ret_previous_path= */ NULL);
                if (r < 0)
                        return r;

                w->journal = journal_file_offline_close(w->journal);
        } else {
                r = do_rotate(w, w->server->file_flags);
                if (r < 0)
                        return r;
        }

        r = journal_directory_vacuum(w->output, w->metrics.max_use, w->metrics.n_max_files,
                                     w->server->max_retention_usec, /* oldest_usec= */ NULL, /* verbose= */ true);
        if (r < 0)
                return r;

        return idle;
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

                r = journal_directory_vacuum(w->output, w->metrics.max_use, w->metrics.n_max_files, w->server->max_retention_usec, /* oldest_usec= */ NULL, /* verbose= */ true);
                if (r < 0)
                        return r;
        }

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
        r = journal_directory_vacuum(w->output, w->metrics.max_use, w->metrics.n_max_files, w->server->max_retention_usec, /* oldest_usec= */ NULL, /* verbose= */ true);
        if (r < 0)
                return r;

        log_debug("Retrying write.");
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
