/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "async.h"
#include "chattr-util.h"
#include "copy.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "journal-authenticate.h"
#include "journal-file-util.h"
#include "path-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "sync-util.h"

#define PAYLOAD_BUFFER_SIZE (16U * 1024U)
#define MINIMUM_HOLE_SIZE (1U * 1024U * 1024U / 2U)

static int journal_file_end_punch_hole(JournalFile *f) {
        uint64_t p, sz;
        int r;

        r = journal_file_tail_end_by_pread(f, &p);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine end of tail object: %m");

        assert(p <= (uint64_t) f->last_stat.st_size);

        sz = ((uint64_t) f->last_stat.st_size) - p;
        if (sz < MINIMUM_HOLE_SIZE)
                return 0;

        if (fallocate(f->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, p, sz) < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), /* Make recognizable */
                                               "Hole punching not supported by backing file system, skipping.");

                return log_debug_errno(errno, "Failed to punch hole at end of journal file %s: %m", f->path);
        }

        return 0;
}

static int journal_file_entry_array_punch_hole(JournalFile *f, uint64_t p, uint64_t n_entries) {
        Object o;
        uint64_t offset, sz, n_items = 0, n_unused;
        int r;

        if (n_entries == 0)
                return 0;

        for (uint64_t q = p; q != 0; q = le64toh(o.entry_array.next_entry_array_offset)) {
                r = journal_file_read_object_header(f, OBJECT_ENTRY_ARRAY, q, &o);
                if (r < 0)
                        return r;

                n_items += journal_file_entry_array_n_items(f, &o);
                p = q;
        }

        if (p == 0)
                return 0;

        if (n_entries > n_items)
                return -EBADMSG;

        /* Amount of unused items in the final entry array. */
        n_unused = n_items - n_entries;

        if (n_unused == 0)
                return 0;

        offset = p + offsetof(Object, entry_array.items) +
                (journal_file_entry_array_n_items(f, &o) - n_unused) * journal_file_entry_array_item_size(f);
        sz = p + le64toh(o.object.size) - offset;

        if (sz < MINIMUM_HOLE_SIZE)
                return 0;

        if (fallocate(f->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, sz) < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), /* Make recognizable */
                                               "Hole punching not supported by backing file system, skipping.");

                return log_debug_errno(errno, "Failed to punch hole in entry array of %s: %m", f->path);
        }

        return 0;
}

static int journal_file_punch_holes(JournalFile *f) {
        HashItem items[PAYLOAD_BUFFER_SIZE / sizeof(HashItem)];
        uint64_t p, sz;
        ssize_t n = SSIZE_MAX;
        int r;

        assert(f);

        r = journal_file_end_punch_hole(f);
        if (r < 0)
                return r;

        r = journal_file_entry_array_punch_hole(
                        f, le64toh(f->header->entry_array_offset), le64toh(f->header->n_entries));
        if (r < 0)
                return r;

        p = le64toh(f->header->data_hash_table_offset);
        sz = le64toh(f->header->data_hash_table_size);

        for (uint64_t i = p; i < p + sz && n > 0; i += n) {
                size_t m = MIN(sizeof(items), p + sz - i);
                n = pread(f->fd, items, m, i);
                if (n < 0)
                        return log_debug_errno(errno, "Failed to read hash table items: %m");

                /* Let's ignore any partial hash items by rounding down to the nearest multiple of HashItem. */
                n -= n % sizeof(HashItem);

                for (size_t j = 0; j < (size_t) n / sizeof(HashItem); j++) {
                        Object o;

                        for (uint64_t q = le64toh(items[j].head_hash_offset); q != 0;
                             q = le64toh(o.data.next_hash_offset)) {

                                r = journal_file_read_object_header(f, OBJECT_DATA, q, &o);
                                if (r < 0) {
                                        log_debug_errno(r, "Invalid data object: %m, ignoring");
                                        break;
                                }

                                if (le64toh(o.data.n_entries) == 0)
                                        continue;

                                r = journal_file_entry_array_punch_hole(
                                                f, le64toh(o.data.entry_array_offset), le64toh(o.data.n_entries) - 1);
                                if (r == -EOPNOTSUPP)
                                        return -EOPNOTSUPP;

                                /* Ignore other errors */
                        }
                }
        }

        return 0;
}

void journal_file_finalize(JournalFile *f, uint8_t state) {
        int r;

        assert(f);
        assert(IN_SET(state, STATE_OFFLINE, STATE_ARCHIVED));

        if (!journal_file_writable(f))
                return;

#if HAVE_GCRYPT
        /* Write the final tag. */
        r = journal_file_append_tag(f);
        if (r < 0)
                log_debug_errno(r, "Failed to append tag on closing journal file %s, ignoring: %m", f->path);
#endif

        /* offlining the file. */
        r = journal_file_set_state(f, state);
        if (r < 0)
                log_debug_errno(r, "Failed to offlining journal file %s, ignoring: %m", f->path);

        /* If there is a scheduled task, finish it now. */
        if (sd_event_source_get_enabled(f->post_change_timer, NULL) > 0) {
                journal_file_post_change(f);
                sd_event_source_set_enabled(f->post_change_timer, SD_EVENT_OFF);
        }
}

JournalFile* journal_file_offline_close(JournalFile *f) {
        if (!f)
                return NULL;

        if (!journal_file_writable(f))
                return journal_file_close(f);

        assert(f->close_fd);
        assert(f->fd >= 0);
        journal_file_finalize(f, STATE_OFFLINE);
        (void) asynchronous_fsync_and_close(TAKE_FD(f->fd));
        return journal_file_close(f);
}

static void journal_file_post_archive_tasks(JournalFile *f) {
        int r;

        assert(f);
        assert(f->fd >= 0);
        assert(f->path);

        (void) journal_file_punch_holes(f);

        if (fsync(f->fd) < 0)
                log_debug_errno(errno, "Failed to fsync() journal file '%s', ignoring: %m", f->path);

        /* If we've archived the journal file, first try to re-enable COW on the file. If the FS_NOCOW_FL
         * flag was never set or we successfully removed it, continue. If we fail to remove the flag on the
         * archived file, rewrite the file without the NOCOW flag. We need this fallback because on some
         * filesystems (BTRFS), the NOCOW flag cannot be removed after data has been written to a file. The
         * only way to remove it is to copy all data to a new file without the NOCOW flag set. */
        r = chattr_fd(f->fd, 0, FS_NOCOW_FL, NULL);
        if (r < 0) {
                log_debug_errno(r, "Failed to re-enable copy-on-write for %s, rewriting file: %m", f->path);

                /* Here, setting COPY_VERIFY_LINKED flag is crucial. Otherwise, a broken journal file may be
                 * created, if journal_directory_vacuum() -> unlinkat_deallocate() is called in the main
                 * process while this process is copying the file. See issue #24150 and #31222. */
                r = copy_file_atomic_at_full(
                                f->fd, NULL, AT_FDCWD, f->path, f->mode,
                                0,
                                FS_NOCOW_FL,
                                COPY_REPLACE | COPY_FSYNC | COPY_HOLES | COPY_ALL_XATTRS | COPY_VERIFY_LINKED,
                                NULL, NULL);
                if (r < 0)
                        log_debug_errno(r, "Failed to rewrite %s, ignoring: %m", f->path);
        }
}

static void asynchronous_post_archive_tasks(JournalFile *f) {
        int r;

        assert(f);
        assert(f->fd >= 0);

        r = safe_fork_full("(journal-archiver)", NULL, &f->fd, 1, FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DETACH, NULL);
        if (r < 0) {
                /* On failure, process synchronously. */
                log_debug_errno(r, "Failed to fork for archiving journal file '%s', ignoring: %m", f->path);
                journal_file_post_archive_tasks(f);
                return;
        }
        if (r > 0) /* Parent process */
                return;

        /* Child process */
        journal_file_post_archive_tasks(f);
        _exit(EXIT_SUCCESS);
}

static int journal_file_archive_impl(JournalFile *f, char **ret_original_name) {
        int r;

        assert(f);
        assert(f->fd >= 0);
        assert(f->header);

        if (!journal_file_writable(f))
                return -EPERM;

        if (f->header->state == STATE_ARCHIVED)
                return -EINVAL;

        r = journal_file_rename_for_archiving(f, ret_original_name);
        if (r < 0)
                return r;

        journal_file_finalize(f, STATE_ARCHIVED);

        asynchronous_post_archive_tasks(f);
        return 0;
}

int journal_file_archive(JournalFile *f) {
        int r;

        assert(f);

        /* When this function succeeds, the JournalFile object is invalidated. */

        r = journal_file_archive_impl(f, NULL);
        if (r < 0)
                return r;

        journal_file_close(f);
        return 0;
}

int journal_file_rotate(
                JournalFile **f,
                MMapCache *mmap_cache,
                JournalFileFlags file_flags,
                uint64_t compress_threshold_bytes) {

        _cleanup_free_ char *path = NULL;
        JournalFile *new_file = NULL;
        int r;

        assert(f);
        assert(*f);

        r = journal_file_archive_impl(*f, &path);
        if (r < 0)
                return r;

        r = journal_file_open(
                        /* fd= */ -EBADF,
                        path,
                        (*f)->open_flags,
                        file_flags,
                        (*f)->mode,
                        compress_threshold_bytes,
                        /* metrics= */ NULL,
                        mmap_cache,
                        /* template= */ *f,
                        &new_file);

        journal_file_close(*f);

        *f = new_file;
        return r;
}

int journal_file_open_reliably(
                const char *fname,
                int open_flags,
                JournalFileFlags file_flags,
                mode_t mode,
                uint64_t compress_threshold_bytes,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                JournalFile **ret) {

        _cleanup_(journal_file_offline_closep) JournalFile *old_file = NULL;
        int r;

        r = journal_file_open(
                        /* fd= */ -EBADF,
                        fname,
                        open_flags,
                        file_flags,
                        mode,
                        compress_threshold_bytes,
                        metrics,
                        mmap_cache,
                        /* template = */ NULL,
                        ret);
        if (!IN_SET(r,
                    -EBADMSG,           /* Corrupted */
                    -EADDRNOTAVAIL,     /* Referenced object offset out of bounds */
                    -ENODATA,           /* Truncated */
                    -EHOSTDOWN,         /* Other machine */
                    -EPROTONOSUPPORT,   /* Incompatible feature */
                    -EBUSY,             /* Unclean shutdown */
                    -ESHUTDOWN,         /* Already archived */
                    -EIO,               /* IO error, including SIGBUS on mmap */
                    -EIDRM))            /* File has been deleted */
                return r;

        if ((open_flags & O_ACCMODE) == O_RDONLY)
                return r;

        if (!(open_flags & O_CREAT))
                return r;

        if (!endswith(fname, ".journal"))
                return r;

        /* The file is corrupted. Rotate it away and try it again (but only once) */
        log_warning_errno(r, "File %s corrupted or uncleanly shut down, renaming and replacing.", fname);

        /* The file is corrupted. Try opening it read-only as the template before rotating to inherit its
         * sequence number and ID. */
        r = journal_file_open(-EBADF, fname,
                              (open_flags & ~(O_ACCMODE|O_CREAT|O_EXCL)) | O_RDONLY,
                              file_flags, 0, compress_threshold_bytes, NULL,
                              mmap_cache, /* template = */ NULL, &old_file);
        if (r < 0)
                log_debug_errno(r, "Failed to continue sequence from file %s, ignoring: %m", fname);

        r = journal_file_dispose(AT_FDCWD, fname);
        if (r < 0)
                return r;

        return journal_file_open(-EBADF, fname, open_flags, file_flags, mode, compress_threshold_bytes, metrics,
                                 mmap_cache, /* template = */ old_file, ret);
}
