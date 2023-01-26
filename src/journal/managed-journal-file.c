/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <unistd.h>

#include "chattr-util.h"
#include "copy.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "journal-authenticate.h"
#include "managed-journal-file.h"
#include "path-util.h"
#include "random-util.h"
#include "set.h"
#include "stat-util.h"
#include "sync-util.h"

#define PAYLOAD_BUFFER_SIZE (16U * 1024U)
#define MINIMUM_HOLE_SIZE (1U * 1024U * 1024U / 2U)

static int managed_journal_file_truncate(JournalFile *f) {
        uint64_t p;
        int r;

        /* truncate excess from the end of archives */
        r = journal_file_tail_end_by_pread(f, &p);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine end of tail object: %m");

        /* arena_size can't exceed the file size, ensure it's updated before truncating */
        f->header->arena_size = htole64(p - le64toh(f->header->header_size));

        if (ftruncate(f->fd, p) < 0)
                return log_debug_errno(errno, "Failed to truncate %s: %m", f->path);

        return journal_file_fstat(f);
}

static int managed_journal_file_entry_array_punch_hole(JournalFile *f, uint64_t p, uint64_t n_entries) {
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

        if (p == le64toh(f->header->tail_object_offset) && !JOURNAL_HEADER_SEALED(f->header)) {
                ssize_t n;

                o.object.size = htole64(offset - p);

                n = pwrite(f->fd, &o, sizeof(EntryArrayObject), p);
                if (n < 0)
                        return log_debug_errno(errno, "Failed to modify entry array object size: %m");
                if ((size_t) n != sizeof(EntryArrayObject))
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Short pwrite() while modifying entry array object size.");

                f->header->arena_size = htole64(ALIGN64(offset) - le64toh(f->header->header_size));

                if (ftruncate(f->fd, ALIGN64(offset)) < 0)
                        return log_debug_errno(errno, "Failed to truncate %s: %m", f->path);

                return 0;
        }

        if (fallocate(f->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, sz) < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), /* Make recognizable */
                                               "Hole punching not supported by backing file system, skipping.");

                return log_debug_errno(errno, "Failed to punch hole in entry array of %s: %m", f->path);
        }

        return 0;
}

static int managed_journal_file_punch_holes(JournalFile *f) {
        HashItem items[PAYLOAD_BUFFER_SIZE / sizeof(HashItem)];
        uint64_t p, sz;
        ssize_t n = SSIZE_MAX;
        int r;

        r = managed_journal_file_entry_array_punch_hole(
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

                                r = managed_journal_file_entry_array_punch_hole(
                                                f, le64toh(o.data.entry_array_offset), le64toh(o.data.n_entries) - 1);
                                if (r == -EOPNOTSUPP)
                                        return -EOPNOTSUPP;

                                /* Ignore other errors */
                        }
                }
        }

        return 0;
}

/* This may be called from a separate thread to prevent blocking the caller for the duration of fsync().
 * As a result we use atomic operations on f->offline_state for inter-thread communications with
 * journal_file_set_offline() and journal_file_set_online(). */
static void managed_journal_file_set_offline_internal(ManagedJournalFile *f) {
        int r;

        assert(f);
        assert(f->file->fd >= 0);
        assert(f->file->header);

        for (;;) {
                switch (f->file->offline_state) {
                case OFFLINE_CANCEL: {
                        OfflineState tmp_state = OFFLINE_CANCEL;
                        if (!__atomic_compare_exchange_n(&f->file->offline_state, &tmp_state, OFFLINE_DONE,
                                                         false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                                continue;
                        }
                        return;

                case OFFLINE_AGAIN_FROM_SYNCING: {
                        OfflineState tmp_state = OFFLINE_AGAIN_FROM_SYNCING;
                        if (!__atomic_compare_exchange_n(&f->file->offline_state, &tmp_state, OFFLINE_SYNCING,
                                                         false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                                continue;
                        }
                        break;

                case OFFLINE_AGAIN_FROM_OFFLINING: {
                        OfflineState tmp_state = OFFLINE_AGAIN_FROM_OFFLINING;
                        if (!__atomic_compare_exchange_n(&f->file->offline_state, &tmp_state, OFFLINE_SYNCING,
                                                         false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                                continue;
                        }
                        break;

                case OFFLINE_SYNCING:
                        if (f->file->archive) {
                                (void) managed_journal_file_truncate(f->file);
                                (void) managed_journal_file_punch_holes(f->file);
                        }

                        (void) fsync(f->file->fd);

                        {
                                OfflineState tmp_state = OFFLINE_SYNCING;
                                if (!__atomic_compare_exchange_n(&f->file->offline_state, &tmp_state, OFFLINE_OFFLINING,
                                                                 false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                                        continue;
                        }

                        f->file->header->state = f->file->archive ? STATE_ARCHIVED : STATE_OFFLINE;
                        (void) fsync(f->file->fd);

                        /* If we've archived the journal file, first try to re-enable COW on the file. If the
                         * FS_NOCOW_FL flag was never set or we successfully removed it, continue. If we fail
                         * to remove the flag on the archived file, rewrite the file without the NOCOW flag.
                         * We need this fallback because on some filesystems (BTRFS), the NOCOW flag cannot
                         * be removed after data has been written to a file. The only way to remove it is to
                         * copy all data to a new file without the NOCOW flag set. */

                        if (f->file->archive) {
                                r = chattr_fd(f->file->fd, 0, FS_NOCOW_FL, NULL);
                                if (r >= 0)
                                        continue;

                                log_debug_errno(r, "Failed to re-enable copy-on-write for %s: %m, rewriting file", f->file->path);

                                r = copy_file_atomic(FORMAT_PROC_FD_PATH(f->file->fd), f->file->path, f->file->mode,
                                                     0,
                                                     FS_NOCOW_FL,
                                                     COPY_REPLACE | COPY_FSYNC | COPY_HOLES | COPY_ALL_XATTRS);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to rewrite %s: %m", f->file->path);
                                        continue;
                                }
                        }

                        break;

                case OFFLINE_OFFLINING: {
                        OfflineState tmp_state = OFFLINE_OFFLINING;
                        if (!__atomic_compare_exchange_n(&f->file->offline_state, &tmp_state, OFFLINE_DONE,
                                                         false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                                continue;
                        }
                        _fallthrough_;
                case OFFLINE_DONE:
                        return;

                case OFFLINE_JOINED:
                        log_debug("OFFLINE_JOINED unexpected offline state for journal_file_set_offline_internal()");
                        return;
                }
        }
}

static void * managed_journal_file_set_offline_thread(void *arg) {
        ManagedJournalFile *f = arg;

        (void) pthread_setname_np(pthread_self(), "journal-offline");

        managed_journal_file_set_offline_internal(f);

        return NULL;
}

/* Trigger a restart if the offline thread is mid-flight in a restartable state. */
static bool managed_journal_file_set_offline_try_restart(ManagedJournalFile *f) {
        for (;;) {
                switch (f->file->offline_state) {
                case OFFLINE_AGAIN_FROM_SYNCING:
                case OFFLINE_AGAIN_FROM_OFFLINING:
                        return true;

                case OFFLINE_CANCEL: {
                        OfflineState tmp_state = OFFLINE_CANCEL;
                        if (!__atomic_compare_exchange_n(&f->file->offline_state, &tmp_state, OFFLINE_AGAIN_FROM_SYNCING,
                                                         false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                                continue;
                        }
                        return true;

                case OFFLINE_SYNCING: {
                        OfflineState tmp_state = OFFLINE_SYNCING;
                        if (!__atomic_compare_exchange_n(&f->file->offline_state, &tmp_state, OFFLINE_AGAIN_FROM_SYNCING,
                                                         false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                                continue;
                        }
                        return true;

                case OFFLINE_OFFLINING: {
                        OfflineState tmp_state = OFFLINE_OFFLINING;
                        if (!__atomic_compare_exchange_n(&f->file->offline_state, &tmp_state, OFFLINE_AGAIN_FROM_OFFLINING,
                                                         false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                                continue;
                        }
                        return true;

                default:
                        return false;
                }
        }
}

/* Sets a journal offline.
 *
 * If wait is false then an offline is dispatched in a separate thread for a
 * subsequent journal_file_set_offline() or journal_file_set_online() of the
 * same journal to synchronize with.
 *
 * If wait is true, then either an existing offline thread will be restarted
 * and joined, or if none exists the offline is simply performed in this
 * context without involving another thread.
 */
int managed_journal_file_set_offline(ManagedJournalFile *f, bool wait) {
        int target_state;
        bool restarted;
        int r;

        assert(f);

        if (!journal_file_writable(f->file))
                return -EPERM;

        if (f->file->fd < 0 || !f->file->header)
                return -EINVAL;

        target_state = f->file->archive ? STATE_ARCHIVED : STATE_OFFLINE;

        /* An offlining journal is implicitly online and may modify f->header->state,
         * we must also join any potentially lingering offline thread when already in
         * the desired offline state.
         */
        if (!managed_journal_file_is_offlining(f) && f->file->header->state == target_state)
                return journal_file_set_offline_thread_join(f->file);

        /* Restart an in-flight offline thread and wait if needed, or join a lingering done one. */
        restarted = managed_journal_file_set_offline_try_restart(f);
        if ((restarted && wait) || !restarted) {
                r = journal_file_set_offline_thread_join(f->file);
                if (r < 0)
                        return r;
        }

        if (restarted)
                return 0;

        /* Initiate a new offline. */
        f->file->offline_state = OFFLINE_SYNCING;

        if (wait) /* Without using a thread if waiting. */
                managed_journal_file_set_offline_internal(f);
        else {
                sigset_t ss, saved_ss;
                int k;

                assert_se(sigfillset(&ss) >= 0);
                /* Don't block SIGBUS since the offlining thread accesses a memory mapped file.
                 * Asynchronous SIGBUS signals can safely be handled by either thread. */
                assert_se(sigdelset(&ss, SIGBUS) >= 0);

                r = pthread_sigmask(SIG_BLOCK, &ss, &saved_ss);
                if (r > 0)
                        return -r;

                r = pthread_create(&f->file->offline_thread, NULL, managed_journal_file_set_offline_thread, f);

                k = pthread_sigmask(SIG_SETMASK, &saved_ss, NULL);
                if (r > 0) {
                        f->file->offline_state = OFFLINE_JOINED;
                        return -r;
                }
                if (k > 0)
                        return -k;
        }

        return 0;
}

bool managed_journal_file_is_offlining(ManagedJournalFile *f) {
        assert(f);

        __atomic_thread_fence(__ATOMIC_SEQ_CST);

        if (IN_SET(f->file->offline_state, OFFLINE_DONE, OFFLINE_JOINED))
                return false;

        return true;
}

ManagedJournalFile* managed_journal_file_close(ManagedJournalFile *f) {
        if (!f)
                return NULL;

#if HAVE_GCRYPT
        /* Write the final tag */
        if (JOURNAL_HEADER_SEALED(f->file->header) && journal_file_writable(f->file)) {
                int r;

                r = journal_file_append_tag(f->file);
                if (r < 0)
                        log_error_errno(r, "Failed to append tag when closing journal: %m");
        }
#endif

        if (sd_event_source_get_enabled(f->file->post_change_timer, NULL) > 0)
                journal_file_post_change(f->file);
        sd_event_source_disable_unref(f->file->post_change_timer);

        managed_journal_file_set_offline(f, true);

        journal_file_close(f->file);

        return mfree(f);
}

int managed_journal_file_open(
                int fd,
                const char *fname,
                int open_flags,
                JournalFileFlags file_flags,
                mode_t mode,
                uint64_t compress_threshold_bytes,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                ManagedJournalFile *template,
                ManagedJournalFile **ret) {
        _cleanup_free_ ManagedJournalFile *f = NULL;
        int r;

        set_clear_with_destructor(deferred_closes, managed_journal_file_close);

        f = new0(ManagedJournalFile, 1);
        if (!f)
                return -ENOMEM;

        r = journal_file_open(fd, fname, open_flags, file_flags, mode, compress_threshold_bytes, metrics,
                              mmap_cache, template ? template->file : NULL, &f->file);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);

        return 0;
}


ManagedJournalFile* managed_journal_file_initiate_close(ManagedJournalFile *f, Set *deferred_closes) {
        int r;

        assert(f);

        if (deferred_closes) {
                r = set_put(deferred_closes, f);
                if (r < 0)
                        log_debug_errno(r, "Failed to add file to deferred close set, closing immediately.");
                else {
                        (void) managed_journal_file_set_offline(f, false);
                        return NULL;
                }
        }

        return managed_journal_file_close(f);
}

int managed_journal_file_rotate(
                ManagedJournalFile **f,
                MMapCache *mmap_cache,
                JournalFileFlags file_flags,
                uint64_t compress_threshold_bytes,
                Set *deferred_closes) {

        _cleanup_free_ char *path = NULL;
        ManagedJournalFile *new_file = NULL;
        int r;

        assert(f);
        assert(*f);

        r = journal_file_archive((*f)->file, &path);
        if (r < 0)
                return r;

        r = managed_journal_file_open(
                        -1,
                        path,
                        (*f)->file->open_flags,
                        file_flags,
                        (*f)->file->mode,
                        compress_threshold_bytes,
                        NULL,            /* metrics */
                        mmap_cache,
                        deferred_closes,
                        *f,              /* template */
                        &new_file);

        managed_journal_file_initiate_close(*f, deferred_closes);
        *f = new_file;

        return r;
}

int managed_journal_file_open_reliably(
                const char *fname,
                int open_flags,
                JournalFileFlags file_flags,
                mode_t mode,
                uint64_t compress_threshold_bytes,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                ManagedJournalFile *template,
                ManagedJournalFile **ret) {

        _cleanup_(managed_journal_file_closep) ManagedJournalFile *old_file = NULL;
        int r;

        r = managed_journal_file_open(-1, fname, open_flags, file_flags, mode, compress_threshold_bytes, metrics,
                                      mmap_cache, deferred_closes, template, ret);
        if (!IN_SET(r,
                    -EBADMSG,           /* Corrupted */
                    -ENODATA,           /* Truncated */
                    -EHOSTDOWN,         /* Other machine */
                    -EPROTONOSUPPORT,   /* Incompatible feature */
                    -EBUSY,             /* Unclean shutdown */
                    -ESHUTDOWN,         /* Already archived */
                    -EIO,               /* IO error, including SIGBUS on mmap */
                    -EIDRM,             /* File has been deleted */
                    -ETXTBSY))          /* File is from the future */
                return r;

        if ((open_flags & O_ACCMODE) == O_RDONLY)
                return r;

        if (!(open_flags & O_CREAT))
                return r;

        if (!endswith(fname, ".journal"))
                return r;

        /* The file is corrupted. Rotate it away and try it again (but only once) */
        log_warning_errno(r, "File %s corrupted or uncleanly shut down, renaming and replacing.", fname);

        if (!template) {
                /* The file is corrupted and no template is specified. Try opening it read-only as the
                 * template before rotating to inherit its sequence number and ID. */
                r = managed_journal_file_open(-1, fname,
                                              (open_flags & ~(O_ACCMODE|O_CREAT|O_EXCL)) | O_RDONLY,
                                              file_flags, 0, compress_threshold_bytes, NULL,
                                              mmap_cache, deferred_closes, NULL, &old_file);
                if (r < 0)
                        log_debug_errno(r, "Failed to continue sequence from file %s, ignoring: %m", fname);
                else
                        template = old_file;
        }

        r = journal_file_dispose(AT_FDCWD, fname);
        if (r < 0)
                return r;

        return managed_journal_file_open(-1, fname, open_flags, file_flags, mode, compress_threshold_bytes, metrics,
                                         mmap_cache, deferred_closes, template, ret);
}
