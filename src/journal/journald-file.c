/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <unistd.h>

#include "chattr-util.h"
#include "copy.h"
#include "fd-util.h"
#include "format-util.h"
#include "journal-authenticate.h"
#include "journald-file.h"
#include "path-util.h"
#include "random-util.h"
#include "set.h"
#include "stat-util.h"
#include "sync-util.h"

#define PAYLOAD_BUFFER_SIZE (16U * 1024U)
#define MINIMUM_HOLE_SIZE (1U * 1024U * 1024U / 2U)

static int journald_file_truncate(JournalFile *f) {
        uint64_t p;
        int r;

        /* truncate excess from the end of archives */
        r = journal_file_tail_end(f, &p);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine end of tail object: %m");

        /* arena_size can't exceed the file size, ensure it's updated before truncating */
        f->header->arena_size = htole64(p - le64toh(f->header->header_size));

        if (ftruncate(f->fd, p) < 0)
                log_debug_errno(errno, "Failed to truncate %s: %m", f->path);

        return 0;
}

static int journald_file_entry_array_punch_hole(JournalFile *f, uint64_t p, uint64_t n_entries) {
        Object o;
        uint64_t offset, sz, n_items = 0, n_unused;
        int r;

        if (n_entries == 0)
                return 0;

        for (uint64_t q = p; q != 0; q = le64toh(o.entry_array.next_entry_array_offset)) {
                r = journal_file_read_object(f, OBJECT_ENTRY_ARRAY, q, &o);
                if (r < 0)
                        return r;

                n_items += journal_file_entry_array_n_items(&o);
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
                (journal_file_entry_array_n_items(&o) - n_unused) * sizeof(le64_t);
        sz = p + le64toh(o.object.size) - offset;

        if (sz < MINIMUM_HOLE_SIZE)
                return 0;

        if (fallocate(f->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, sz) < 0)
                return log_debug_errno(errno, "Failed to punch hole in entry array of %s: %m", f->path);

        return 0;
}

static int journald_file_punch_holes(JournalFile *f) {
        HashItem items[PAYLOAD_BUFFER_SIZE / sizeof(HashItem)];
        uint64_t p, sz;
        ssize_t n = SSIZE_MAX;
        int r;

        r = journald_file_entry_array_punch_hole(
                f, le64toh(f->header->entry_array_offset), le64toh(f->header->n_entries));
        if (r < 0)
                return r;

        p = le64toh(f->header->data_hash_table_offset);
        sz = le64toh(f->header->data_hash_table_size);

        for (uint64_t i = p; i < p + sz && n > 0; i += n) {
                n = pread(f->fd, items, MIN(sizeof(items), p + sz - i), i);
                if (n < 0)
                        return n;

                /* Let's ignore any partial hash items by rounding down to the nearest multiple of HashItem. */
                n -= n % sizeof(HashItem);

                for (size_t j = 0; j < (size_t) n / sizeof(HashItem); j++) {
                        Object o;

                        for (uint64_t q = le64toh(items[j].head_hash_offset); q != 0;
                             q = le64toh(o.data.next_hash_offset)) {

                                r = journal_file_read_object(f, OBJECT_DATA, q, &o);
                                if (r < 0) {
                                        log_debug_errno(r, "Invalid data object: %m, ignoring");
                                        break;
                                }

                                if (le64toh(o.data.n_entries) == 0)
                                        continue;

                                (void) journald_file_entry_array_punch_hole(
                                        f, le64toh(o.data.entry_array_offset), le64toh(o.data.n_entries) - 1);
                        }
                }
        }

        return 0;
}

/* This may be called from a separate thread to prevent blocking the caller for the duration of fsync().
 * As a result we use atomic operations on f->offline_state for inter-thread communications with
 * journal_file_set_offline() and journal_file_set_online(). */
static void journald_file_set_offline_internal(JournaldFile *f) {
        int r;

        assert(f);
        assert(f->file->fd >= 0);
        assert(f->file->header);

        for (;;) {
                switch (f->file->offline_state) {
                case OFFLINE_CANCEL:
                        if (!__sync_bool_compare_and_swap(&f->file->offline_state, OFFLINE_CANCEL, OFFLINE_DONE))
                                continue;
                        return;

                case OFFLINE_AGAIN_FROM_SYNCING:
                        if (!__sync_bool_compare_and_swap(&f->file->offline_state, OFFLINE_AGAIN_FROM_SYNCING, OFFLINE_SYNCING))
                                continue;
                        break;

                case OFFLINE_AGAIN_FROM_OFFLINING:
                        if (!__sync_bool_compare_and_swap(&f->file->offline_state, OFFLINE_AGAIN_FROM_OFFLINING, OFFLINE_SYNCING))
                                continue;
                        break;

                case OFFLINE_SYNCING:
                        if (f->file->archive) {
                                (void) journald_file_truncate(f->file);
                                (void) journald_file_punch_holes(f->file);
                        }

                        (void) fsync(f->file->fd);

                        if (!__sync_bool_compare_and_swap(&f->file->offline_state, OFFLINE_SYNCING, OFFLINE_OFFLINING))
                                continue;

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

                                r = copy_file_atomic(f->file->path, f->file->path, f->file->mode, 0, FS_NOCOW_FL, COPY_REPLACE | COPY_FSYNC | COPY_HOLES);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to rewrite %s: %m", f->file->path);
                                        continue;
                                }
                        }

                        break;

                case OFFLINE_OFFLINING:
                        if (!__sync_bool_compare_and_swap(&f->file->offline_state, OFFLINE_OFFLINING, OFFLINE_DONE))
                                continue;
                        _fallthrough_;
                case OFFLINE_DONE:
                        return;

                case OFFLINE_JOINED:
                        log_debug("OFFLINE_JOINED unexpected offline state for journal_file_set_offline_internal()");
                        return;
                }
        }
}

static void * journald_file_set_offline_thread(void *arg) {
        JournaldFile *f = arg;

        (void) pthread_setname_np(pthread_self(), "journal-offline");

        journald_file_set_offline_internal(f);

        return NULL;
}

/* Trigger a restart if the offline thread is mid-flight in a restartable state. */
static bool journald_file_set_offline_try_restart(JournaldFile *f) {
        for (;;) {
                switch (f->file->offline_state) {
                case OFFLINE_AGAIN_FROM_SYNCING:
                case OFFLINE_AGAIN_FROM_OFFLINING:
                        return true;

                case OFFLINE_CANCEL:
                        if (!__sync_bool_compare_and_swap(&f->file->offline_state, OFFLINE_CANCEL, OFFLINE_AGAIN_FROM_SYNCING))
                                continue;
                        return true;

                case OFFLINE_SYNCING:
                        if (!__sync_bool_compare_and_swap(&f->file->offline_state, OFFLINE_SYNCING, OFFLINE_AGAIN_FROM_SYNCING))
                                continue;
                        return true;

                case OFFLINE_OFFLINING:
                        if (!__sync_bool_compare_and_swap(&f->file->offline_state, OFFLINE_OFFLINING, OFFLINE_AGAIN_FROM_OFFLINING))
                                continue;
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
int journald_file_set_offline(JournaldFile *f, bool wait) {
        int target_state;
        bool restarted;
        int r;

        assert(f);

        if (!f->file->writable)
                return -EPERM;

        if (f->file->fd < 0 || !f->file->header)
                return -EINVAL;

        target_state = f->file->archive ? STATE_ARCHIVED : STATE_OFFLINE;

        /* An offlining journal is implicitly online and may modify f->header->state,
         * we must also join any potentially lingering offline thread when already in
         * the desired offline state.
         */
        if (!journald_file_is_offlining(f) && f->file->header->state == target_state)
                return journal_file_set_offline_thread_join(f->file);

        /* Restart an in-flight offline thread and wait if needed, or join a lingering done one. */
        restarted = journald_file_set_offline_try_restart(f);
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
                journald_file_set_offline_internal(f);
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

                r = pthread_create(&f->file->offline_thread, NULL, journald_file_set_offline_thread, f);

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

bool journald_file_is_offlining(JournaldFile *f) {
        assert(f);

        __sync_synchronize();

        if (IN_SET(f->file->offline_state, OFFLINE_DONE, OFFLINE_JOINED))
                return false;

        return true;
}

JournaldFile* journald_file_close(JournaldFile *f) {
        if (!f)
                return NULL;

#if HAVE_GCRYPT
        /* Write the final tag */
        if (f->file->seal && f->file->writable) {
                int r;

                r = journal_file_append_tag(f->file);
                if (r < 0)
                        log_error_errno(r, "Failed to append tag when closing journal: %m");
        }
#endif

        if (f->file->post_change_timer) {
                if (sd_event_source_get_enabled(f->file->post_change_timer, NULL) > 0)
                        journal_file_post_change(f->file);

                sd_event_source_disable_unref(f->file->post_change_timer);
        }

        journald_file_set_offline(f, true);

        journal_file_close(f->file);

        return mfree(f);
}

int journald_file_open(
                int fd,
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                JournaldFile *template,
                JournaldFile **ret) {
        _cleanup_free_ JournaldFile *f = NULL;
        int r;

        set_clear_with_destructor(deferred_closes, journald_file_close);

        f = new0(JournaldFile, 1);
        if (!f)
                return -ENOMEM;

        r = journal_file_open(fd, fname, flags, mode, compress, compress_threshold_bytes, seal, metrics,
                              mmap_cache, template ? template->file : NULL, &f->file);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);

        return 0;
}


JournaldFile* journald_file_initiate_close(JournaldFile *f, Set *deferred_closes) {
        int r;

        assert(f);

        if (deferred_closes) {
                r = set_put(deferred_closes, f);
                if (r < 0)
                        log_debug_errno(r, "Failed to add file to deferred close set, closing immediately.");
                else {
                        (void) journald_file_set_offline(f, false);
                        return NULL;
                }
        }

        return journald_file_close(f);
}

int journald_file_rotate(
                JournaldFile **f,
                MMapCache *mmap_cache,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                Set *deferred_closes) {

        _cleanup_free_ char *path = NULL;
        JournaldFile *new_file = NULL;
        int r;

        assert(f);
        assert(*f);

        r = journal_file_archive((*f)->file, &path);
        if (r < 0)
                return r;

        r = journald_file_open(
                        -1,
                        path,
                        (*f)->file->flags,
                        (*f)->file->mode,
                        compress,
                        compress_threshold_bytes,
                        seal,
                        NULL,            /* metrics */
                        mmap_cache,
                        deferred_closes,
                        *f,              /* template */
                        &new_file);

        journald_file_initiate_close(*f, deferred_closes);
        *f = new_file;

        return r;
}

int journald_file_open_reliably(
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                JournaldFile *template,
                JournaldFile **ret) {

        int r;

        r = journald_file_open(-1, fname, flags, mode, compress, compress_threshold_bytes, seal, metrics,
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

        if ((flags & O_ACCMODE) == O_RDONLY)
                return r;

        if (!(flags & O_CREAT))
                return r;

        if (!endswith(fname, ".journal"))
                return r;

        /* The file is corrupted. Rotate it away and try it again (but only once) */
        log_warning_errno(r, "File %s corrupted or uncleanly shut down, renaming and replacing.", fname);

        r = journal_file_dispose(AT_FDCWD, fname);
        if (r < 0)
                return r;

        return journald_file_open(-1, fname, flags, mode, compress, compress_threshold_bytes, seal, metrics,
                                  mmap_cache, deferred_closes, template, ret);
}
