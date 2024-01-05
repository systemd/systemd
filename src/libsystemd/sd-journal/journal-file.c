/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <pthread.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <sys/uio.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "chattr-util.h"
#include "compress.h"
#include "env-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "id128-util.h"
#include "journal-authenticate.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-internal.h"
#include "lookup3.h"
#include "memory-util.h"
#include "missing_threads.h"
#include "path-util.h"
#include "prioq.h"
#include "random-util.h"
#include "set.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "sync-util.h"
#include "user-util.h"
#include "xattr-util.h"

#define DEFAULT_DATA_HASH_TABLE_SIZE (2047ULL*sizeof(HashItem))
#define DEFAULT_FIELD_HASH_TABLE_SIZE (333ULL*sizeof(HashItem))

#define DEFAULT_COMPRESS_THRESHOLD (512ULL)
#define MIN_COMPRESS_THRESHOLD (8ULL)

/* This is the minimum journal file size */
#define JOURNAL_FILE_SIZE_MIN (512 * U64_KB)             /* 512 KiB */
#define JOURNAL_COMPACT_SIZE_MAX ((uint64_t) UINT32_MAX) /* 4 GiB */

/* These are the lower and upper bounds if we deduce the max_use value from the file system size */
#define MAX_USE_LOWER (1 * U64_MB)                       /* 1 MiB */
#define MAX_USE_UPPER (4 * U64_GB)                       /* 4 GiB */

/* Those are the lower and upper bounds for the minimal use limit,
 * i.e. how much we'll use even if keep_free suggests otherwise. */
#define MIN_USE_LOW  (1  * U64_MB)                       /* 1 MiB */
#define MIN_USE_HIGH (16 * U64_MB)                       /* 16 MiB */

/* This is the upper bound if we deduce max_size from max_use */
#define MAX_SIZE_UPPER (128 * U64_MB)                    /* 128 MiB */

/* This is the upper bound if we deduce the keep_free value from the file system size */
#define KEEP_FREE_UPPER (4 * U64_GB)                     /* 4 GiB */

/* This is the keep_free value when we can't determine the system size */
#define DEFAULT_KEEP_FREE (1 * U64_MB)                   /* 1 MB */

/* This is the default maximum number of journal files to keep around. */
#define DEFAULT_N_MAX_FILES 100

/* n_data was the first entry we added after the initial file format design */
#define HEADER_SIZE_MIN ALIGN64(offsetof(Header, n_data))

/* How many entries to keep in the entry array chain cache at max */
#define CHAIN_CACHE_MAX 20

/* How much to increase the journal file size at once each time we allocate something new. */
#define FILE_SIZE_INCREASE (8 * U64_MB)                  /* 8MB */

/* Reread fstat() of the file for detecting deletions at least this often */
#define LAST_STAT_REFRESH_USEC (5*USEC_PER_SEC)

/* Longest hash chain to rotate after */
#define HASH_CHAIN_DEPTH_MAX 100

#ifdef __clang__
#  pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

static int mmap_prot_from_open_flags(int flags) {
        switch (flags & O_ACCMODE) {
        case O_RDONLY:
                return PROT_READ;
        case O_WRONLY:
                return PROT_WRITE;
        case O_RDWR:
                return PROT_READ|PROT_WRITE;
        default:
                assert_not_reached();
        }
}

int journal_file_tail_end_by_pread(JournalFile *f, uint64_t *ret_offset) {
        uint64_t p;
        int r;

        assert(f);
        assert(f->header);
        assert(ret_offset);

        /* Same as journal_file_tail_end_by_mmap() below, but operates with pread() to avoid the mmap cache
         * (and thus is thread safe) */

        p = le64toh(f->header->tail_object_offset);
        if (p == 0)
                p = le64toh(f->header->header_size);
        else {
                Object tail;
                uint64_t sz;

                r = journal_file_read_object_header(f, OBJECT_UNUSED, p, &tail);
                if (r < 0)
                        return r;

                sz = le64toh(tail.object.size);
                if (sz > UINT64_MAX - sizeof(uint64_t) + 1)
                        return -EBADMSG;

                sz = ALIGN64(sz);
                if (p > UINT64_MAX - sz)
                        return -EBADMSG;

                p += sz;
        }

        *ret_offset = p;

        return 0;
}

int journal_file_tail_end_by_mmap(JournalFile *f, uint64_t *ret_offset) {
        uint64_t p;
        int r;

        assert(f);
        assert(f->header);
        assert(ret_offset);

        /* Same as journal_file_tail_end_by_pread() above, but operates with the usual mmap logic */

        p = le64toh(f->header->tail_object_offset);
        if (p == 0)
                p = le64toh(f->header->header_size);
        else {
                Object *tail;
                uint64_t sz;

                r = journal_file_move_to_object(f, OBJECT_UNUSED, p, &tail);
                if (r < 0)
                        return r;

                sz = le64toh(READ_NOW(tail->object.size));
                if (sz > UINT64_MAX - sizeof(uint64_t) + 1)
                        return -EBADMSG;

                sz = ALIGN64(sz);
                if (p > UINT64_MAX - sz)
                        return -EBADMSG;

                p += sz;
        }

        *ret_offset = p;

        return 0;
}

int journal_file_set_offline_thread_join(JournalFile *f) {
        int r;

        assert(f);

        if (__atomic_load_n(&f->offline_state, __ATOMIC_SEQ_CST) == OFFLINE_JOINED)
                return 0;

        r = pthread_join(f->offline_thread, NULL);
        if (r)
                return -r;

        __atomic_store_n(&f->offline_state, OFFLINE_JOINED, __ATOMIC_SEQ_CST);

        if (mmap_cache_fd_got_sigbus(f->cache_fd))
                return -EIO;

        return 0;
}

static int journal_file_set_online(JournalFile *f) {
        OfflineState tmp_state;
        bool wait;
        assert(f);

        if (!journal_file_writable(f))
                return -EPERM;

        if (f->fd < 0 || !f->header)
                return -EINVAL;

        wait = true;
        tmp_state = __atomic_load_n(&f->offline_state, __ATOMIC_SEQ_CST);
        do {
                switch (tmp_state) {
                case OFFLINE_JOINED:
                        /* No offline thread, no need to wait. */
                        wait = false;
                        break;

                case OFFLINE_SYNCING: {
                                if (!__atomic_compare_exchange_n(&f->offline_state, &tmp_state, OFFLINE_CANCEL,
                                    false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                                        continue;
                        }
                        /* Canceled syncing prior to offlining, no need to wait. */
                        wait = false;
                        break;

                case OFFLINE_AGAIN_FROM_SYNCING: {
                                if (!__atomic_compare_exchange_n(&f->offline_state, &tmp_state, OFFLINE_CANCEL,
                                    false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                                        continue;
                        }
                        /* Canceled restart from syncing, no need to wait. */
                        wait = false;
                        break;

                case OFFLINE_AGAIN_FROM_OFFLINING: {
                                if (!__atomic_compare_exchange_n(&f->offline_state, &tmp_state, OFFLINE_CANCEL,
                                    false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                                        continue;
                        }
                        /* Canceled restart from offlining, must wait for offlining to complete however. */
                        _fallthrough_;
                default: {
                        int r;

                        r = journal_file_set_offline_thread_join(f);
                        if (r < 0)
                                return r;

                        wait = false;
                        break;
                }
                }
        } while (wait);

        if (mmap_cache_fd_got_sigbus(f->cache_fd))
                return -EIO;

        switch (f->header->state) {
                case STATE_ONLINE:
                        return 0;

                case STATE_OFFLINE:
                        f->header->state = STATE_ONLINE;
                        (void) fsync(f->fd);
                        return 0;

                default:
                        return -EINVAL;
        }
}

JournalFile* journal_file_close(JournalFile *f) {
        if (!f)
                return NULL;

        assert(f->newest_boot_id_prioq_idx == PRIOQ_IDX_NULL);

        if (f->cache_fd)
                mmap_cache_fd_free(f->cache_fd);

        if (f->close_fd)
                safe_close(f->fd);
        free(f->path);

        ordered_hashmap_free_free(f->chain_cache);

#if HAVE_COMPRESSION
        free(f->compress_buffer);
#endif

#if HAVE_GCRYPT
        if (f->fss_file) {
                size_t sz = PAGE_ALIGN(f->fss_file_size);
                assert(sz < SIZE_MAX);
                munmap(f->fss_file, sz);
        } else
                free(f->fsprg_state);

        free(f->fsprg_seed);

        if (f->hmac)
                gcry_md_close(f->hmac);
#endif

        return mfree(f);
}

static bool keyed_hash_requested(void) {
        static thread_local int cached = -1;
        int r;

        if (cached < 0) {
                r = getenv_bool("SYSTEMD_JOURNAL_KEYED_HASH");
                if (r < 0) {
                        if (r != -ENXIO)
                                log_debug_errno(r, "Failed to parse $SYSTEMD_JOURNAL_KEYED_HASH environment variable, ignoring: %m");
                        cached = true;
                } else
                        cached = r;
        }

        return cached;
}

static bool compact_mode_requested(void) {
        static thread_local int cached = -1;
        int r;

        if (cached < 0) {
                r = getenv_bool("SYSTEMD_JOURNAL_COMPACT");
                if (r < 0) {
                        if (r != -ENXIO)
                                log_debug_errno(r, "Failed to parse $SYSTEMD_JOURNAL_COMPACT environment variable, ignoring: %m");
                        cached = true;
                } else
                        cached = r;
        }

        return cached;
}

#if HAVE_COMPRESSION
static Compression getenv_compression(void) {
        Compression c;
        const char *e;
        int r;

        e = getenv("SYSTEMD_JOURNAL_COMPRESS");
        if (!e)
                return DEFAULT_COMPRESSION;

        r = parse_boolean(e);
        if (r >= 0)
                return r ? DEFAULT_COMPRESSION : COMPRESSION_NONE;

        c = compression_from_string(e);
        if (c < 0) {
                log_debug_errno(c, "Failed to parse SYSTEMD_JOURNAL_COMPRESS value, ignoring: %s", e);
                return DEFAULT_COMPRESSION;
        }

        if (!compression_supported(c)) {
                log_debug("Unsupported compression algorithm specified, ignoring: %s", e);
                return DEFAULT_COMPRESSION;
        }

        return c;
}
#endif

static Compression compression_requested(void) {
#if HAVE_COMPRESSION
        static thread_local Compression cached = _COMPRESSION_INVALID;

        if (cached < 0)
                cached = getenv_compression();

        return cached;
#else
        return COMPRESSION_NONE;
#endif
}

static int journal_file_init_header(
                JournalFile *f,
                JournalFileFlags file_flags,
                JournalFile *template) {

        bool seal = false;
        ssize_t k;
        int r;

        assert(f);

#if HAVE_GCRYPT
        /* Try to load the FSPRG state, and if we can't, then just don't do sealing */
        seal = FLAGS_SET(file_flags, JOURNAL_SEAL) && journal_file_fss_load(f) >= 0;
#endif

        Header h = {
                .header_size = htole64(ALIGN64(sizeof(h))),
                .incompatible_flags = htole32(
                                FLAGS_SET(file_flags, JOURNAL_COMPRESS) * COMPRESSION_TO_HEADER_INCOMPATIBLE_FLAG(compression_requested()) |
                                keyed_hash_requested() * HEADER_INCOMPATIBLE_KEYED_HASH |
                                compact_mode_requested() * HEADER_INCOMPATIBLE_COMPACT),
                .compatible_flags = htole32(
                                (seal * (HEADER_COMPATIBLE_SEALED | HEADER_COMPATIBLE_SEALED_CONTINUOUS) ) |
                                HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID),
        };

        assert_cc(sizeof(h.signature) == sizeof(HEADER_SIGNATURE));
        memcpy(h.signature, HEADER_SIGNATURE, sizeof(HEADER_SIGNATURE));

        r = sd_id128_randomize(&h.file_id);
        if (r < 0)
                return r;

        r = sd_id128_get_machine(&h.machine_id);
        if (r < 0 && !ERRNO_IS_MACHINE_ID_UNSET(r))
                return r; /* If we have no valid machine ID (test environment?), let's simply leave the
                           * machine ID field all zeroes. */

        if (template) {
                h.seqnum_id = template->header->seqnum_id;
                h.tail_entry_seqnum = template->header->tail_entry_seqnum;
        } else
                h.seqnum_id = h.file_id;

        k = pwrite(f->fd, &h, sizeof(h), 0);
        if (k < 0)
                return -errno;
        if (k != sizeof(h))
                return -EIO;

        return 0;
}

static int journal_file_refresh_header(JournalFile *f) {
        int r;

        assert(f);
        assert(f->header);

        /* We used to update the header's boot ID field here, but we don't do that anymore, as per
         * HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID */

        r = journal_file_set_online(f);

        /* Sync the online state to disk; likely just created a new file, also sync the directory this file
         * is located in. */
        (void) fsync_full(f->fd);

        return r;
}

static bool warn_wrong_flags(const JournalFile *f, bool compatible) {
        const uint32_t any = compatible ? HEADER_COMPATIBLE_ANY : HEADER_INCOMPATIBLE_ANY,
                supported = compatible ? HEADER_COMPATIBLE_SUPPORTED : HEADER_INCOMPATIBLE_SUPPORTED;
        const char *type = compatible ? "compatible" : "incompatible";
        uint32_t flags;

        assert(f);
        assert(f->header);

        flags = le32toh(compatible ? f->header->compatible_flags : f->header->incompatible_flags);

        if (flags & ~supported) {
                if (flags & ~any)
                        log_debug("Journal file %s has unknown %s flags 0x%"PRIx32,
                                  f->path, type, flags & ~any);
                flags = (flags & any) & ~supported;
                if (flags) {
                        const char* strv[6];
                        size_t n = 0;
                        _cleanup_free_ char *t = NULL;

                        if (compatible) {
                                if (flags & HEADER_COMPATIBLE_SEALED)
                                        strv[n++] = "sealed";
                                if (flags & HEADER_COMPATIBLE_SEALED_CONTINUOUS)
                                        strv[n++] = "sealed-continuous";
                        } else {
                                if (flags & HEADER_INCOMPATIBLE_COMPRESSED_XZ)
                                        strv[n++] = "xz-compressed";
                                if (flags & HEADER_INCOMPATIBLE_COMPRESSED_LZ4)
                                        strv[n++] = "lz4-compressed";
                                if (flags & HEADER_INCOMPATIBLE_COMPRESSED_ZSTD)
                                        strv[n++] = "zstd-compressed";
                                if (flags & HEADER_INCOMPATIBLE_KEYED_HASH)
                                        strv[n++] = "keyed-hash";
                                if (flags & HEADER_INCOMPATIBLE_COMPACT)
                                        strv[n++] = "compact";
                        }
                        strv[n] = NULL;
                        assert(n < ELEMENTSOF(strv));

                        t = strv_join((char**) strv, ", ");
                        log_debug("Journal file %s uses %s %s %s disabled at compilation time.",
                                  f->path, type, n > 1 ? "flags" : "flag", strnull(t));
                }
                return true;
        }

        return false;
}

static bool offset_is_valid(uint64_t offset, uint64_t header_size, uint64_t tail_object_offset) {
        if (offset == 0)
                return true;
        if (!VALID64(offset))
                return false;
        if (offset < header_size)
                return false;
        if (offset > tail_object_offset)
                return false;
        return true;
}

static bool hash_table_is_valid(uint64_t offset, uint64_t size, uint64_t header_size, uint64_t arena_size, uint64_t tail_object_offset) {
        if ((offset == 0) != (size == 0))
                return false;
        if (offset == 0)
                return true;
        if (offset <= offsetof(Object, hash_table.items))
                return false;
        offset -= offsetof(Object, hash_table.items);
        if (!offset_is_valid(offset, header_size, tail_object_offset))
                return false;
        assert(offset <= header_size + arena_size);
        if (size > header_size + arena_size - offset)
                return false;
        return true;
}

static int journal_file_verify_header(JournalFile *f) {
        uint64_t arena_size, header_size;

        assert(f);
        assert(f->header);

        if (memcmp(f->header->signature, HEADER_SIGNATURE, 8))
                return -EBADMSG;

        /* In both read and write mode we refuse to open files with incompatible
         * flags we don't know. */
        if (warn_wrong_flags(f, false))
                return -EPROTONOSUPPORT;

        /* When open for writing we refuse to open files with compatible flags, too. */
        if (journal_file_writable(f) && warn_wrong_flags(f, true))
                return -EPROTONOSUPPORT;

        if (f->header->state >= _STATE_MAX)
                return -EBADMSG;

        header_size = le64toh(READ_NOW(f->header->header_size));

        /* The first addition was n_data, so check that we are at least this large */
        if (header_size < HEADER_SIZE_MIN)
                return -EBADMSG;

        /* When open for writing we refuse to open files with a mismatch of the header size, i.e. writing to
         * files implementing older or new header structures. */
        if (journal_file_writable(f) && header_size != sizeof(Header))
                return -EPROTONOSUPPORT;

        /* Don't write to journal files without the new boot ID update behavior guarantee. */
        if (journal_file_writable(f) && !JOURNAL_HEADER_TAIL_ENTRY_BOOT_ID(f->header))
                return -EPROTONOSUPPORT;

        if (JOURNAL_HEADER_SEALED(f->header) && !JOURNAL_HEADER_CONTAINS(f->header, n_entry_arrays))
                return -EBADMSG;

        arena_size = le64toh(READ_NOW(f->header->arena_size));

        if (UINT64_MAX - header_size < arena_size || header_size + arena_size > (uint64_t) f->last_stat.st_size)
                return -ENODATA;

        uint64_t tail_object_offset = le64toh(f->header->tail_object_offset);
        if (!offset_is_valid(tail_object_offset, header_size, UINT64_MAX))
                return -ENODATA;
        if (header_size + arena_size < tail_object_offset)
                return -ENODATA;
        if (header_size + arena_size - tail_object_offset < sizeof(ObjectHeader))
                return -ENODATA;

        if (!hash_table_is_valid(le64toh(f->header->data_hash_table_offset),
                                 le64toh(f->header->data_hash_table_size),
                                 header_size, arena_size, tail_object_offset))
                return -ENODATA;

        if (!hash_table_is_valid(le64toh(f->header->field_hash_table_offset),
                                 le64toh(f->header->field_hash_table_size),
                                 header_size, arena_size, tail_object_offset))
                return -ENODATA;

        uint64_t entry_array_offset = le64toh(f->header->entry_array_offset);
        if (!offset_is_valid(entry_array_offset, header_size, tail_object_offset))
                return -ENODATA;

        if (JOURNAL_HEADER_CONTAINS(f->header, tail_entry_array_offset)) {
                uint32_t offset = le32toh(f->header->tail_entry_array_offset);
                uint32_t n = le32toh(f->header->tail_entry_array_n_entries);

                if (!offset_is_valid(offset, header_size, tail_object_offset))
                        return -ENODATA;
                if (entry_array_offset > offset)
                        return -ENODATA;
                if (entry_array_offset == 0 && offset != 0)
                        return -ENODATA;
                if ((offset == 0) != (n == 0))
                        return -ENODATA;
                assert(offset <= header_size + arena_size);
                if ((uint64_t) n * journal_file_entry_array_item_size(f) > header_size + arena_size - offset)
                        return -ENODATA;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, tail_entry_offset)) {
                uint64_t offset = le64toh(f->header->tail_entry_offset);

                if (!offset_is_valid(offset, header_size, tail_object_offset))
                        return -ENODATA;

                if (offset > 0) {
                        /* When there is an entry object, then these fields must be filled. */
                        if (sd_id128_is_null(f->header->tail_entry_boot_id))
                                return -ENODATA;
                        if (!VALID_REALTIME(le64toh(f->header->head_entry_realtime)))
                                return -ENODATA;
                        if (!VALID_REALTIME(le64toh(f->header->tail_entry_realtime)))
                                return -ENODATA;
                        if (!VALID_MONOTONIC(le64toh(f->header->tail_entry_realtime)))
                                return -ENODATA;
                } else {
                        /* Otherwise, the fields must be zero. */
                        if (JOURNAL_HEADER_TAIL_ENTRY_BOOT_ID(f->header) &&
                            !sd_id128_is_null(f->header->tail_entry_boot_id))
                                return -ENODATA;
                        if (f->header->head_entry_realtime != 0)
                                return -ENODATA;
                        if (f->header->tail_entry_realtime != 0)
                                return -ENODATA;
                        if (f->header->tail_entry_realtime != 0)
                                return -ENODATA;
                }
        }

        /* Verify number of objects */
        uint64_t n_objects = le64toh(f->header->n_objects);
        if (n_objects > arena_size / sizeof(ObjectHeader))
                return -ENODATA;

        uint64_t n_entries = le64toh(f->header->n_entries);
        if (n_entries > n_objects)
                return -ENODATA;

        if (JOURNAL_HEADER_CONTAINS(f->header, n_data) &&
            le64toh(f->header->n_data) > n_objects)
                return -ENODATA;

        if (JOURNAL_HEADER_CONTAINS(f->header, n_fields) &&
            le64toh(f->header->n_fields) > n_objects)
                return -ENODATA;

        if (JOURNAL_HEADER_CONTAINS(f->header, n_tags) &&
            le64toh(f->header->n_tags) > n_objects)
                return -ENODATA;

        if (JOURNAL_HEADER_CONTAINS(f->header, n_entry_arrays) &&
            le64toh(f->header->n_entry_arrays) > n_objects)
                return -ENODATA;

        if (JOURNAL_HEADER_CONTAINS(f->header, tail_entry_array_n_entries) &&
            le32toh(f->header->tail_entry_array_n_entries) > n_entries)
                return -ENODATA;

        if (journal_file_writable(f)) {
                sd_id128_t machine_id;
                uint8_t state;
                int r;

                r = sd_id128_get_machine(&machine_id);
                if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r)) /* Gracefully handle the machine ID not being initialized yet */
                        machine_id = SD_ID128_NULL;
                else if (r < 0)
                        return r;

                if (!sd_id128_equal(machine_id, f->header->machine_id))
                        return log_debug_errno(SYNTHETIC_ERRNO(EHOSTDOWN),
                                               "Trying to open journal file from different host for writing, refusing.");

                state = f->header->state;

                if (state == STATE_ARCHIVED)
                        return -ESHUTDOWN; /* Already archived */
                if (state == STATE_ONLINE)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBUSY),
                                               "Journal file %s is already online. Assuming unclean closing.",
                                               f->path);
                if (state != STATE_OFFLINE)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBUSY),
                                               "Journal file %s has unknown state %i.",
                                               f->path, state);

                if (f->header->field_hash_table_size == 0 || f->header->data_hash_table_size == 0)
                        return -EBADMSG;
        }

        return 0;
}

int journal_file_fstat(JournalFile *f) {
        int r;

        assert(f);
        assert(f->fd >= 0);

        if (fstat(f->fd, &f->last_stat) < 0)
                return -errno;

        f->last_stat_usec = now(CLOCK_MONOTONIC);

        /* Refuse dealing with files that aren't regular */
        r = stat_verify_regular(&f->last_stat);
        if (r < 0)
                return r;

        /* Refuse appending to files that are already deleted */
        if (f->last_stat.st_nlink <= 0)
                return -EIDRM;

        return 0;
}

static int journal_file_allocate(JournalFile *f, uint64_t offset, uint64_t size) {
        uint64_t old_size, new_size, old_header_size, old_arena_size;
        int r;

        assert(f);
        assert(f->header);

        /* We assume that this file is not sparse, and we know that for sure, since we always call
         * posix_fallocate() ourselves */

        if (size > PAGE_ALIGN_DOWN_U64(UINT64_MAX) - offset)
                return -EINVAL;

        if (mmap_cache_fd_got_sigbus(f->cache_fd))
                return -EIO;

        old_header_size = le64toh(READ_NOW(f->header->header_size));
        old_arena_size = le64toh(READ_NOW(f->header->arena_size));
        if (old_arena_size > PAGE_ALIGN_DOWN_U64(UINT64_MAX) - old_header_size)
                return -EBADMSG;

        old_size = old_header_size + old_arena_size;

        new_size = MAX(PAGE_ALIGN_U64(offset + size), old_header_size);

        if (new_size <= old_size) {

                /* We already pre-allocated enough space, but before
                 * we write to it, let's check with fstat() if the
                 * file got deleted, in order make sure we don't throw
                 * away the data immediately. Don't check fstat() for
                 * all writes though, but only once ever 10s. */

                if (f->last_stat_usec + LAST_STAT_REFRESH_USEC > now(CLOCK_MONOTONIC))
                        return 0;

                return journal_file_fstat(f);
        }

        /* Allocate more space. */

        if (f->metrics.max_size > 0 && new_size > f->metrics.max_size)
                return -E2BIG;

        /* Refuse to go over 4G in compact mode so offsets can be stored in 32-bit. */
        if (JOURNAL_HEADER_COMPACT(f->header) && new_size > UINT32_MAX)
                return -E2BIG;

        if (new_size > f->metrics.min_size && f->metrics.keep_free > 0) {
                struct statvfs svfs;

                if (fstatvfs(f->fd, &svfs) >= 0) {
                        uint64_t available;

                        available = LESS_BY(u64_multiply_safe(svfs.f_bfree, svfs.f_bsize), f->metrics.keep_free);

                        if (new_size - old_size > available)
                                return -E2BIG;
                }
        }

        /* Increase by larger blocks at once */
        new_size = ROUND_UP(new_size, FILE_SIZE_INCREASE);
        if (f->metrics.max_size > 0 && new_size > f->metrics.max_size)
                new_size = f->metrics.max_size;

        /* Note that the glibc fallocate() fallback is very
           inefficient, hence we try to minimize the allocation area
           as we can. */
        r = posix_fallocate_loop(f->fd, old_size, new_size - old_size);
        if (r < 0)
                return r;

        f->header->arena_size = htole64(new_size - old_header_size);

        return journal_file_fstat(f);
}

static int journal_file_move_to(
                JournalFile *f,
                ObjectType type,
                bool keep_always,
                uint64_t offset,
                uint64_t size,
                void **ret) {

        int r;

        assert(f);
        assert(ret);

        /* This function may clear, overwrite, or alter previously cached entries with the same type. After
         * this function has been called, all previously read objects with the same type may be invalidated,
         * hence must be re-read before use. */

        if (size <= 0)
                return -EINVAL;

        if (size > UINT64_MAX - offset)
                return -EBADMSG;

        /* Avoid SIGBUS on invalid accesses */
        if (offset + size > (uint64_t) f->last_stat.st_size) {
                /* Hmm, out of range? Let's refresh the fstat() data
                 * first, before we trust that check. */

                r = journal_file_fstat(f);
                if (r < 0)
                        return r;

                if (offset + size > (uint64_t) f->last_stat.st_size)
                        return -EADDRNOTAVAIL;
        }

        return mmap_cache_fd_get(f->cache_fd, type_to_category(type), keep_always, offset, size, &f->last_stat, ret);
}

static uint64_t minimum_header_size(JournalFile *f, Object *o) {

        static const uint64_t table[] = {
                [OBJECT_DATA]             = sizeof(DataObject),
                [OBJECT_FIELD]            = sizeof(FieldObject),
                [OBJECT_ENTRY]            = sizeof(EntryObject),
                [OBJECT_DATA_HASH_TABLE]  = sizeof(HashTableObject),
                [OBJECT_FIELD_HASH_TABLE] = sizeof(HashTableObject),
                [OBJECT_ENTRY_ARRAY]      = sizeof(EntryArrayObject),
                [OBJECT_TAG]              = sizeof(TagObject),
        };

        assert(f);
        assert(o);

        if (o->object.type == OBJECT_DATA)
                return journal_file_data_payload_offset(f);

        if (o->object.type >= ELEMENTSOF(table) || table[o->object.type] <= 0)
                return sizeof(ObjectHeader);

        return table[o->object.type];
}

static int check_object_header(JournalFile *f, Object *o, ObjectType type, uint64_t offset) {
        uint64_t s;

        assert(f);
        assert(o);

        s = le64toh(READ_NOW(o->object.size));
        if (s == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Attempt to move to uninitialized object: %" PRIu64,
                                       offset);

        if (s < sizeof(ObjectHeader))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Attempt to move to overly short object with size %"PRIu64": %" PRIu64,
                                       s, offset);

        if (o->object.type <= OBJECT_UNUSED || o->object.type >= _OBJECT_TYPE_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Attempt to move to object with invalid type (%u): %" PRIu64,
                                       o->object.type, offset);

        if (type > OBJECT_UNUSED && o->object.type != type)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Found %s object while expecting %s object: %" PRIu64,
                                       journal_object_type_to_string(o->object.type),
                                       journal_object_type_to_string(type),
                                       offset);

        if (s < minimum_header_size(f, o))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Size of %s object (%"PRIu64") is smaller than the minimum object size (%"PRIu64"): %" PRIu64,
                                       journal_object_type_to_string(o->object.type),
                                       s,
                                       minimum_header_size(f, o),
                                       offset);

        return 0;
}

/* Lightweight object checks. We want this to be fast, so that we won't
 * slowdown every journal_file_move_to_object() call too much. */
static int check_object(JournalFile *f, Object *o, uint64_t offset) {
        assert(f);
        assert(o);

        switch (o->object.type) {

        case OBJECT_DATA:
                if ((le64toh(o->data.entry_offset) == 0) ^ (le64toh(o->data.n_entries) == 0))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Bad data n_entries: %" PRIu64 ": %" PRIu64,
                                               le64toh(o->data.n_entries),
                                               offset);

                if (le64toh(o->object.size) <= journal_file_data_payload_offset(f))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Bad data size (<= %zu): %" PRIu64 ": %" PRIu64,
                                               journal_file_data_payload_offset(f),
                                               le64toh(o->object.size),
                                               offset);

                if (!VALID64(le64toh(o->data.next_hash_offset)) ||
                    !VALID64(le64toh(o->data.next_field_offset)) ||
                    !VALID64(le64toh(o->data.entry_offset)) ||
                    !VALID64(le64toh(o->data.entry_array_offset)))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid offset, next_hash_offset=" OFSfmt ", next_field_offset=" OFSfmt ", entry_offset=" OFSfmt ", entry_array_offset=" OFSfmt ": %" PRIu64,
                                               le64toh(o->data.next_hash_offset),
                                               le64toh(o->data.next_field_offset),
                                               le64toh(o->data.entry_offset),
                                               le64toh(o->data.entry_array_offset),
                                               offset);

                break;

        case OBJECT_FIELD:
                if (le64toh(o->object.size) <= offsetof(Object, field.payload))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Bad field size (<= %zu): %" PRIu64 ": %" PRIu64,
                                               offsetof(Object, field.payload),
                                               le64toh(o->object.size),
                                               offset);

                if (!VALID64(le64toh(o->field.next_hash_offset)) ||
                    !VALID64(le64toh(o->field.head_data_offset)))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid offset, next_hash_offset=" OFSfmt ", head_data_offset=" OFSfmt ": %" PRIu64,
                                               le64toh(o->field.next_hash_offset),
                                               le64toh(o->field.head_data_offset),
                                               offset);
                break;

        case OBJECT_ENTRY: {
                uint64_t sz;

                sz = le64toh(READ_NOW(o->object.size));
                if (sz < offsetof(Object, entry.items) ||
                    (sz - offsetof(Object, entry.items)) % journal_file_entry_item_size(f) != 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Bad entry size (<= %zu): %" PRIu64 ": %" PRIu64,
                                               offsetof(Object, entry.items),
                                               sz,
                                               offset);

                if ((sz - offsetof(Object, entry.items)) / journal_file_entry_item_size(f) <= 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid number items in entry: %" PRIu64 ": %" PRIu64,
                                               (sz - offsetof(Object, entry.items)) / journal_file_entry_item_size(f),
                                               offset);

                if (le64toh(o->entry.seqnum) <= 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid entry seqnum: %" PRIx64 ": %" PRIu64,
                                               le64toh(o->entry.seqnum),
                                               offset);

                if (!VALID_REALTIME(le64toh(o->entry.realtime)))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid entry realtime timestamp: %" PRIu64 ": %" PRIu64,
                                               le64toh(o->entry.realtime),
                                               offset);

                if (!VALID_MONOTONIC(le64toh(o->entry.monotonic)))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid entry monotonic timestamp: %" PRIu64 ": %" PRIu64,
                                               le64toh(o->entry.monotonic),
                                               offset);

                if (sd_id128_is_null(o->entry.boot_id))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid object entry with an empty boot ID: %" PRIu64,
                                               offset);

                break;
        }

        case OBJECT_DATA_HASH_TABLE:
        case OBJECT_FIELD_HASH_TABLE: {
                uint64_t sz;

                sz = le64toh(READ_NOW(o->object.size));
                if (sz < offsetof(Object, hash_table.items) ||
                    (sz - offsetof(Object, hash_table.items)) % sizeof(HashItem) != 0 ||
                    (sz - offsetof(Object, hash_table.items)) / sizeof(HashItem) <= 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid %s hash table size: %" PRIu64 ": %" PRIu64,
                                               journal_object_type_to_string(o->object.type),
                                               sz,
                                               offset);

                break;
        }

        case OBJECT_ENTRY_ARRAY: {
                uint64_t sz, next;

                sz = le64toh(READ_NOW(o->object.size));
                if (sz < offsetof(Object, entry_array.items) ||
                    (sz - offsetof(Object, entry_array.items)) % journal_file_entry_array_item_size(f) != 0 ||
                    (sz - offsetof(Object, entry_array.items)) / journal_file_entry_array_item_size(f) <= 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid object entry array size: %" PRIu64 ": %" PRIu64,
                                               sz,
                                               offset);
                /* Here, we request that the offset of each entry array object is in strictly increasing order. */
                next = le64toh(o->entry_array.next_entry_array_offset);
                if (!VALID64(next) || (next > 0 && next <= offset))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid object entry array next_entry_array_offset: %" PRIu64 ": %" PRIu64,
                                               next,
                                               offset);

                break;
        }

        case OBJECT_TAG:
                if (le64toh(o->object.size) != sizeof(TagObject))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid object tag size: %" PRIu64 ": %" PRIu64,
                                               le64toh(o->object.size),
                                               offset);

                if (!VALID_EPOCH(le64toh(o->tag.epoch)))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid object tag epoch: %" PRIu64 ": %" PRIu64,
                                               le64toh(o->tag.epoch), offset);

                break;
        }

        return 0;
}

int journal_file_move_to_object(JournalFile *f, ObjectType type, uint64_t offset, Object **ret) {
        int r;
        Object *o;

        assert(f);

        /* Even if this function fails, it may clear, overwrite, or alter previously cached entries with the
         * same type. After this function has been called, all previously read objects with the same type may
         * be invalidated, hence must be re-read before use. */

        /* Objects may only be located at multiple of 64 bit */
        if (!VALID64(offset))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Attempt to move to %s object at non-64-bit boundary: %" PRIu64,
                                       journal_object_type_to_string(type),
                                       offset);

        /* Object may not be located in the file header */
        if (offset < le64toh(f->header->header_size))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Attempt to move to %s object located in file header: %" PRIu64,
                                       journal_object_type_to_string(type),
                                       offset);

        r = journal_file_move_to(f, type, false, offset, sizeof(ObjectHeader), (void**) &o);
        if (r < 0)
                return r;

        r = check_object_header(f, o, type, offset);
        if (r < 0)
                return r;

        r = journal_file_move_to(f, type, false, offset, le64toh(READ_NOW(o->object.size)), (void**) &o);
        if (r < 0)
                return r;

        r = check_object_header(f, o, type, offset);
        if (r < 0)
                return r;

        r = check_object(f, o, offset);
        if (r < 0)
                return r;

        if (ret)
                *ret = o;

        return 0;
}

int journal_file_pin_object(JournalFile *f, Object *o) {
        assert(f);
        assert(o);

        /* This attaches the mmap window that provides the object to the 'pinning' category. So, reading
         * another object with the same type will not invalidate the object, until this function is called
         * for another object. */
        return mmap_cache_fd_pin(f->cache_fd, type_to_category(o->object.type), o, le64toh(o->object.size));
}

int journal_file_read_object_header(JournalFile *f, ObjectType type, uint64_t offset, Object *ret) {
        ssize_t n;
        Object o;
        int r;

        assert(f);

        /* Objects may only be located at multiple of 64 bit */
        if (!VALID64(offset))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Attempt to read %s object at non-64-bit boundary: %" PRIu64,
                                       journal_object_type_to_string(type), offset);

        /* Object may not be located in the file header */
        if (offset < le64toh(f->header->header_size))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Attempt to read %s object located in file header: %" PRIu64,
                                       journal_object_type_to_string(type), offset);

        /* This will likely read too much data but it avoids having to call pread() twice. */
        n = pread(f->fd, &o, sizeof(o), offset);
        if (n < 0)
                return log_debug_errno(errno, "Failed to read journal %s object at offset: %" PRIu64,
                                       journal_object_type_to_string(type), offset);

        if ((size_t) n < sizeof(o.object))
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to read short %s object at offset: %" PRIu64,
                                       journal_object_type_to_string(type), offset);

        r = check_object_header(f, &o, type, offset);
        if (r < 0)
                return r;

        if ((size_t) n < minimum_header_size(f, &o))
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                       "Short read while reading %s object: %" PRIu64,
                                       journal_object_type_to_string(type), offset);

        r = check_object(f, &o, offset);
        if (r < 0)
                return r;

        if (ret)
                *ret = o;

        return 0;
}

static uint64_t inc_seqnum(uint64_t seqnum) {
        if (seqnum < UINT64_MAX-1)
                return seqnum + 1;

        return 1; /* skip over UINT64_MAX and 0 when we run out of seqnums and start again */
}

static uint64_t journal_file_entry_seqnum(
                JournalFile *f,
                uint64_t *seqnum) {

        uint64_t next_seqnum;

        assert(f);
        assert(f->header);

        /* Picks a new sequence number for the entry we are about to add and returns it. */

        next_seqnum = inc_seqnum(le64toh(f->header->tail_entry_seqnum));

        /* If an external seqnum counter was passed, we update both the local and the external one, and set
         * it to the maximum of both */
        if (seqnum)
                *seqnum = next_seqnum = MAX(inc_seqnum(*seqnum), next_seqnum);

        f->header->tail_entry_seqnum = htole64(next_seqnum);

        if (f->header->head_entry_seqnum == 0)
                f->header->head_entry_seqnum = htole64(next_seqnum);

        return next_seqnum;
}

int journal_file_append_object(
                JournalFile *f,
                ObjectType type,
                uint64_t size,
                Object **ret_object,
                uint64_t *ret_offset) {

        int r;
        uint64_t p;
        Object *o;

        assert(f);
        assert(f->header);
        assert(type > OBJECT_UNUSED && type < _OBJECT_TYPE_MAX);
        assert(size >= sizeof(ObjectHeader));

        r = journal_file_set_online(f);
        if (r < 0)
                return r;

        r = journal_file_tail_end_by_mmap(f, &p);
        if (r < 0)
                return r;

        r = journal_file_allocate(f, p, size);
        if (r < 0)
                return r;

        r = journal_file_move_to(f, type, false, p, size, (void**) &o);
        if (r < 0)
                return r;

        o->object = (ObjectHeader) {
                .type = type,
                .size = htole64(size),
        };

        f->header->tail_object_offset = htole64(p);
        f->header->n_objects = htole64(le64toh(f->header->n_objects) + 1);

        if (ret_object)
                *ret_object = o;

        if (ret_offset)
                *ret_offset = p;

        return 0;
}

static int journal_file_setup_data_hash_table(JournalFile *f) {
        uint64_t s, p;
        Object *o;
        int r;

        assert(f);
        assert(f->header);

        /* We estimate that we need 1 hash table entry per 768 bytes
           of journal file and we want to make sure we never get
           beyond 75% fill level. Calculate the hash table size for
           the maximum file size based on these metrics. */

        s = (f->metrics.max_size * 4 / 768 / 3) * sizeof(HashItem);
        if (s < DEFAULT_DATA_HASH_TABLE_SIZE)
                s = DEFAULT_DATA_HASH_TABLE_SIZE;

        log_debug("Reserving %"PRIu64" entries in data hash table.", s / sizeof(HashItem));

        r = journal_file_append_object(f,
                                       OBJECT_DATA_HASH_TABLE,
                                       offsetof(Object, hash_table.items) + s,
                                       &o, &p);
        if (r < 0)
                return r;

        memzero(o->hash_table.items, s);

        f->header->data_hash_table_offset = htole64(p + offsetof(Object, hash_table.items));
        f->header->data_hash_table_size = htole64(s);

        return 0;
}

static int journal_file_setup_field_hash_table(JournalFile *f) {
        uint64_t s, p;
        Object *o;
        int r;

        assert(f);
        assert(f->header);

        /* We use a fixed size hash table for the fields as this
         * number should grow very slowly only */

        s = DEFAULT_FIELD_HASH_TABLE_SIZE;
        log_debug("Reserving %"PRIu64" entries in field hash table.", s / sizeof(HashItem));

        r = journal_file_append_object(f,
                                       OBJECT_FIELD_HASH_TABLE,
                                       offsetof(Object, hash_table.items) + s,
                                       &o, &p);
        if (r < 0)
                return r;

        memzero(o->hash_table.items, s);

        f->header->field_hash_table_offset = htole64(p + offsetof(Object, hash_table.items));
        f->header->field_hash_table_size = htole64(s);

        return 0;
}

int journal_file_map_data_hash_table(JournalFile *f) {
        uint64_t s, p;
        void *t;
        int r;

        assert(f);
        assert(f->header);

        if (f->data_hash_table)
                return 0;

        p = le64toh(f->header->data_hash_table_offset);
        s = le64toh(f->header->data_hash_table_size);

        r = journal_file_move_to(f,
                                 OBJECT_DATA_HASH_TABLE,
                                 true,
                                 p, s,
                                 &t);
        if (r < 0)
                return r;

        f->data_hash_table = t;
        return 0;
}

int journal_file_map_field_hash_table(JournalFile *f) {
        uint64_t s, p;
        void *t;
        int r;

        assert(f);
        assert(f->header);

        if (f->field_hash_table)
                return 0;

        p = le64toh(f->header->field_hash_table_offset);
        s = le64toh(f->header->field_hash_table_size);

        r = journal_file_move_to(f,
                                 OBJECT_FIELD_HASH_TABLE,
                                 true,
                                 p, s,
                                 &t);
        if (r < 0)
                return r;

        f->field_hash_table = t;
        return 0;
}

static int journal_file_link_field(
                JournalFile *f,
                Object *o,
                uint64_t offset,
                uint64_t hash) {

        uint64_t p, h, m;
        int r;

        assert(f);
        assert(f->header);
        assert(f->field_hash_table);
        assert(o);
        assert(offset > 0);

        if (o->object.type != OBJECT_FIELD)
                return -EINVAL;

        m = le64toh(READ_NOW(f->header->field_hash_table_size)) / sizeof(HashItem);
        if (m <= 0)
                return -EBADMSG;

        /* This might alter the window we are looking at */
        o->field.next_hash_offset = o->field.head_data_offset = 0;

        h = hash % m;
        p = le64toh(f->field_hash_table[h].tail_hash_offset);
        if (p == 0)
                f->field_hash_table[h].head_hash_offset = htole64(offset);
        else {
                r = journal_file_move_to_object(f, OBJECT_FIELD, p, &o);
                if (r < 0)
                        return r;

                o->field.next_hash_offset = htole64(offset);
        }

        f->field_hash_table[h].tail_hash_offset = htole64(offset);

        if (JOURNAL_HEADER_CONTAINS(f->header, n_fields))
                f->header->n_fields = htole64(le64toh(f->header->n_fields) + 1);

        return 0;
}

static int journal_file_link_data(
                JournalFile *f,
                Object *o,
                uint64_t offset,
                uint64_t hash) {

        uint64_t p, h, m;
        int r;

        assert(f);
        assert(f->header);
        assert(f->data_hash_table);
        assert(o);
        assert(offset > 0);

        if (o->object.type != OBJECT_DATA)
                return -EINVAL;

        m = le64toh(READ_NOW(f->header->data_hash_table_size)) / sizeof(HashItem);
        if (m <= 0)
                return -EBADMSG;

        /* This might alter the window we are looking at */
        o->data.next_hash_offset = o->data.next_field_offset = 0;
        o->data.entry_offset = o->data.entry_array_offset = 0;
        o->data.n_entries = 0;

        h = hash % m;
        p = le64toh(f->data_hash_table[h].tail_hash_offset);
        if (p == 0)
                /* Only entry in the hash table is easy */
                f->data_hash_table[h].head_hash_offset = htole64(offset);
        else {
                /* Move back to the previous data object, to patch in
                 * pointer */

                r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
                if (r < 0)
                        return r;

                o->data.next_hash_offset = htole64(offset);
        }

        f->data_hash_table[h].tail_hash_offset = htole64(offset);

        if (JOURNAL_HEADER_CONTAINS(f->header, n_data))
                f->header->n_data = htole64(le64toh(f->header->n_data) + 1);

        return 0;
}

static int get_next_hash_offset(
                JournalFile *f,
                uint64_t *p,
                le64_t *next_hash_offset,
                uint64_t *depth,
                le64_t *header_max_depth) {

        uint64_t nextp;

        assert(f);
        assert(p);
        assert(next_hash_offset);
        assert(depth);

        nextp = le64toh(READ_NOW(*next_hash_offset));
        if (nextp > 0) {
                if (nextp <= *p) /* Refuse going in loops */
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Detected hash item loop in %s, refusing.", f->path);

                (*depth)++;

                /* If the depth of this hash chain is larger than all others we have seen so far, record it */
                if (header_max_depth && journal_file_writable(f))
                        *header_max_depth = htole64(MAX(*depth, le64toh(*header_max_depth)));
        }

        *p = nextp;
        return 0;
}

int journal_file_find_field_object_with_hash(
                JournalFile *f,
                const void *field,
                uint64_t size,
                uint64_t hash,
                Object **ret_object,
                uint64_t *ret_offset) {

        uint64_t p, osize, h, m, depth = 0;
        int r;

        assert(f);
        assert(f->header);
        assert(field);
        assert(size > 0);

        /* If the field hash table is empty, we can't find anything */
        if (le64toh(f->header->field_hash_table_size) <= 0)
                return 0;

        /* Map the field hash table, if it isn't mapped yet. */
        r = journal_file_map_field_hash_table(f);
        if (r < 0)
                return r;

        osize = offsetof(Object, field.payload) + size;

        m = le64toh(READ_NOW(f->header->field_hash_table_size)) / sizeof(HashItem);
        if (m <= 0)
                return -EBADMSG;

        h = hash % m;
        p = le64toh(f->field_hash_table[h].head_hash_offset);
        while (p > 0) {
                Object *o;

                r = journal_file_move_to_object(f, OBJECT_FIELD, p, &o);
                if (r < 0)
                        return r;

                if (le64toh(o->field.hash) == hash &&
                    le64toh(o->object.size) == osize &&
                    memcmp(o->field.payload, field, size) == 0) {

                        if (ret_object)
                                *ret_object = o;
                        if (ret_offset)
                                *ret_offset = p;

                        return 1;
                }

                r = get_next_hash_offset(
                                f,
                                &p,
                                &o->field.next_hash_offset,
                                &depth,
                                JOURNAL_HEADER_CONTAINS(f->header, field_hash_chain_depth) ? &f->header->field_hash_chain_depth : NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

uint64_t journal_file_hash_data(
                JournalFile *f,
                const void *data,
                size_t sz) {

        assert(f);
        assert(f->header);
        assert(data || sz == 0);

        /* We try to unify our codebase on siphash, hence new-styled journal files utilizing the keyed hash
         * function use siphash. Old journal files use the Jenkins hash. */

        if (JOURNAL_HEADER_KEYED_HASH(f->header))
                return siphash24(data, sz, f->header->file_id.bytes);

        return jenkins_hash64(data, sz);
}

int journal_file_find_field_object(
                JournalFile *f,
                const void *field,
                uint64_t size,
                Object **ret_object,
                uint64_t *ret_offset) {

        assert(f);
        assert(field);
        assert(size > 0);

        return journal_file_find_field_object_with_hash(
                        f,
                        field, size,
                        journal_file_hash_data(f, field, size),
                        ret_object, ret_offset);
}

int journal_file_find_data_object_with_hash(
                JournalFile *f,
                const void *data,
                uint64_t size,
                uint64_t hash,
                Object **ret_object,
                uint64_t *ret_offset) {

        uint64_t p, h, m, depth = 0;
        int r;

        assert(f);
        assert(f->header);
        assert(data || size == 0);

        /* If there's no data hash table, then there's no entry. */
        if (le64toh(f->header->data_hash_table_size) <= 0)
                return 0;

        /* Map the data hash table, if it isn't mapped yet. */
        r = journal_file_map_data_hash_table(f);
        if (r < 0)
                return r;

        m = le64toh(READ_NOW(f->header->data_hash_table_size)) / sizeof(HashItem);
        if (m <= 0)
                return -EBADMSG;

        h = hash % m;
        p = le64toh(f->data_hash_table[h].head_hash_offset);

        while (p > 0) {
                Object *o;
                void *d;
                size_t rsize;

                r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
                if (r < 0)
                        return r;

                if (le64toh(o->data.hash) != hash)
                        goto next;

                r = journal_file_data_payload(f, o, p, NULL, 0, 0, &d, &rsize);
                if (r < 0)
                        return r;
                assert(r > 0); /* journal_file_data_payload() always returns > 0 if no field is provided. */

                if (memcmp_nn(data, size, d, rsize) == 0) {
                         if (ret_object)
                                *ret_object = o;

                        if (ret_offset)
                                *ret_offset = p;

                        return 1;
                }

        next:
                r = get_next_hash_offset(
                                f,
                                &p,
                                &o->data.next_hash_offset,
                                &depth,
                                JOURNAL_HEADER_CONTAINS(f->header, data_hash_chain_depth) ? &f->header->data_hash_chain_depth : NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

int journal_file_find_data_object(
                JournalFile *f,
                const void *data,
                uint64_t size,
                Object **ret_object,
                uint64_t *ret_offset) {

        assert(f);
        assert(data || size == 0);

        return journal_file_find_data_object_with_hash(
                        f,
                        data, size,
                        journal_file_hash_data(f, data, size),
                        ret_object, ret_offset);
}

bool journal_field_valid(const char *p, size_t l, bool allow_protected) {
        /* We kinda enforce POSIX syntax recommendations for
           environment variables here, but make a couple of additional
           requirements.

           http://pubs.opengroup.org/onlinepubs/000095399/basedefs/xbd_chap08.html */

        assert(p);

        if (l == SIZE_MAX)
                l = strlen(p);

        /* No empty field names */
        if (l <= 0)
                return false;

        /* Don't allow names longer than 64 chars */
        if (l > 64)
                return false;

        /* Variables starting with an underscore are protected */
        if (!allow_protected && p[0] == '_')
                return false;

        /* Don't allow digits as first character */
        if (ascii_isdigit(p[0]))
                return false;

        /* Only allow A-Z0-9 and '_' */
        for (const char *a = p; a < p + l; a++)
                if ((*a < 'A' || *a > 'Z') &&
                    !ascii_isdigit(*a) &&
                    *a != '_')
                        return false;

        return true;
}

static int journal_file_append_field(
                JournalFile *f,
                const void *field,
                uint64_t size,
                Object **ret_object,
                uint64_t *ret_offset) {

        uint64_t hash, p;
        uint64_t osize;
        Object *o;
        int r;

        assert(f);
        assert(field);
        assert(size > 0);

        if (!journal_field_valid(field, size, true))
                return -EBADMSG;

        hash = journal_file_hash_data(f, field, size);

        r = journal_file_find_field_object_with_hash(f, field, size, hash, ret_object, ret_offset);
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        osize = offsetof(Object, field.payload) + size;
        r = journal_file_append_object(f, OBJECT_FIELD, osize, &o, &p);
        if (r < 0)
                return r;

        o->field.hash = htole64(hash);
        memcpy(o->field.payload, field, size);

        r = journal_file_link_field(f, o, p, hash);
        if (r < 0)
                return r;

        /* The linking might have altered the window, so let's only pass the offset to hmac which will
         * move to the object again if needed. */

#if HAVE_GCRYPT
        r = journal_file_hmac_put_object(f, OBJECT_FIELD, NULL, p);
        if (r < 0)
                return r;
#endif

        if (ret_object) {
                r = journal_file_move_to_object(f, OBJECT_FIELD, p, ret_object);
                if (r < 0)
                        return r;
        }

        if (ret_offset)
                *ret_offset = p;

        return 0;
}

static int maybe_compress_payload(JournalFile *f, uint8_t *dst, const uint8_t *src, uint64_t size, size_t *rsize) {
        assert(f);
        assert(f->header);

#if HAVE_COMPRESSION
        Compression c;
        int r;

        c = JOURNAL_FILE_COMPRESSION(f);
        if (c == COMPRESSION_NONE || size < f->compress_threshold_bytes)
                return 0;

        r = compress_blob(c, src, size, dst, size - 1, rsize);
        if (r < 0)
                return log_debug_errno(r, "Failed to compress data object using %s, ignoring: %m", compression_to_string(c));

        log_debug("Compressed data object %"PRIu64" -> %zu using %s", size, *rsize, compression_to_string(c));

        return 1; /* compressed */
#else
        return 0;
#endif
}

static int journal_file_append_data(
                JournalFile *f,
                const void *data,
                uint64_t size,
                Object **ret_object,
                uint64_t *ret_offset) {

        uint64_t hash, p, osize;
        Object *o, *fo;
        size_t rsize = 0;
        const void *eq;
        int r;

        assert(f);

        if (!data || size == 0)
                return -EINVAL;

        hash = journal_file_hash_data(f, data, size);

        r = journal_file_find_data_object_with_hash(f, data, size, hash, ret_object, ret_offset);
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        eq = memchr(data, '=', size);
        if (!eq)
                return -EINVAL;

        osize = journal_file_data_payload_offset(f) + size;
        r = journal_file_append_object(f, OBJECT_DATA, osize, &o, &p);
        if (r < 0)
                return r;

        o->data.hash = htole64(hash);

        r = maybe_compress_payload(f, journal_file_data_payload_field(f, o), data, size, &rsize);
        if (r <= 0)
                /* We don't really care failures, let's continue without compression */
                memcpy_safe(journal_file_data_payload_field(f, o), data, size);
        else {
                Compression c = JOURNAL_FILE_COMPRESSION(f);

                assert(c >= 0 && c < _COMPRESSION_MAX && c != COMPRESSION_NONE);

                o->object.size = htole64(journal_file_data_payload_offset(f) + rsize);
                o->object.flags |= COMPRESSION_TO_OBJECT_FLAG(c);
        }

        r = journal_file_link_data(f, o, p, hash);
        if (r < 0)
                return r;

        /* The linking might have altered the window, so let's refresh our pointer. */
        r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
        if (r < 0)
                return r;

#if HAVE_GCRYPT
        r = journal_file_hmac_put_object(f, OBJECT_DATA, o, p);
        if (r < 0)
                return r;
#endif

        /* Create field object ... */
        r = journal_file_append_field(f, data, (uint8_t*) eq - (uint8_t*) data, &fo, NULL);
        if (r < 0)
                return r;

        /* ... and link it in. */
        o->data.next_field_offset = fo->field.head_data_offset;
        fo->field.head_data_offset = le64toh(p);

        if (ret_object)
                *ret_object = o;

        if (ret_offset)
                *ret_offset = p;

        return 0;
}

static int maybe_decompress_payload(
                JournalFile *f,
                uint8_t *payload,
                uint64_t size,
                Compression compression,
                const char *field,
                size_t field_length,
                size_t data_threshold,
                void **ret_data,
                size_t *ret_size) {

        assert(f);

        /* We can't read objects larger than 4G on a 32-bit machine */
        if ((uint64_t) (size_t) size != size)
                return -E2BIG;

        if (compression != COMPRESSION_NONE) {
#if HAVE_COMPRESSION
                size_t rsize;
                int r;

                if (field) {
                        r = decompress_startswith(compression, payload, size, &f->compress_buffer, field,
                                                  field_length, '=');
                        if (r < 0)
                                return log_debug_errno(r,
                                                       "Cannot decompress %s object of length %" PRIu64 ": %m",
                                                       compression_to_string(compression),
                                                       size);
                        if (r == 0) {
                                if (ret_data)
                                        *ret_data = NULL;
                                if (ret_size)
                                        *ret_size = 0;
                                return 0;
                        }
                }

                r = decompress_blob(compression, payload, size, &f->compress_buffer, &rsize, 0);
                if (r < 0)
                        return r;

                if (ret_data)
                        *ret_data = f->compress_buffer;
                if (ret_size)
                        *ret_size = rsize;
#else
                return -EPROTONOSUPPORT;
#endif
        } else {
                if (field && (size < field_length + 1 || memcmp(payload, field, field_length) != 0 || payload[field_length] != '=')) {
                        if (ret_data)
                                *ret_data = NULL;
                        if (ret_size)
                                *ret_size = 0;
                        return 0;
                }

                if (ret_data)
                        *ret_data = payload;
                if (ret_size)
                        *ret_size = (size_t) size;
        }

        return 1;
}

int journal_file_data_payload(
                JournalFile *f,
                Object *o,
                uint64_t offset,
                const char *field,
                size_t field_length,
                size_t data_threshold,
                void **ret_data,
                size_t *ret_size) {

        uint64_t size;
        Compression c;
        int r;

        assert(f);
        assert(!field == (field_length == 0)); /* These must be specified together. */

        if (!o) {
                r = journal_file_move_to_object(f, OBJECT_DATA, offset, &o);
                if (r < 0)
                        return r;
        }

        size = le64toh(READ_NOW(o->object.size));
        if (size < journal_file_data_payload_offset(f))
                return -EBADMSG;

        size -= journal_file_data_payload_offset(f);

        c = COMPRESSION_FROM_OBJECT(o);
        if (c < 0)
                return -EPROTONOSUPPORT;

        return maybe_decompress_payload(f, journal_file_data_payload_field(f, o), size, c, field,
                                        field_length, data_threshold, ret_data, ret_size);
}

uint64_t journal_file_entry_n_items(JournalFile *f, Object *o) {
        uint64_t sz;

        assert(f);
        assert(o);

        if (o->object.type != OBJECT_ENTRY)
                return 0;

        sz = le64toh(READ_NOW(o->object.size));
        if (sz < offsetof(Object, entry.items))
                return 0;

        return (sz - offsetof(Object, entry.items)) / journal_file_entry_item_size(f);
}

uint64_t journal_file_entry_array_n_items(JournalFile *f, Object *o) {
        uint64_t sz;

        assert(f);
        assert(o);

        if (o->object.type != OBJECT_ENTRY_ARRAY)
                return 0;

        sz = le64toh(READ_NOW(o->object.size));
        if (sz < offsetof(Object, entry_array.items))
                return 0;

        return (sz - offsetof(Object, entry_array.items)) / journal_file_entry_array_item_size(f);
}

uint64_t journal_file_hash_table_n_items(Object *o) {
        uint64_t sz;

        assert(o);

        if (!IN_SET(o->object.type, OBJECT_DATA_HASH_TABLE, OBJECT_FIELD_HASH_TABLE))
                return 0;

        sz = le64toh(READ_NOW(o->object.size));
        if (sz < offsetof(Object, hash_table.items))
                return 0;

        return (sz - offsetof(Object, hash_table.items)) / sizeof(HashItem);
}

static void write_entry_array_item(JournalFile *f, Object *o, uint64_t i, uint64_t p) {
        assert(f);
        assert(o);

        if (JOURNAL_HEADER_COMPACT(f->header)) {
                assert(p <= UINT32_MAX);
                o->entry_array.items.compact[i] = htole32(p);
        } else
                o->entry_array.items.regular[i] = htole64(p);
}

static int link_entry_into_array(
                JournalFile *f,
                le64_t *first,
                le64_t *idx,
                le32_t *tail,
                le32_t *tidx,
                uint64_t p) {

        uint64_t n = 0, ap = 0, q, i, a, hidx;
        Object *o;
        int r;

        assert(f);
        assert(f->header);
        assert(first);
        assert(idx);
        assert(p > 0);

        a = tail ? le32toh(*tail) : le64toh(*first);
        hidx = le64toh(READ_NOW(*idx));
        i = tidx ? le32toh(READ_NOW(*tidx)) : hidx;

        while (a > 0) {
                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                if (r < 0)
                        return r;

                n = journal_file_entry_array_n_items(f, o);
                if (i < n) {
                        write_entry_array_item(f, o, i, p);
                        *idx = htole64(hidx + 1);
                        if (tidx)
                                *tidx = htole32(le32toh(*tidx) + 1);
                        return 0;
                }

                i -= n;
                ap = a;
                a = le64toh(o->entry_array.next_entry_array_offset);
        }

        if (hidx > n)
                n = (hidx+1) * 2;
        else
                n = n * 2;

        if (n < 4)
                n = 4;

        r = journal_file_append_object(f, OBJECT_ENTRY_ARRAY,
                                       offsetof(Object, entry_array.items) + n * journal_file_entry_array_item_size(f),
                                       &o, &q);
        if (r < 0)
                return r;

#if HAVE_GCRYPT
        r = journal_file_hmac_put_object(f, OBJECT_ENTRY_ARRAY, o, q);
        if (r < 0)
                return r;
#endif

        write_entry_array_item(f, o, i, p);

        if (ap == 0)
                *first = htole64(q);
        else {
                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, ap, &o);
                if (r < 0)
                        return r;

                o->entry_array.next_entry_array_offset = htole64(q);
        }

        if (tail)
                *tail = htole32(q);

        if (JOURNAL_HEADER_CONTAINS(f->header, n_entry_arrays))
                f->header->n_entry_arrays = htole64(le64toh(f->header->n_entry_arrays) + 1);

        *idx = htole64(hidx + 1);
        if (tidx)
                *tidx = htole32(1);

        return 0;
}

static int link_entry_into_array_plus_one(
                JournalFile *f,
                le64_t *extra,
                le64_t *first,
                le64_t *idx,
                le32_t *tail,
                le32_t *tidx,
                uint64_t p) {

        uint64_t hidx;
        int r;

        assert(f);
        assert(extra);
        assert(first);
        assert(idx);
        assert(p > 0);

        hidx = le64toh(READ_NOW(*idx));
        if (hidx == UINT64_MAX)
                return -EBADMSG;
        if (hidx == 0)
                *extra = htole64(p);
        else {
                le64_t i;

                i = htole64(hidx - 1);
                r = link_entry_into_array(f, first, &i, tail, tidx, p);
                if (r < 0)
                        return r;
        }

        *idx = htole64(hidx + 1);
        return 0;
}

static int journal_file_link_entry_item(JournalFile *f, uint64_t offset, uint64_t p) {
        Object *o;
        int r;

        assert(f);
        assert(offset > 0);

        r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
        if (r < 0)
                return r;

        return link_entry_into_array_plus_one(f,
                                              &o->data.entry_offset,
                                              &o->data.entry_array_offset,
                                              &o->data.n_entries,
                                              JOURNAL_HEADER_COMPACT(f->header) ? &o->data.compact.tail_entry_array_offset : NULL,
                                              JOURNAL_HEADER_COMPACT(f->header) ? &o->data.compact.tail_entry_array_n_entries : NULL,
                                              offset);
}

static int journal_file_link_entry(
                JournalFile *f,
                Object *o,
                uint64_t offset,
                const EntryItem items[],
                size_t n_items) {

        int r;

        assert(f);
        assert(f->header);
        assert(o);
        assert(offset > 0);

        if (o->object.type != OBJECT_ENTRY)
                return -EINVAL;

        __atomic_thread_fence(__ATOMIC_SEQ_CST);

        /* Link up the entry itself */
        r = link_entry_into_array(f,
                                  &f->header->entry_array_offset,
                                  &f->header->n_entries,
                                  JOURNAL_HEADER_CONTAINS(f->header, tail_entry_array_offset) ? &f->header->tail_entry_array_offset : NULL,
                                  JOURNAL_HEADER_CONTAINS(f->header, tail_entry_array_n_entries) ? &f->header->tail_entry_array_n_entries : NULL,
                                  offset);
        if (r < 0)
                return r;

        /* log_debug("=> %s seqnr=%"PRIu64" n_entries=%"PRIu64, f->path, o->entry.seqnum, f->header->n_entries); */

        if (f->header->head_entry_realtime == 0)
                f->header->head_entry_realtime = o->entry.realtime;

        f->header->tail_entry_realtime = o->entry.realtime;
        f->header->tail_entry_monotonic = o->entry.monotonic;
        if (JOURNAL_HEADER_CONTAINS(f->header, tail_entry_offset))
                f->header->tail_entry_offset = htole64(offset);
        f->newest_mtime = 0; /* we have a new tail entry now, explicitly invalidate newest boot id/timestamp info */

        /* Link up the items */
        for (uint64_t i = 0; i < n_items; i++) {
                int k;

                /* If we fail to link an entry item because we can't allocate a new entry array, don't fail
                 * immediately but try to link the other entry items since it might still be possible to link
                 * those if they don't require a new entry array to be allocated. */

                k = journal_file_link_entry_item(f, offset, items[i].object_offset);
                if (k == -E2BIG)
                        r = k;
                else if (k < 0)
                        return k;
        }

        return r;
}

static void write_entry_item(JournalFile *f, Object *o, uint64_t i, const EntryItem *item) {
        assert(f);
        assert(o);
        assert(item);

        if (JOURNAL_HEADER_COMPACT(f->header)) {
                assert(item->object_offset <= UINT32_MAX);
                o->entry.items.compact[i].object_offset = htole32(item->object_offset);
        } else {
                o->entry.items.regular[i].object_offset = htole64(item->object_offset);
                o->entry.items.regular[i].hash = htole64(item->hash);
        }
}

static int journal_file_append_entry_internal(
                JournalFile *f,
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const sd_id128_t *machine_id,
                uint64_t xor_hash,
                const EntryItem items[],
                size_t n_items,
                uint64_t *seqnum,
                sd_id128_t *seqnum_id,
                Object **ret_object,
                uint64_t *ret_offset) {

        uint64_t np;
        uint64_t osize;
        Object *o;
        int r;

        assert(f);
        assert(f->header);
        assert(ts);
        assert(boot_id);
        assert(!sd_id128_is_null(*boot_id));
        assert(items || n_items == 0);

        if (f->strict_order) {
                /* If requested be stricter with ordering in this journal file, to make searching via
                 * bisection fully deterministic. This is an optional feature, so that if desired journal
                 * files can be written where the ordering is not strictly enforced (in which case bisection
                 * will yield *a* result, but not the *only* result, when searching for points in
                 * time). Strict ordering mode is enabled when journald originally writes the files, but
                 * might not necessarily be if other tools (the remoting tools for example) write journal
                 * files from combined sources.
                 *
                 * Typically, if any of the errors generated here are seen journald will just rotate the
                 * journal files and start anew. */

                if (ts->realtime < le64toh(f->header->tail_entry_realtime))
                        return log_debug_errno(SYNTHETIC_ERRNO(EREMCHG),
                                               "Realtime timestamp %" PRIu64 " smaller than previous realtime "
                                               "timestamp %" PRIu64 ", refusing entry.",
                                               ts->realtime, le64toh(f->header->tail_entry_realtime));

                if (sd_id128_equal(*boot_id, f->header->tail_entry_boot_id) &&
                    ts->monotonic < le64toh(f->header->tail_entry_monotonic))
                        return log_debug_errno(
                                        SYNTHETIC_ERRNO(ENOTNAM),
                                        "Monotonic timestamp %" PRIu64
                                        " smaller than previous monotonic timestamp %" PRIu64
                                        " while having the same boot ID, refusing entry.",
                                        ts->monotonic,
                                        le64toh(f->header->tail_entry_monotonic));
        }

        if (seqnum_id) {
                /* Settle the passed in sequence number ID */

                if (sd_id128_is_null(*seqnum_id))
                        *seqnum_id = f->header->seqnum_id; /* Caller has none assigned, then copy the one from the file */
                else if (!sd_id128_equal(*seqnum_id, f->header->seqnum_id)) {
                        /* Different seqnum IDs? We can't allow entries from multiple IDs end up in the same journal.*/
                        if (le64toh(f->header->n_entries) == 0)
                                f->header->seqnum_id = *seqnum_id; /* Caller has one, and file so far has no entries, then copy the one from the caller */
                        else
                                return log_debug_errno(SYNTHETIC_ERRNO(EILSEQ),
                                                       "Sequence number IDs don't match, refusing entry.");
                }
        }

        if (machine_id && sd_id128_is_null(f->header->machine_id))
                /* Initialize machine ID when not set yet */
                f->header->machine_id = *machine_id;

        osize = offsetof(Object, entry.items) + (n_items * journal_file_entry_item_size(f));

        r = journal_file_append_object(f, OBJECT_ENTRY, osize, &o, &np);
        if (r < 0)
                return r;

        o->entry.seqnum = htole64(journal_file_entry_seqnum(f, seqnum));
        o->entry.realtime = htole64(ts->realtime);
        o->entry.monotonic = htole64(ts->monotonic);
        o->entry.xor_hash = htole64(xor_hash);
        o->entry.boot_id = f->header->tail_entry_boot_id = *boot_id;

        for (size_t i = 0; i < n_items; i++)
                write_entry_item(f, o, i, &items[i]);

#if HAVE_GCRYPT
        r = journal_file_hmac_put_object(f, OBJECT_ENTRY, o, np);
        if (r < 0)
                return r;
#endif

        r = journal_file_link_entry(f, o, np, items, n_items);
        if (r < 0)
                return r;

        if (ret_object)
                *ret_object = o;

        if (ret_offset)
                *ret_offset = np;

        return r;
}

void journal_file_post_change(JournalFile *f) {
        assert(f);

        if (f->fd < 0)
                return;

        /* inotify() does not receive IN_MODIFY events from file
         * accesses done via mmap(). After each access we hence
         * trigger IN_MODIFY by truncating the journal file to its
         * current size which triggers IN_MODIFY. */

        __atomic_thread_fence(__ATOMIC_SEQ_CST);

        if (ftruncate(f->fd, f->last_stat.st_size) < 0)
                log_debug_errno(errno, "Failed to truncate file to its own size: %m");
}

static int post_change_thunk(sd_event_source *timer, uint64_t usec, void *userdata) {
        assert(userdata);

        journal_file_post_change(userdata);

        return 1;
}

static void schedule_post_change(JournalFile *f) {
        sd_event *e;
        int r;

        assert(f);
        assert(f->post_change_timer);

        assert_se(e = sd_event_source_get_event(f->post_change_timer));

        /* If we are already going down, post the change immediately. */
        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                goto fail;

        r = sd_event_source_get_enabled(f->post_change_timer, NULL);
        if (r < 0) {
                log_debug_errno(r, "Failed to get ftruncate timer state: %m");
                goto fail;
        }
        if (r > 0)
                return;

        r = sd_event_source_set_time_relative(f->post_change_timer, f->post_change_timer_period);
        if (r < 0) {
                log_debug_errno(r, "Failed to set time for scheduling ftruncate: %m");
                goto fail;
        }

        r = sd_event_source_set_enabled(f->post_change_timer, SD_EVENT_ONESHOT);
        if (r < 0) {
                log_debug_errno(r, "Failed to enable scheduled ftruncate: %m");
                goto fail;
        }

        return;

fail:
        /* On failure, let's simply post the change immediately. */
        journal_file_post_change(f);
}

/* Enable coalesced change posting in a timer on the provided sd_event instance */
int journal_file_enable_post_change_timer(JournalFile *f, sd_event *e, usec_t t) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *timer = NULL;
        int r;

        assert(f);
        assert_return(!f->post_change_timer, -EINVAL);
        assert(e);
        assert(t);

        /* If we are already going down, we cannot install the timer.
         * In such case, the caller needs to call journal_file_post_change() explicitly. */
        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return 0;

        r = sd_event_add_time(e, &timer, CLOCK_MONOTONIC, 0, 0, post_change_thunk, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(timer, SD_EVENT_OFF);
        if (r < 0)
                return r;

        f->post_change_timer = TAKE_PTR(timer);
        f->post_change_timer_period = t;

        return 1;
}

static int entry_item_cmp(const EntryItem *a, const EntryItem *b) {
        return CMP(ASSERT_PTR(a)->object_offset, ASSERT_PTR(b)->object_offset);
}

static size_t remove_duplicate_entry_items(EntryItem items[], size_t n) {
        size_t j = 1;

        assert(items || n == 0);

        if (n <= 1)
                return n;

        for (size_t i = 1; i < n; i++)
                if (items[i].object_offset != items[j - 1].object_offset)
                        items[j++] = items[i];

        return j;
}

int journal_file_append_entry(
                JournalFile *f,
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const struct iovec iovec[],
                size_t n_iovec,
                uint64_t *seqnum,
                sd_id128_t *seqnum_id,
                Object **ret_object,
                uint64_t *ret_offset) {

        _cleanup_free_ EntryItem *items_alloc = NULL;
        EntryItem *items;
        uint64_t xor_hash = 0;
        struct dual_timestamp _ts;
        sd_id128_t _boot_id, _machine_id, *machine_id;
        int r;

        assert(f);
        assert(f->header);
        assert(iovec);
        assert(n_iovec > 0);

        if (ts) {
                if (!VALID_REALTIME(ts->realtime))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid realtime timestamp %" PRIu64 ", refusing entry.",
                                               ts->realtime);
                if (!VALID_MONOTONIC(ts->monotonic))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid monotomic timestamp %" PRIu64 ", refusing entry.",
                                               ts->monotonic);
        } else {
                dual_timestamp_now(&_ts);
                ts = &_ts;
        }

        if (boot_id) {
                if (sd_id128_is_null(*boot_id))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Empty boot ID, refusing entry.");
        } else {
                r = sd_id128_get_boot(&_boot_id);
                if (r < 0)
                        return r;

                boot_id = &_boot_id;
        }

        r = sd_id128_get_machine(&_machine_id);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                /* Gracefully handle the machine ID not being initialized yet */
                machine_id = NULL;
        else if (r < 0)
                return r;
        else
                machine_id = &_machine_id;

#if HAVE_GCRYPT
        r = journal_file_maybe_append_tag(f, ts->realtime);
        if (r < 0)
                return r;
#endif

        if (n_iovec < ALLOCA_MAX / sizeof(EntryItem) / 2)
                items = newa(EntryItem, n_iovec);
        else {
                items_alloc = new(EntryItem, n_iovec);
                if (!items_alloc)
                        return -ENOMEM;

                items = items_alloc;
        }

        for (size_t i = 0; i < n_iovec; i++) {
                uint64_t p;
                Object *o;

                r = journal_file_append_data(f, iovec[i].iov_base, iovec[i].iov_len, &o, &p);
                if (r < 0)
                        return r;

                /* When calculating the XOR hash field, we need to take special care if the "keyed-hash"
                 * journal file flag is on. We use the XOR hash field to quickly determine the identity of a
                 * specific record, and give records with otherwise identical position (i.e. match in seqno,
                 * timestamp, …) a stable ordering. But for that we can't have it that the hash of the
                 * objects in each file is different since they are keyed. Hence let's calculate the Jenkins
                 * hash here for that. This also has the benefit that cursors for old and new journal files
                 * are completely identical (they include the XOR hash after all). For classic Jenkins-hash
                 * files things are easier, we can just take the value from the stored record directly. */

                if (JOURNAL_HEADER_KEYED_HASH(f->header))
                        xor_hash ^= jenkins_hash64(iovec[i].iov_base, iovec[i].iov_len);
                else
                        xor_hash ^= le64toh(o->data.hash);

                items[i] = (EntryItem) {
                        .object_offset = p,
                        .hash = le64toh(o->data.hash),
                };
        }

        /* Order by the position on disk, in order to improve seek
         * times for rotating media. */
        typesafe_qsort(items, n_iovec, entry_item_cmp);
        n_iovec = remove_duplicate_entry_items(items, n_iovec);

        r = journal_file_append_entry_internal(
                        f,
                        ts,
                        boot_id,
                        machine_id,
                        xor_hash,
                        items,
                        n_iovec,
                        seqnum,
                        seqnum_id,
                        ret_object,
                        ret_offset);

        /* If the memory mapping triggered a SIGBUS then we return an
         * IO error and ignore the error code passed down to us, since
         * it is very likely just an effect of a nullified replacement
         * mapping page */

        if (mmap_cache_fd_got_sigbus(f->cache_fd))
                r = -EIO;

        if (f->post_change_timer)
                schedule_post_change(f);
        else
                journal_file_post_change(f);

        return r;
}

typedef struct ChainCacheItem {
        uint64_t first; /* The offset of the entry array object at the beginning of the chain,
                         * i.e., le64toh(f->header->entry_array_offset), or le64toh(o->data.entry_offset). */
        uint64_t array; /* The offset of the cached entry array object. */
        uint64_t begin; /* The offset of the first item in the cached array. */
        uint64_t total; /* The total number of items in all arrays before the cached one in the chain. */
        uint64_t last_index; /* The last index we looked at in the cached array, to optimize locality when bisecting. */
} ChainCacheItem;

static void chain_cache_put(
                OrderedHashmap *h,
                ChainCacheItem *ci,
                uint64_t first,
                uint64_t array,
                uint64_t begin,
                uint64_t total,
                uint64_t last_index) {

        assert(h);

        if (!ci) {
                /* If the chain item to cache for this chain is the
                 * first one it's not worth caching anything */
                if (array == first)
                        return;

                if (ordered_hashmap_size(h) >= CHAIN_CACHE_MAX) {
                        ci = ordered_hashmap_steal_first(h);
                        assert(ci);
                } else {
                        ci = new(ChainCacheItem, 1);
                        if (!ci)
                                return;
                }

                ci->first = first;

                if (ordered_hashmap_put(h, &ci->first, ci) < 0) {
                        free(ci);
                        return;
                }
        } else
                assert(ci->first == first);

        ci->array = array;
        ci->begin = begin;
        ci->total = total;
        ci->last_index = last_index;
}

static int bump_array_index(uint64_t *i, direction_t direction, uint64_t n) {
        assert(i);

        /* Increase or decrease the specified index, in the right direction. */

        if (direction == DIRECTION_DOWN) {
                if (*i >= n - 1)
                        return 0;

                (*i)++;
        } else {
                if (*i <= 0)
                        return 0;

                (*i)--;
        }

        return 1;
}

static int bump_entry_array(
                JournalFile *f,
                Object *o,       /* the current entry array object. */
                uint64_t offset, /* the offset of the entry array object. */
                uint64_t first,  /* The offset of the first entry array object in the chain. */
                direction_t direction,
                uint64_t *ret) {

        int r;

        assert(f);
        assert(ret);

        if (direction == DIRECTION_DOWN) {
                assert(o);
                assert(o->object.type == OBJECT_ENTRY_ARRAY);

                *ret = le64toh(o->entry_array.next_entry_array_offset);
        } else {

                /* Entry array chains are a singly linked list, so to find the previous array in the chain, we have
                 * to start iterating from the top. */

                assert(offset > 0);

                uint64_t p = first, q = 0;
                while (p > 0 && p != offset) {
                        r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, p, &o);
                        if (r < 0)
                                return r;

                        q = p;
                        p = le64toh(o->entry_array.next_entry_array_offset);
                }

                /* If we can't find the previous entry array in the entry array chain, we're likely dealing with a
                 * corrupted journal file. */
                if (p == 0)
                        return -EBADMSG;

                *ret = q;
        }

        return *ret > 0;
}

static int generic_array_get(
                JournalFile *f,
                uint64_t first,         /* The offset of the first entry array object in the chain. */
                uint64_t i,             /* The index of the target object counted from the beginning of the entry array chain. */
                direction_t direction,
                Object **ret_object,    /* The found object. */
                uint64_t *ret_offset) { /* The offset of the found object. */

        uint64_t a, t = 0, k = 0; /* Explicit initialization of k to appease gcc */
        ChainCacheItem *ci;
        Object *o = NULL;
        int r;

        assert(f);

        /* FIXME: fix return value assignment on success. */

        a = first;

        /* Try the chain cache first */
        ci = ordered_hashmap_get(f->chain_cache, &first);
        if (ci && i > ci->total) {
                a = ci->array;
                i -= ci->total;
                t = ci->total;
        }

        while (a > 0) {
                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)) {
                        /* If there's corruption and we're going downwards, let's pretend we reached the
                         * final entry in the entry array chain. */

                        if (direction == DIRECTION_DOWN)
                                return 0;

                        /* If there's corruption and we're going upwards, move back to the previous entry
                         * array and start iterating entries from there. */

                        i = UINT64_MAX;
                        break;
                }
                if (r < 0)
                        return r;

                k = journal_file_entry_array_n_items(f, o);
                if (k == 0)
                        return 0;

                if (i < k)
                        break;

                /* The index is larger than the number of elements in the array. Let's move to the next array. */
                i -= k;
                t += k;
                a = le64toh(o->entry_array.next_entry_array_offset);
        }

        /* If we've found the right location, now look for the first non-corrupt entry object (in the right
         * direction). */

        while (a > 0) {
                if (i == UINT64_MAX) {
                        r = bump_entry_array(f, o, a, first, direction, &a);
                        if (r <= 0)
                                return r;

                        r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o);
                        if (r < 0)
                                return r;

                        k = journal_file_entry_array_n_items(f, o);
                        if (k == 0)
                                break;

                        if (direction == DIRECTION_DOWN)
                                i = 0;
                        else {
                                /* We moved to the previous array. The total must be decreased. */
                                if (t < k)
                                        return -EBADMSG; /* chain cache is broken ? */

                                i = k - 1;
                                t -= k;
                        }
                }

                do {
                        uint64_t p;

                        p = journal_file_entry_array_item(f, o, i);

                        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, ret_object);
                        if (r >= 0) {
                                /* Let's cache this item for the next invocation */
                                chain_cache_put(f->chain_cache, ci, first, a, journal_file_entry_array_item(f, o, 0), t, i);

                                if (ret_offset)
                                        *ret_offset = p;

                                return 1;
                        }
                        if (!IN_SET(r, -EADDRNOTAVAIL, -EBADMSG))
                                return r;

                        /* OK, so this entry is borked. Most likely some entry didn't get synced to
                         * disk properly, let's see if the next one might work for us instead. */
                        log_debug_errno(r, "Entry item %" PRIu64 " is bad, skipping over it.", i);

                } while (bump_array_index(&i, direction, k) > 0);

                /* All entries tried in the above do-while loop are broken. Let's move to the next (or previous) array. */

                if (direction == DIRECTION_DOWN)
                        /* We are going to the next array, the total must be incremented. */
                        t += k;

                i = UINT64_MAX;
        }

        return 0;
}

enum {
        TEST_FOUND,         /* The current object passes the test. */
        TEST_LEFT,          /* The current object is in an earlier position, and the object we are looking
                             * for should exist in a later position. */
        TEST_RIGHT,         /* The current object is in a later position, and the object we are looking for
                             * should exist in an earlier position. */
        TEST_GOTO_NEXT,     /* No matching object exists in this array and earlier arrays, go to the next array. */
        TEST_GOTO_PREVIOUS, /* No matching object exists in this array and later arrays, go to the previous array. */
};

static int generic_array_bisect_step(
                JournalFile *f,
                Object *array,     /* entry array object */
                uint64_t i,        /* index of the entry item in the array we will test. */
                uint64_t needle,
                int (*test_object)(JournalFile *f, uint64_t p, uint64_t needle),
                direction_t direction,
                uint64_t *m,       /* The maximum number of the entries we will check in the array. */
                uint64_t *left,    /* The index of the left boundary in the array. */
                uint64_t *right) { /* The index of the right boundary in the array. */

        uint64_t p;
        int r;

        assert(f);
        assert(array);
        assert(test_object);
        assert(m);
        assert(left);
        assert(right);
        assert(*left <= i);
        assert(i <= *right);
        assert(*right < *m);

        p = journal_file_entry_array_item(f, array, i);
        if (p <= 0)
                r = -EBADMSG;
        else
                r = test_object(f, p, needle);
        if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL)) {
                log_debug_errno(r, "Encountered invalid entry while bisecting, cutting algorithm short.");

                if (i == *left) {
                        /* This happens on two situations:
                         *
                         * a) i == 0 (hence, *left == 0):
                         *    The first entry in the array is corrupted, let's go back to the previous array.
                         *
                         * b) *right == *left or *left + 1, and we are going to downwards:
                         *    In that case, the (i-1)-th object has been already tested in the previous call,
                         *    which returned TEST_LEFT. See below. So, there is no matching entry in this
                         *    array nor in the whole entry array chain. */
                        assert(i == 0 || (*right - *left <= 1 && direction == DIRECTION_DOWN));
                        return TEST_GOTO_PREVIOUS;
                }

                /* Otherwise, cutting the array short. So, here we limit the number of elements we will see
                 * in this array, and set the right boundary to the last possibly non-corrupted object. */
                *m = i;
                *right = i - 1;
                return TEST_RIGHT;
        }
        if (r < 0)
                return r;

        if (r == TEST_FOUND)
                /* There may be multiple entries that match with the needle. When the direction is down, we
                 * need to find the first matching entry, hence the right boundary can be moved, but the left
                 * one cannot. Similarly, when the direction is up, we need to find the last matching entry,
                 * hence the left boundary can be moved, but the right one cannot. */
                r = direction == DIRECTION_DOWN ? TEST_RIGHT : TEST_LEFT;

        if (r == TEST_RIGHT) {
                /* Currently, left --- needle --- i --- right, hence we can move the right boundary to i.  */
                if (direction == DIRECTION_DOWN)
                        *right = i;
                else {
                        if (i == 0)
                                return TEST_GOTO_PREVIOUS;
                        *right = i - 1;
                }
        } else {
                /* Currently, left --- i --- needle --- right, hence we can move the left boundary to i. */
                if (direction == DIRECTION_DOWN) {
                        /* Note, here *m is always positive, as by the assertions at the beginning, we have
                         * 0 <= *left <= i <= *right < m */
                        if (i == *m - 1)
                                return TEST_GOTO_NEXT;

                        *left = i + 1;
                } else
                        *left = i;
        }

        return r;
}

static int generic_array_bisect(
                JournalFile *f,
                uint64_t first,  /* The offset of the first entry array object in the chain. */
                uint64_t n,      /* The total number of elements in the chain of the entry array. */
                uint64_t needle, /* The target value (e.g. seqnum, monotonic, realtime, ...). */
                int (*test_object)(JournalFile *f,
                                   uint64_t p, /* the offset of the (data or entry) object that will be tested. */
                                   uint64_t needle),
                direction_t direction,
                Object **ret_object,  /* The found object. */
                uint64_t *ret_offset, /* The offset of the found object. */
                uint64_t *ret_idx) {  /* The index of the found object counted from the beginning of the entry array chain. */

        /* Given an entry array chain, this function finds the object "closest" to the given needle in the
         * chain, taking into account the provided direction. A function can be provided to determine how
         * an object is matched against the given needle.
         *
         * Given a journal file, the offset of an object and the needle, the test_object() function should
         * return TEST_RIGHT if the needle is located earlier in the entry array chain, TEST_LEFT if the
         * needle is located later in the entry array chain, and TEST_FOUND if the object matches the needle.
         * If test_object() returns TEST_FOUND for a specific object, that object's information will be used
         * to populate the return values of this function. If test_object() never returns TEST_FOUND, the
         * return values are populated with the details of one of the objects closest to the needle. If the
         * direction is DIRECTION_UP, the earlier object is used. Otherwise, the later object is used.
         * If there are multiple objects that test_object() return TEST_FOUND for, then the first matching
         * object returned when direction is DIRECTION_DOWN. Otherwise the last object is returned. */

        uint64_t a, p, t = 0, i, last_index = UINT64_MAX;
        ChainCacheItem *ci;
        Object *array;
        int r;

        assert(f);
        assert(test_object);

        if (n <= 0)
                return 0;

        /* Start with the first array in the chain */
        a = first;

        ci = ordered_hashmap_get(f->chain_cache, &first);
        if (ci && n > ci->total && ci->begin != 0) {
                /* Ah, we have iterated this bisection array chain previously! Let's see if we can skip ahead
                 * in the chain, as far as the last time. But we can't jump backwards in the chain, so let's
                 * check that first. */

                r = test_object(f, ci->begin, needle);
                if (IN_SET(r, -EBADMSG, -EADDRNOTAVAIL))
                        log_debug_errno(r, "Cached entry is corrupted, ignoring: %m");
                else if (r < 0)
                        return r;
                else if (r == TEST_LEFT) {
                        /* OK, what we are looking for is right of the begin of this EntryArray, so let's
                         * jump straight to previously cached array in the chain */

                        a = ci->array;
                        n -= ci->total;
                        t = ci->total;
                        last_index = ci->last_index;
                }
        }

        while (a > 0) {
                uint64_t left, right, k, m, m_original;

                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &array);
                if (r < 0)
                        return r;

                k = journal_file_entry_array_n_items(f, array);
                m = m_original = MIN(k, n);
                if (m <= 0)
                        return 0;

                left = 0;
                right = m - 1;

                if (direction == DIRECTION_UP) {
                        /* If we're going upwards, the last entry of the previous array may pass the test,
                         * and the first entry of the current array may not pass. In that case, the last
                         * entry of the previous array must be returned. Hence, we need to test the first
                         * entry of the current array. */
                        r = generic_array_bisect_step(f, array, 0, needle, test_object, direction, &m, &left, &right);
                        if (r < 0)
                                return r;
                        if (r == TEST_GOTO_PREVIOUS)
                                goto previous;
                }

                /* Test the last entry of this array, to determine if we should go to the next array. */
                r = generic_array_bisect_step(f, array, right, needle, test_object, direction, &m, &left, &right);
                if (r < 0)
                        return r;
                if (r == TEST_GOTO_PREVIOUS)
                        goto previous;

                /* The expected entry should be in this array, (or the last entry of the previous array). */
                if (r == TEST_RIGHT) {

                        /* If we cached the last index we looked at, let's try to not to jump too wildly
                         * around and see if we can limit the range to look at early to the immediate
                         * neighbors of the last index we looked at. */

                        if (last_index > 0 && left < last_index - 1 && last_index - 1 < right) {
                                r = generic_array_bisect_step(f, array, last_index - 1, needle, test_object, direction, &m, &left, &right);
                                if (r < 0)
                                        return r;
                                if (r == TEST_GOTO_PREVIOUS)
                                        goto previous;
                        }

                        if (last_index < UINT64_MAX && left < last_index + 1 && last_index + 1 < right) {
                                r = generic_array_bisect_step(f, array, last_index + 1, needle, test_object, direction, &m, &left, &right);
                                if (r < 0)
                                        return r;
                                if (r == TEST_GOTO_PREVIOUS)
                                        goto previous;
                        }

                        for (;;) {
                                if (left == right) {
                                        /* We found one or more corrupted entries in generic_array_bisect_step().
                                         * In that case, the entry pointed by 'right' may not be tested.
                                         *
                                         * When we are going to downwards, the entry object pointed by 'left'
                                         * has not been tested yet, Hence, even if left == right, we still
                                         * have to check the final entry to see if it actually matches.
                                         *
                                         * On the other hand, when we are going to upwards, the entry pointed
                                         * by 'left' is always tested, So, it is not necessary to test the
                                         * final entry again. */
                                        if (m != m_original && direction == DIRECTION_DOWN) {
                                                r = generic_array_bisect_step(f, array, left, needle, test_object, direction, &m, &left, &right);
                                                if (r < 0)
                                                        return r;
                                                if (IN_SET(r, TEST_GOTO_PREVIOUS, TEST_GOTO_NEXT))
                                                        return 0; /* The entry does not pass the test, or is corrupted */

                                                assert(TEST_RIGHT);
                                                assert(left == right);
                                        }

                                        i = left;
                                        goto found;
                                }

                                assert(left < right);
                                i = (left + right + (direction == DIRECTION_UP)) / 2;

                                r = generic_array_bisect_step(f, array, i, needle, test_object, direction, &m, &left, &right);
                                if (r < 0)
                                        return r;
                                if (r == TEST_GOTO_PREVIOUS)
                                        goto previous;
                                if (r == TEST_GOTO_NEXT)
                                        return 0; /* Found a corrupt entry, and the array was cut short. */
                        }
                }

                /* Not found in this array (or the last entry of this array should be returned), go to the next array. */
                assert(r == (direction == DIRECTION_DOWN ? TEST_GOTO_NEXT : TEST_LEFT));

                if (k >= n) {
                        if (direction == DIRECTION_UP) {
                                assert(n > 0);
                                i = n - 1;
                                goto found;
                        }

                        return 0;
                }

                n -= k;
                t += k;
                last_index = UINT64_MAX;
                a = le64toh(array->entry_array.next_entry_array_offset);
        }

        return 0;

previous:
        /* Not found in the current array, return the last entry of the previous array. */
        assert(r == TEST_GOTO_PREVIOUS);

        /* The current array is the first in the chain. no previous array. */
        if (t == 0)
                return 0;

        /* When we are going downwards, there is no matching entries in the previous array. */
        if (direction == DIRECTION_DOWN)
                return 0;

        /* Indicate to go to the previous array later. Note, do not move to the previous array here,
         * as that may invalidate the current array object in the mmap cache and
         * journal_file_entry_array_item() below may read invalid address. */
        i = UINT64_MAX;

found:
        p = journal_file_entry_array_item(f, array, 0);
        if (p <= 0)
                return -EBADMSG;

        /* Let's cache this item for the next invocation */
        chain_cache_put(f->chain_cache, ci, first, a, p, t, i);

        if (i == UINT64_MAX) {
                uint64_t m;

                /* Get the last entry of the previous array. */

                r = bump_entry_array(f, NULL, a, first, DIRECTION_UP, &a);
                if (r <= 0)
                        return r;

                r = journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &array);
                if (r < 0)
                        return r;

                m = journal_file_entry_array_n_items(f, array);
                if (m == 0 || t < m)
                        return -EBADMSG;

                t -= m;
                i = m - 1;
        }

        p = journal_file_entry_array_item(f, array, i);
        if (p == 0)
                return -EBADMSG;

        if (ret_object) {
                r = journal_file_move_to_object(f, OBJECT_ENTRY, p, ret_object);
                if (r < 0)
                        return r;
        }

        if (ret_offset)
                *ret_offset = p;

        if (ret_idx)
                *ret_idx = t + i;

        return 1;
}

static int generic_array_bisect_for_data(
                JournalFile *f,
                Object *d,
                uint64_t needle,
                int (*test_object)(JournalFile *f, uint64_t p, uint64_t needle),
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        uint64_t extra, first, n;
        int r;

        assert(f);
        assert(d);
        assert(d->object.type == OBJECT_DATA);
        assert(test_object);

        n = le64toh(d->data.n_entries);
        if (n <= 0)
                return 0;
        n--; /* n_entries is the number of entries linked to the data object, including the 'extra' entry. */

        extra = le64toh(d->data.entry_offset);
        first = le64toh(d->data.entry_array_offset);

        /* This bisects the array in object 'first', but first checks an extra. */
        r = test_object(f, extra, needle);
        if (r < 0)
                return r;

        if (direction == DIRECTION_DOWN) {
                /* If we are going downwards, then we need to return the first object that passes the test.
                 * When there is no object that passes the test, we need to return the first object that
                 * test_object() returns TEST_RIGHT for. */
                if (IN_SET(r,
                           TEST_FOUND,  /* The 'extra' object passes the test. Hence, this is the first
                                         * object that passes the test. */
                           TEST_RIGHT)) /* The 'extra' object is the first object that test_object() returns
                                         * TEST_RIGHT for, and no object exists even in the chained arrays
                                         * that passes the test. */
                        goto use_extra; /* The 'extra' object is exactly the one we are looking for. It is
                                         * not necessary to bisect the chained arrays. */

                /* Otherwise, the 'extra' object is not the one we are looking for. Search in the arrays. */

        } else {
                /* If we are going upwards, then we need to return the last object that passes the test.
                 * When there is no object that passes the test, we need to return the the last object that
                 * test_object() returns TEST_LEFT for. */
                if (r == TEST_RIGHT)
                        return 0; /* Not only the 'extra' object, but also all objects in the chained arrays
                                   * will never get TEST_FOUND or TEST_LEFT. The object we are looking for
                                   * does not exist. */

                /* Even if the 'extra' object passes the test, there may be multiple objects in the arrays
                 * that also pass the test. Hence, we need to bisect the arrays for finding the last matching
                 * object. */
        }

        r = generic_array_bisect(f, first, n, needle, test_object, direction, ret_object, ret_offset, NULL);
        if (r != 0)
                return r; /* When > 0, the found object is the first (or last, when DIRECTION_UP) object.
                           * Hence, return the found object now. */

        /* No matching object found in the chained arrays.
         * DIRECTION_DOWN : the 'extra' object neither matches the condition. There is no matching object.
         * DIRECTION_UP   : the 'extra' object matches the condition. So, return it. */
        if (direction == DIRECTION_DOWN)
                return 0;

use_extra:
        if (ret_object) {
                r = journal_file_move_to_object(f, OBJECT_ENTRY, extra, ret_object);
                if (r < 0)
                        return r;
        }

        if (ret_offset)
                *ret_offset = extra;

        return 1;
}

static int test_object_offset(JournalFile *f, uint64_t p, uint64_t needle) {
        assert(f);
        assert(p > 0);

        if (p == needle)
                return TEST_FOUND;
        else if (p < needle)
                return TEST_LEFT;
        else
                return TEST_RIGHT;
}

int journal_file_move_to_entry_by_offset(
                JournalFile *f,
                uint64_t p,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        assert(f);
        assert(f->header);

        return generic_array_bisect(
                        f,
                        le64toh(f->header->entry_array_offset),
                        le64toh(f->header->n_entries),
                        p,
                        test_object_offset,
                        direction,
                        ret_object, ret_offset, NULL);
}

static int test_object_seqnum(JournalFile *f, uint64_t p, uint64_t needle) {
        uint64_t sq;
        Object *o;
        int r;

        assert(f);
        assert(p > 0);

        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
        if (r < 0)
                return r;

        sq = le64toh(READ_NOW(o->entry.seqnum));
        if (sq == needle)
                return TEST_FOUND;
        else if (sq < needle)
                return TEST_LEFT;
        else
                return TEST_RIGHT;
}

int journal_file_move_to_entry_by_seqnum(
                JournalFile *f,
                uint64_t seqnum,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        assert(f);
        assert(f->header);

        return generic_array_bisect(
                        f,
                        le64toh(f->header->entry_array_offset),
                        le64toh(f->header->n_entries),
                        seqnum,
                        test_object_seqnum,
                        direction,
                        ret_object, ret_offset, NULL);
}

static int test_object_realtime(JournalFile *f, uint64_t p, uint64_t needle) {
        Object *o;
        uint64_t rt;
        int r;

        assert(f);
        assert(p > 0);

        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
        if (r < 0)
                return r;

        rt = le64toh(READ_NOW(o->entry.realtime));
        if (rt == needle)
                return TEST_FOUND;
        else if (rt < needle)
                return TEST_LEFT;
        else
                return TEST_RIGHT;
}

int journal_file_move_to_entry_by_realtime(
                JournalFile *f,
                uint64_t realtime,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        assert(f);
        assert(f->header);

        return generic_array_bisect(
                        f,
                        le64toh(f->header->entry_array_offset),
                        le64toh(f->header->n_entries),
                        realtime,
                        test_object_realtime,
                        direction,
                        ret_object, ret_offset, NULL);
}

static int test_object_monotonic(JournalFile *f, uint64_t p, uint64_t needle) {
        Object *o;
        uint64_t m;
        int r;

        assert(f);
        assert(p > 0);

        r = journal_file_move_to_object(f, OBJECT_ENTRY, p, &o);
        if (r < 0)
                return r;

        m = le64toh(READ_NOW(o->entry.monotonic));
        if (m == needle)
                return TEST_FOUND;
        else if (m < needle)
                return TEST_LEFT;
        else
                return TEST_RIGHT;
}

static int find_data_object_by_boot_id(
                JournalFile *f,
                sd_id128_t boot_id,
                Object **ret_object,
                uint64_t *ret_offset) {

        char t[STRLEN("_BOOT_ID=") + 32 + 1] = "_BOOT_ID=";

        assert(f);

        sd_id128_to_string(boot_id, t + 9);
        return journal_file_find_data_object(f, t, sizeof(t) - 1, ret_object, ret_offset);
}

int journal_file_move_to_entry_by_monotonic(
                JournalFile *f,
                sd_id128_t boot_id,
                uint64_t monotonic,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        Object *o;
        int r;

        assert(f);

        r = find_data_object_by_boot_id(f, boot_id, &o, NULL);
        if (r <= 0)
                return r;

        return generic_array_bisect_for_data(
                        f,
                        o,
                        monotonic,
                        test_object_monotonic,
                        direction,
                        ret_object, ret_offset);
}

void journal_file_reset_location(JournalFile *f) {
        assert(f);

        f->location_type = LOCATION_HEAD;
        f->current_offset = 0;
        f->current_seqnum = 0;
        f->current_realtime = 0;
        f->current_monotonic = 0;
        zero(f->current_boot_id);
        f->current_xor_hash = 0;

        /* Also reset the previous reading direction. Otherwise, next_beyond_location() may wrongly handle we
         * already hit EOF. See issue #29216. */
        f->last_direction = _DIRECTION_INVALID;
}

void journal_file_save_location(JournalFile *f, Object *o, uint64_t offset) {
        assert(f);
        assert(o);

        f->location_type = LOCATION_SEEK;
        f->current_offset = offset;
        f->current_seqnum = le64toh(o->entry.seqnum);
        f->current_realtime = le64toh(o->entry.realtime);
        f->current_monotonic = le64toh(o->entry.monotonic);
        f->current_boot_id = o->entry.boot_id;
        f->current_xor_hash = le64toh(o->entry.xor_hash);
}

static bool check_properly_ordered(uint64_t new_offset, uint64_t old_offset, direction_t direction) {

        /* Consider it an error if any of the two offsets is uninitialized */
        if (old_offset == 0 || new_offset == 0)
                return false;

        /* If we go down, the new offset must be larger than the old one. */
        return direction == DIRECTION_DOWN ?
                new_offset > old_offset  :
                new_offset < old_offset;
}

int journal_file_next_entry(
                JournalFile *f,
                uint64_t p,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        uint64_t i, n, q;
        Object *o;
        int r;

        assert(f);
        assert(f->header);

        /* FIXME: fix return value assignment. */

        n = le64toh(READ_NOW(f->header->n_entries));
        if (n <= 0)
                return 0;

        /* When the input offset 'p' is zero, return the first (or last on DIRECTION_UP) entry. */
        if (p == 0)
                return generic_array_get(f,
                                         le64toh(f->header->entry_array_offset),
                                         direction == DIRECTION_DOWN ? 0 : n - 1,
                                         direction,
                                         ret_object, ret_offset);

        /* Otherwise, first find the nearest entry object. */
        r = generic_array_bisect(f,
                                 le64toh(f->header->entry_array_offset),
                                 le64toh(f->header->n_entries),
                                 p,
                                 test_object_offset,
                                 direction,
                                 ret_object ? &o : NULL, &q, &i);
        if (r <= 0)
                return r;

        assert(direction == DIRECTION_DOWN ? p <= q : q <= p);

        /* If the input offset 'p' points to an entry object, generic_array_bisect() should provides
         * the same offset, and the index needs to be shifted. Otherwise, use the found object as is,
         * as it is the nearest entry object from the input offset 'p'. */

        if (p != q)
                goto found;

        r = bump_array_index(&i, direction, n);
        if (r <= 0)
                return r;

        /* And jump to it */
        r = generic_array_get(f, le64toh(f->header->entry_array_offset), i, direction, ret_object ? &o : NULL, &q);
        if (r <= 0)
                return r;

        /* Ensure our array is properly ordered. */
        if (!check_properly_ordered(q, p, direction))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "%s: entry array not properly ordered at entry index %" PRIu64,
                                       f->path, i);
found:
        if (ret_object)
                *ret_object = o;
        if (ret_offset)
                *ret_offset = q;

        return 1;
}

int journal_file_move_to_entry_for_data(
                JournalFile *f,
                Object *d,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        uint64_t extra, first, n;
        int r = 0;

        assert(f);
        assert(d);
        assert(d->object.type == OBJECT_DATA);
        assert(IN_SET(direction, DIRECTION_DOWN, DIRECTION_UP));

        /* FIXME: fix return value assignment. */

        /* This returns the first (when the direction is down, otherwise the last) entry linked to the
         * specified data object. */

        n = le64toh(d->data.n_entries);
        if (n <= 0)
                return 0;
        n--; /* n_entries is the number of entries linked to the data object, including the 'extra' entry. */

        extra = le64toh(d->data.entry_offset);
        first = le64toh(d->data.entry_array_offset);

        if (direction == DIRECTION_DOWN && extra > 0) {
                /* When we are going downwards, first try to read the extra entry. */
                r = journal_file_move_to_object(f, OBJECT_ENTRY, extra, ret_object);
                if (r >= 0)
                        goto use_extra;
                if (!IN_SET(r, -EADDRNOTAVAIL, -EBADMSG))
                        return r;
        }

        if (n > 0) {
                /* DIRECTION_DOWN : The extra entry is broken, falling back to the entries in the array.
                 * DIRECTION_UP   : Try to find a valid entry in the array from the tail. */
                r = generic_array_get(f,
                                      first,
                                      direction == DIRECTION_DOWN ? 0 : n - 1,
                                      direction,
                                      ret_object, ret_offset);
                if (!IN_SET(r, 0, -EADDRNOTAVAIL, -EBADMSG))
                        return r; /* found or critical error. */
        }

        if (direction == DIRECTION_UP && extra > 0) {
                /* No valid entry exists in the chained array, falling back to the extra entry. */
                r = journal_file_move_to_object(f, OBJECT_ENTRY, extra, ret_object);
                if (r >= 0)
                        goto use_extra;
        }

        return r;

use_extra:
        if (ret_offset)
                *ret_offset = extra;

        return 1;
}

int journal_file_move_to_entry_by_offset_for_data(
                JournalFile *f,
                Object *d,
                uint64_t p,
                direction_t direction,
                Object **ret, uint64_t *ret_offset) {

        assert(f);
        assert(d);
        assert(d->object.type == OBJECT_DATA);

        return generic_array_bisect_for_data(
                        f,
                        d,
                        p,
                        test_object_offset,
                        direction,
                        ret, ret_offset);
}

int journal_file_move_to_entry_by_monotonic_for_data(
                JournalFile *f,
                Object *d,
                sd_id128_t boot_id,
                uint64_t monotonic,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        Object *o, *entry;
        uint64_t z;
        int r;

        assert(f);
        assert(d);
        assert(d->object.type == OBJECT_DATA);

        /* First, pin the given data object, before reading the _BOOT_ID= data object below. */
        r = journal_file_pin_object(f, d);
        if (r < 0)
                return r;

        /* Then, read a data object for _BOOT_ID= and seek by time. */
        r = find_data_object_by_boot_id(f, boot_id, &o, NULL);
        if (r <= 0)
                return r;

        r = generic_array_bisect_for_data(f,
                                          o,
                                          monotonic,
                                          test_object_monotonic,
                                          direction,
                                          NULL, &z);
        if (r <= 0)
                return r;

        /* And now, continue seeking until we find an entry that exists in both bisection arrays. */
        for (;;) {
                uint64_t p;

                /* The journal entry found by the above bisect_plus_one() may not have the specified data,
                 * that is, it may not be linked in the data object. So, we need to check that. */

                r = journal_file_move_to_entry_by_offset_for_data(
                                f, d, z, direction, ret_object ? &entry : NULL, &p);
                if (r <= 0)
                        return r;
                if (p == z)
                        break; /* The journal entry has the specified data. Yay! */

                /* If the entry does not have the data, then move to the next (or previous, depends on the
                 * 'direction') entry linked to the data object. But, the next entry may be in another boot.
                 * So, we need to check that the entry has the matching boot ID. */

                r = journal_file_move_to_entry_by_offset_for_data(
                                f, o, p, direction, ret_object ? &entry : NULL, &z);
                if (r <= 0)
                        return r;
                if (p == z)
                        break; /* The journal entry has the specified boot ID. Yay! */

                /* If not, let's try to the next entry... */
        }

        if (ret_object)
                *ret_object = entry;
        if (ret_offset)
                *ret_offset = z;
        return 1;
}

int journal_file_move_to_entry_by_seqnum_for_data(
                JournalFile *f,
                Object *d,
                uint64_t seqnum,
                direction_t direction,
                Object **ret_object,
                uint64_t *ret_offset) {

        assert(f);
        assert(d);
        assert(d->object.type == OBJECT_DATA);

        return generic_array_bisect_for_data(
                        f,
                        d,
                        seqnum,
                        test_object_seqnum,
                        direction,
                        ret_object, ret_offset);
}

int journal_file_move_to_entry_by_realtime_for_data(
                JournalFile *f,
                Object *d,
                uint64_t realtime,
                direction_t direction,
                Object **ret, uint64_t *ret_offset) {

        assert(f);
        assert(d);
        assert(d->object.type == OBJECT_DATA);

        return generic_array_bisect_for_data(
                        f,
                        d,
                        realtime,
                        test_object_realtime,
                        direction,
                        ret, ret_offset);
}

void journal_file_dump(JournalFile *f) {
        Object *o;
        uint64_t p;
        int r;

        assert(f);
        assert(f->header);

        journal_file_print_header(f);

        p = le64toh(READ_NOW(f->header->header_size));
        while (p != 0) {
                const char *s;
                Compression c;

                r = journal_file_move_to_object(f, OBJECT_UNUSED, p, &o);
                if (r < 0)
                        goto fail;

                s = journal_object_type_to_string(o->object.type);

                switch (o->object.type) {

                case OBJECT_ENTRY:
                        assert(s);

                        printf("Type: %s seqnum=%"PRIu64" monotonic=%"PRIu64" realtime=%"PRIu64"\n",
                               s,
                               le64toh(o->entry.seqnum),
                               le64toh(o->entry.monotonic),
                               le64toh(o->entry.realtime));
                        break;

                case OBJECT_TAG:
                        assert(s);

                        printf("Type: %s seqnum=%"PRIu64" epoch=%"PRIu64"\n",
                               s,
                               le64toh(o->tag.seqnum),
                               le64toh(o->tag.epoch));
                        break;

                default:
                        if (s)
                                printf("Type: %s \n", s);
                        else
                                printf("Type: unknown (%i)", o->object.type);

                        break;
                }

                c = COMPRESSION_FROM_OBJECT(o);
                if (c > COMPRESSION_NONE)
                        printf("Flags: %s\n",
                               compression_to_string(c));

                if (p == le64toh(f->header->tail_object_offset))
                        p = 0;
                else
                        p += ALIGN64(le64toh(o->object.size));
        }

        return;
fail:
        log_error("File corrupt");
}

/* Note: the lifetime of the compound literal is the immediately surrounding block. */
#define FORMAT_TIMESTAMP_SAFE(t) (FORMAT_TIMESTAMP(t) ?: " --- ")

void journal_file_print_header(JournalFile *f) {
        struct stat st;

        assert(f);
        assert(f->header);

        printf("File path: %s\n"
               "File ID: %s\n"
               "Machine ID: %s\n"
               "Boot ID: %s\n"
               "Sequential number ID: %s\n"
               "State: %s\n"
               "Compatible flags:%s%s%s%s\n"
               "Incompatible flags:%s%s%s%s%s%s\n"
               "Header size: %"PRIu64"\n"
               "Arena size: %"PRIu64"\n"
               "Data hash table size: %"PRIu64"\n"
               "Field hash table size: %"PRIu64"\n"
               "Rotate suggested: %s\n"
               "Head sequential number: %"PRIu64" (%"PRIx64")\n"
               "Tail sequential number: %"PRIu64" (%"PRIx64")\n"
               "Head realtime timestamp: %s (%"PRIx64")\n"
               "Tail realtime timestamp: %s (%"PRIx64")\n"
               "Tail monotonic timestamp: %s (%"PRIx64")\n"
               "Objects: %"PRIu64"\n"
               "Entry objects: %"PRIu64"\n",
               f->path,
               SD_ID128_TO_STRING(f->header->file_id),
               SD_ID128_TO_STRING(f->header->machine_id),
               SD_ID128_TO_STRING(f->header->tail_entry_boot_id),
               SD_ID128_TO_STRING(f->header->seqnum_id),
               f->header->state == STATE_OFFLINE ? "OFFLINE" :
               f->header->state == STATE_ONLINE ? "ONLINE" :
               f->header->state == STATE_ARCHIVED ? "ARCHIVED" : "UNKNOWN",
               JOURNAL_HEADER_SEALED(f->header) ? " SEALED" : "",
               JOURNAL_HEADER_SEALED_CONTINUOUS(f->header) ? " SEALED_CONTINUOUS" : "",
               JOURNAL_HEADER_TAIL_ENTRY_BOOT_ID(f->header) ? " TAIL_ENTRY_BOOT_ID" : "",
               (le32toh(f->header->compatible_flags) & ~HEADER_COMPATIBLE_ANY) ? " ???" : "",
               JOURNAL_HEADER_COMPRESSED_XZ(f->header) ? " COMPRESSED-XZ" : "",
               JOURNAL_HEADER_COMPRESSED_LZ4(f->header) ? " COMPRESSED-LZ4" : "",
               JOURNAL_HEADER_COMPRESSED_ZSTD(f->header) ? " COMPRESSED-ZSTD" : "",
               JOURNAL_HEADER_KEYED_HASH(f->header) ? " KEYED-HASH" : "",
               JOURNAL_HEADER_COMPACT(f->header) ? " COMPACT" : "",
               (le32toh(f->header->incompatible_flags) & ~HEADER_INCOMPATIBLE_ANY) ? " ???" : "",
               le64toh(f->header->header_size),
               le64toh(f->header->arena_size),
               le64toh(f->header->data_hash_table_size) / sizeof(HashItem),
               le64toh(f->header->field_hash_table_size) / sizeof(HashItem),
               yes_no(journal_file_rotate_suggested(f, 0, LOG_DEBUG)),
               le64toh(f->header->head_entry_seqnum), le64toh(f->header->head_entry_seqnum),
               le64toh(f->header->tail_entry_seqnum), le64toh(f->header->tail_entry_seqnum),
               FORMAT_TIMESTAMP_SAFE(le64toh(f->header->head_entry_realtime)), le64toh(f->header->head_entry_realtime),
               FORMAT_TIMESTAMP_SAFE(le64toh(f->header->tail_entry_realtime)), le64toh(f->header->tail_entry_realtime),
               FORMAT_TIMESPAN(le64toh(f->header->tail_entry_monotonic), USEC_PER_MSEC), le64toh(f->header->tail_entry_monotonic),
               le64toh(f->header->n_objects),
               le64toh(f->header->n_entries));

        if (JOURNAL_HEADER_CONTAINS(f->header, n_data))
                printf("Data objects: %"PRIu64"\n"
                       "Data hash table fill: %.1f%%\n",
                       le64toh(f->header->n_data),
                       100.0 * (double) le64toh(f->header->n_data) / ((double) (le64toh(f->header->data_hash_table_size) / sizeof(HashItem))));

        if (JOURNAL_HEADER_CONTAINS(f->header, n_fields))
                printf("Field objects: %"PRIu64"\n"
                       "Field hash table fill: %.1f%%\n",
                       le64toh(f->header->n_fields),
                       100.0 * (double) le64toh(f->header->n_fields) / ((double) (le64toh(f->header->field_hash_table_size) / sizeof(HashItem))));

        if (JOURNAL_HEADER_CONTAINS(f->header, n_tags))
                printf("Tag objects: %"PRIu64"\n",
                       le64toh(f->header->n_tags));
        if (JOURNAL_HEADER_CONTAINS(f->header, n_entry_arrays))
                printf("Entry array objects: %"PRIu64"\n",
                       le64toh(f->header->n_entry_arrays));

        if (JOURNAL_HEADER_CONTAINS(f->header, field_hash_chain_depth))
                printf("Deepest field hash chain: %" PRIu64"\n",
                       f->header->field_hash_chain_depth);

        if (JOURNAL_HEADER_CONTAINS(f->header, data_hash_chain_depth))
                printf("Deepest data hash chain: %" PRIu64"\n",
                       f->header->data_hash_chain_depth);

        if (fstat(f->fd, &st) >= 0)
                printf("Disk usage: %s\n", FORMAT_BYTES((uint64_t) st.st_blocks * 512ULL));
}

static int journal_file_warn_btrfs(JournalFile *f) {
        unsigned attrs;
        int r;

        assert(f);

        /* Before we write anything, check if the COW logic is turned
         * off on btrfs. Given our write pattern that is quite
         * unfriendly to COW file systems this should greatly improve
         * performance on COW file systems, such as btrfs, at the
         * expense of data integrity features (which shouldn't be too
         * bad, given that we do our own checksumming). */

        r = fd_is_fs_type(f->fd, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT, "Failed to determine if journal is on btrfs: %m");
        if (r == 0)
                return 0;

        r = read_attr_fd(f->fd, &attrs);
        if (r < 0)
                return log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT, "Failed to read file attributes: %m");

        if (attrs & FS_NOCOW_FL) {
                log_debug("Detected btrfs file system with copy-on-write disabled, all is good.");
                return 0;
        }

        log_ratelimit_notice(JOURNAL_LOG_RATELIMIT,
                             "Creating journal file %s on a btrfs file system, and copy-on-write is enabled. "
                             "This is likely to slow down journal access substantially, please consider turning "
                             "off the copy-on-write file attribute on the journal directory, using chattr +C.",
                             f->path);

        return 1;
}

static void journal_default_metrics(JournalMetrics *m, int fd, bool compact) {
        struct statvfs ss;
        uint64_t fs_size = 0;

        assert(m);
        assert(fd >= 0);

        if (fstatvfs(fd, &ss) >= 0)
                fs_size = u64_multiply_safe(ss.f_frsize, ss.f_blocks);
        else
                log_debug_errno(errno, "Failed to determine disk size: %m");

        if (m->max_use == UINT64_MAX) {

                if (fs_size > 0)
                        m->max_use = CLAMP(PAGE_ALIGN_U64(fs_size / 10), /* 10% of file system size */
                                           MAX_USE_LOWER, MAX_USE_UPPER);
                else
                        m->max_use = MAX_USE_LOWER;
        } else {
                m->max_use = PAGE_ALIGN_U64(m->max_use);

                if (m->max_use != 0 && m->max_use < JOURNAL_FILE_SIZE_MIN*2)
                        m->max_use = JOURNAL_FILE_SIZE_MIN*2;
        }

        if (m->min_use == UINT64_MAX) {
                if (fs_size > 0)
                        m->min_use = CLAMP(PAGE_ALIGN_U64(fs_size / 50), /* 2% of file system size */
                                           MIN_USE_LOW, MIN_USE_HIGH);
                else
                        m->min_use = MIN_USE_LOW;
        }

        if (m->min_use > m->max_use)
                m->min_use = m->max_use;

        if (m->max_size == UINT64_MAX)
                m->max_size = MIN(PAGE_ALIGN_U64(m->max_use / 8), /* 8 chunks */
                                  MAX_SIZE_UPPER);
        else
                m->max_size = PAGE_ALIGN_U64(m->max_size);

        if (compact && m->max_size > JOURNAL_COMPACT_SIZE_MAX)
                m->max_size = JOURNAL_COMPACT_SIZE_MAX;

        if (m->max_size != 0) {
                if (m->max_size < JOURNAL_FILE_SIZE_MIN)
                        m->max_size = JOURNAL_FILE_SIZE_MIN;

                if (m->max_use != 0 && m->max_size*2 > m->max_use)
                        m->max_use = m->max_size*2;
        }

        if (m->min_size == UINT64_MAX)
                m->min_size = JOURNAL_FILE_SIZE_MIN;
        else
                m->min_size = CLAMP(PAGE_ALIGN_U64(m->min_size),
                                    JOURNAL_FILE_SIZE_MIN,
                                    m->max_size ?: UINT64_MAX);

        if (m->keep_free == UINT64_MAX) {
                if (fs_size > 0)
                        m->keep_free = MIN(PAGE_ALIGN_U64(fs_size / 20), /* 5% of file system size */
                                           KEEP_FREE_UPPER);
                else
                        m->keep_free = DEFAULT_KEEP_FREE;
        }

        if (m->n_max_files == UINT64_MAX)
                m->n_max_files = DEFAULT_N_MAX_FILES;

        log_debug("Fixed min_use=%s max_use=%s max_size=%s min_size=%s keep_free=%s n_max_files=%" PRIu64,
                  FORMAT_BYTES(m->min_use),
                  FORMAT_BYTES(m->max_use),
                  FORMAT_BYTES(m->max_size),
                  FORMAT_BYTES(m->min_size),
                  FORMAT_BYTES(m->keep_free),
                  m->n_max_files);
}

int journal_file_open(
                int fd,
                const char *fname,
                int open_flags,
                JournalFileFlags file_flags,
                mode_t mode,
                uint64_t compress_threshold_bytes,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                JournalFile *template,
                JournalFile **ret) {

        bool newly_created = false;
        JournalFile *f;
        void *h;
        int r;

        assert(fd >= 0 || fname);
        assert(file_flags >= 0);
        assert(file_flags <= _JOURNAL_FILE_FLAGS_MAX);
        assert(mmap_cache);
        assert(ret);

        if (!IN_SET((open_flags & O_ACCMODE), O_RDONLY, O_RDWR))
                return -EINVAL;

        if ((open_flags & O_ACCMODE) == O_RDONLY && FLAGS_SET(open_flags, O_CREAT))
                return -EINVAL;

        if (fname && (open_flags & O_CREAT) && !endswith(fname, ".journal"))
                return -EINVAL;

        f = new(JournalFile, 1);
        if (!f)
                return -ENOMEM;

        *f = (JournalFile) {
                .fd = fd,
                .mode = mode,
                .open_flags = open_flags,
                .compress_threshold_bytes = compress_threshold_bytes == UINT64_MAX ?
                                            DEFAULT_COMPRESS_THRESHOLD :
                                            MAX(MIN_COMPRESS_THRESHOLD, compress_threshold_bytes),
                .strict_order = FLAGS_SET(file_flags, JOURNAL_STRICT_ORDER),
                .newest_boot_id_prioq_idx = PRIOQ_IDX_NULL,
                .last_direction = _DIRECTION_INVALID,
        };

        if (fname) {
                f->path = strdup(fname);
                if (!f->path) {
                        r = -ENOMEM;
                        goto fail;
                }
        } else {
                assert(fd >= 0);

                /* If we don't know the path, fill in something explanatory and vaguely useful */
                if (asprintf(&f->path, "/proc/self/%i", fd) < 0) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        f->chain_cache = ordered_hashmap_new(&uint64_hash_ops);
        if (!f->chain_cache) {
                r = -ENOMEM;
                goto fail;
        }

        if (f->fd < 0) {
                /* We pass O_NONBLOCK here, so that in case somebody pointed us to some character device node or FIFO
                 * or so, we likely fail quickly than block for long. For regular files O_NONBLOCK has no effect, hence
                 * it doesn't hurt in that case. */

                f->fd = openat_report_new(AT_FDCWD, f->path, f->open_flags|O_CLOEXEC|O_NONBLOCK, f->mode, &newly_created);
                if (f->fd < 0) {
                        r = f->fd;
                        goto fail;
                }

                /* fds we opened here by us should also be closed by us. */
                f->close_fd = true;

                r = fd_nonblock(f->fd, false);
                if (r < 0)
                        goto fail;

                if (!newly_created) {
                        r = journal_file_fstat(f);
                        if (r < 0)
                                goto fail;
                }
        } else {
                r = journal_file_fstat(f);
                if (r < 0)
                        goto fail;

                /* If we just got the fd passed in, we don't really know if we created the file anew */
                newly_created = f->last_stat.st_size == 0 && journal_file_writable(f);
        }

        r = mmap_cache_add_fd(mmap_cache, f->fd, mmap_prot_from_open_flags(open_flags), &f->cache_fd);
        if (r < 0)
                goto fail;

        if (newly_created) {
                (void) journal_file_warn_btrfs(f);

                /* Let's attach the creation time to the journal file, so that the vacuuming code knows the age of this
                 * file even if the file might end up corrupted one day... Ideally we'd just use the creation time many
                 * file systems maintain for each file, but the API to query this is very new, hence let's emulate this
                 * via extended attributes. If extended attributes are not supported we'll just skip this, and rely
                 * solely on mtime/atime/ctime of the file. */
                (void) fd_setcrtime(f->fd, 0);

                r = journal_file_init_header(f, file_flags, template);
                if (r < 0)
                        goto fail;

                r = journal_file_fstat(f);
                if (r < 0)
                        goto fail;
        }

        if (f->last_stat.st_size < (off_t) HEADER_SIZE_MIN) {
                r = -ENODATA;
                goto fail;
        }

        r = mmap_cache_fd_get(f->cache_fd, MMAP_CACHE_CATEGORY_HEADER, true, 0, PAGE_ALIGN(sizeof(Header)), &f->last_stat, &h);
        if (r == -EINVAL) {
                /* Some file systems (jffs2 or p9fs) don't support mmap() properly (or only read-only
                 * mmap()), and return EINVAL in that case. Let's propagate that as a more recognizable error
                 * code. */
                r = -EAFNOSUPPORT;
                goto fail;
        }
        if (r < 0)
                goto fail;

        f->header = h;

        if (!newly_created) {
                r = journal_file_verify_header(f);
                if (r < 0)
                        goto fail;
        }

#if HAVE_GCRYPT
        if (!newly_created && journal_file_writable(f) && JOURNAL_HEADER_SEALED(f->header)) {
                r = journal_file_fss_load(f);
                if (r < 0)
                        goto fail;
        }
#endif

        if (journal_file_writable(f)) {
                if (metrics) {
                        journal_default_metrics(metrics, f->fd, JOURNAL_HEADER_COMPACT(f->header));
                        f->metrics = *metrics;
                } else if (template)
                        f->metrics = template->metrics;

                r = journal_file_refresh_header(f);
                if (r < 0)
                        goto fail;
        }

#if HAVE_GCRYPT
        r = journal_file_hmac_setup(f);
        if (r < 0)
                goto fail;
#endif

        if (newly_created) {
                r = journal_file_setup_field_hash_table(f);
                if (r < 0)
                        goto fail;

                r = journal_file_setup_data_hash_table(f);
                if (r < 0)
                        goto fail;

#if HAVE_GCRYPT
                r = journal_file_append_first_tag(f);
                if (r < 0)
                        goto fail;
#endif
        }

        if (mmap_cache_fd_got_sigbus(f->cache_fd)) {
                r = -EIO;
                goto fail;
        }

        if (template && template->post_change_timer) {
                r = journal_file_enable_post_change_timer(
                                f,
                                sd_event_source_get_event(template->post_change_timer),
                                template->post_change_timer_period);

                if (r < 0)
                        goto fail;
        }

        /* The file is opened now successfully, thus we take possession of any passed in fd. */
        f->close_fd = true;

        if (DEBUG_LOGGING) {
                static int last_seal = -1, last_keyed_hash = -1;
                static Compression last_compression = _COMPRESSION_INVALID;
                static uint64_t last_bytes = UINT64_MAX;

                if (last_seal != JOURNAL_HEADER_SEALED(f->header) ||
                    last_keyed_hash != JOURNAL_HEADER_KEYED_HASH(f->header) ||
                    last_compression != JOURNAL_FILE_COMPRESSION(f) ||
                    last_bytes != f->compress_threshold_bytes) {

                        log_debug("Journal effective settings seal=%s keyed_hash=%s compress=%s compress_threshold_bytes=%s",
                                  yes_no(JOURNAL_HEADER_SEALED(f->header)), yes_no(JOURNAL_HEADER_KEYED_HASH(f->header)),
                                  compression_to_string(JOURNAL_FILE_COMPRESSION(f)), FORMAT_BYTES(f->compress_threshold_bytes));
                        last_seal = JOURNAL_HEADER_SEALED(f->header);
                        last_keyed_hash = JOURNAL_HEADER_KEYED_HASH(f->header);
                        last_compression = JOURNAL_FILE_COMPRESSION(f);
                        last_bytes = f->compress_threshold_bytes;
                }
        }

        *ret = f;
        return 0;

fail:
        if (f->cache_fd && mmap_cache_fd_got_sigbus(f->cache_fd))
                r = -EIO;

        (void) journal_file_close(f);

        if (newly_created && fd < 0)
                (void) unlink(fname);

        return r;
}

int journal_file_parse_uid_from_filename(const char *path, uid_t *ret_uid) {
        _cleanup_free_ char *buf = NULL, *p = NULL;
        const char *a, *b, *at;
        int r;

        /* This helper returns -EREMOTE when the filename doesn't match user online/offline journal
         * pattern. Hence it currently doesn't parse archived or disposed user journals. */

        assert(path);
        assert(ret_uid);

        r = path_extract_filename(path, &p);
        if (r < 0)
                return r;
        if (r == O_DIRECTORY)
                return -EISDIR;

        a = startswith(p, "user-");
        if (!a)
                return -EREMOTE;
        b = endswith(p, ".journal");
        if (!b)
                return -EREMOTE;

        at = strchr(a, '@');
        if (at)
                return -EREMOTE;

        buf = strndup(a, b-a);
        if (!buf)
                return -ENOMEM;

        return parse_uid(buf, ret_uid);
}

int journal_file_archive(JournalFile *f, char **ret_previous_path) {
        _cleanup_free_ char *p = NULL;

        assert(f);

        if (!journal_file_writable(f))
                return -EINVAL;

        /* Is this a journal file that was passed to us as fd? If so, we synthesized a path name for it, and we refuse
         * rotation, since we don't know the actual path, and couldn't rename the file hence. */
        if (path_startswith(f->path, "/proc/self/fd"))
                return -EINVAL;

        if (!endswith(f->path, ".journal"))
                return -EINVAL;

        if (asprintf(&p, "%.*s@" SD_ID128_FORMAT_STR "-%016"PRIx64"-%016"PRIx64".journal",
                     (int) strlen(f->path) - 8, f->path,
                     SD_ID128_FORMAT_VAL(f->header->seqnum_id),
                     le64toh(f->header->head_entry_seqnum),
                     le64toh(f->header->head_entry_realtime)) < 0)
                return -ENOMEM;

        /* Try to rename the file to the archived version. If the file already was deleted, we'll get ENOENT, let's
         * ignore that case. */
        if (rename(f->path, p) < 0 && errno != ENOENT)
                return -errno;

        /* Sync the rename to disk */
        (void) fsync_directory_of_file(f->fd);

        if (ret_previous_path)
                *ret_previous_path = f->path;
        else
                free(f->path);

        f->path = TAKE_PTR(p);

        /* Set as archive so offlining commits w/state=STATE_ARCHIVED. Previously we would set old_file->header->state
         * to STATE_ARCHIVED directly here, but journal_file_set_offline() short-circuits when state != STATE_ONLINE,
         * which would result in the rotated journal never getting fsync() called before closing.  Now we simply queue
         * the archive state by setting an archive bit, leaving the state as STATE_ONLINE so proper offlining
         * occurs. */
        f->archive = true;

        return 0;
}

int journal_file_dispose(int dir_fd, const char *fname) {
        _cleanup_free_ char *p = NULL;

        assert(fname);

        /* Renames a journal file to *.journal~, i.e. to mark it as corrupted or otherwise uncleanly shutdown. Note that
         * this is done without looking into the file or changing any of its contents. The idea is that this is called
         * whenever something is suspicious and we want to move the file away and make clear that it is not accessed
         * for writing anymore. */

        if (!endswith(fname, ".journal"))
                return -EINVAL;

        if (asprintf(&p, "%.*s@%016" PRIx64 "-%016" PRIx64 ".journal~",
                     (int) strlen(fname) - 8, fname,
                     now(CLOCK_REALTIME),
                     random_u64()) < 0)
                return -ENOMEM;

        if (renameat(dir_fd, fname, dir_fd, p) < 0)
                return -errno;

        return 0;
}

int journal_file_copy_entry(
                JournalFile *from,
                JournalFile *to,
                Object *o,
                uint64_t p,
                uint64_t *seqnum,
                sd_id128_t *seqnum_id) {

        _cleanup_free_ EntryItem *items_alloc = NULL;
        EntryItem *items;
        uint64_t n, m = 0, xor_hash = 0;
        sd_id128_t boot_id;
        dual_timestamp ts;
        int r;

        assert(from);
        assert(to);
        assert(o);
        assert(p > 0);

        if (!journal_file_writable(to))
                return -EPERM;

        ts = (dual_timestamp) {
                .monotonic = le64toh(o->entry.monotonic),
                .realtime = le64toh(o->entry.realtime),
        };
        boot_id = o->entry.boot_id;

        n = journal_file_entry_n_items(from, o);
        if (n == 0)
                return 0;

        if (n < ALLOCA_MAX / sizeof(EntryItem) / 2)
                items = newa(EntryItem, n);
        else {
                items_alloc = new(EntryItem, n);
                if (!items_alloc)
                        return -ENOMEM;

                items = items_alloc;
        }

        for (uint64_t i = 0; i < n; i++) {
                uint64_t h, q;
                void *data;
                size_t l;
                Object *u;

                q = journal_file_entry_item_object_offset(from, o, i);
                r = journal_file_data_payload(from, NULL, q, NULL, 0, 0, &data, &l);
                if (IN_SET(r, -EADDRNOTAVAIL, -EBADMSG)) {
                        log_debug_errno(r, "Entry item %"PRIu64" data object is bad, skipping over it: %m", i);
                        continue;
                }
                if (r < 0)
                        return r;
                assert(r > 0);

                if (l == 0)
                        return -EBADMSG;

                r = journal_file_append_data(to, data, l, &u, &h);
                if (r < 0)
                        return r;

                if (JOURNAL_HEADER_KEYED_HASH(to->header))
                        xor_hash ^= jenkins_hash64(data, l);
                else
                        xor_hash ^= le64toh(u->data.hash);

                items[m++] = (EntryItem) {
                        .object_offset = h,
                        .hash = le64toh(u->data.hash),
                };
        }

        if (m == 0)
                return 0;

        r = journal_file_append_entry_internal(
                        to,
                        &ts,
                        &boot_id,
                        &from->header->machine_id,
                        xor_hash,
                        items,
                        m,
                        seqnum,
                        seqnum_id,
                        /* ret_object= */ NULL,
                        /* ret_offset= */ NULL);

        if (mmap_cache_fd_got_sigbus(to->cache_fd))
                return -EIO;

        return r;
}

void journal_reset_metrics(JournalMetrics *m) {
        assert(m);

        /* Set everything to "pick automatic values". */

        *m = (JournalMetrics) {
                .min_use = UINT64_MAX,
                .max_use = UINT64_MAX,
                .min_size = UINT64_MAX,
                .max_size = UINT64_MAX,
                .keep_free = UINT64_MAX,
                .n_max_files = UINT64_MAX,
        };
}

int journal_file_get_cutoff_realtime_usec(JournalFile *f, usec_t *ret_from, usec_t *ret_to) {
        assert(f);
        assert(f->header);
        assert(ret_from || ret_to);

        if (ret_from) {
                if (f->header->head_entry_realtime == 0)
                        return -ENOENT;

                *ret_from = le64toh(f->header->head_entry_realtime);
        }

        if (ret_to) {
                if (f->header->tail_entry_realtime == 0)
                        return -ENOENT;

                *ret_to = le64toh(f->header->tail_entry_realtime);
        }

        return 1;
}

int journal_file_get_cutoff_monotonic_usec(JournalFile *f, sd_id128_t boot_id, usec_t *ret_from, usec_t *ret_to) {
        Object *o;
        uint64_t p;
        int r;

        assert(f);
        assert(ret_from || ret_to);

        /* FIXME: fix return value assignment on success with 0. */

        r = find_data_object_by_boot_id(f, boot_id, &o, &p);
        if (r <= 0)
                return r;

        if (le64toh(o->data.n_entries) <= 0)
                return 0;

        if (ret_from) {
                r = journal_file_move_to_object(f, OBJECT_ENTRY, le64toh(o->data.entry_offset), &o);
                if (r < 0)
                        return r;

                *ret_from = le64toh(o->entry.monotonic);
        }

        if (ret_to) {
                r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
                if (r < 0)
                        return r;

                r = journal_file_move_to_entry_for_data(f, o, DIRECTION_UP, &o, NULL);
                if (r <= 0)
                        return r;

                *ret_to = le64toh(o->entry.monotonic);
        }

        return 1;
}

bool journal_file_rotate_suggested(JournalFile *f, usec_t max_file_usec, int log_level) {
        assert(f);
        assert(f->header);

        /* If we gained new header fields we gained new features,
         * hence suggest a rotation */
        if (le64toh(f->header->header_size) < sizeof(Header)) {
                log_ratelimit_full(log_level, JOURNAL_LOG_RATELIMIT,
                                   "%s uses an outdated header, suggesting rotation.", f->path);
                return true;
        }

        /* Let's check if the hash tables grew over a certain fill level (75%, borrowing this value from
         * Java's hash table implementation), and if so suggest a rotation. To calculate the fill level we
         * need the n_data field, which only exists in newer versions. */

        if (JOURNAL_HEADER_CONTAINS(f->header, n_data))
                if (le64toh(f->header->n_data) * 4ULL > (le64toh(f->header->data_hash_table_size) / sizeof(HashItem)) * 3ULL) {
                        log_ratelimit_full(
                                log_level, JOURNAL_LOG_RATELIMIT,
                                "Data hash table of %s has a fill level at %.1f (%"PRIu64" of %"PRIu64" items, %"PRIu64" file size, %"PRIu64" bytes per hash table item), suggesting rotation.",
                                f->path,
                                100.0 * (double) le64toh(f->header->n_data) / ((double) (le64toh(f->header->data_hash_table_size) / sizeof(HashItem))),
                                le64toh(f->header->n_data),
                                le64toh(f->header->data_hash_table_size) / sizeof(HashItem),
                                (uint64_t) f->last_stat.st_size,
                                f->last_stat.st_size / le64toh(f->header->n_data));
                        return true;
                }

        if (JOURNAL_HEADER_CONTAINS(f->header, n_fields))
                if (le64toh(f->header->n_fields) * 4ULL > (le64toh(f->header->field_hash_table_size) / sizeof(HashItem)) * 3ULL) {
                        log_ratelimit_full(
                                log_level, JOURNAL_LOG_RATELIMIT,
                                "Field hash table of %s has a fill level at %.1f (%"PRIu64" of %"PRIu64" items), suggesting rotation.",
                                f->path,
                                100.0 * (double) le64toh(f->header->n_fields) / ((double) (le64toh(f->header->field_hash_table_size) / sizeof(HashItem))),
                                le64toh(f->header->n_fields),
                                le64toh(f->header->field_hash_table_size) / sizeof(HashItem));
                        return true;
                }

        /* If there are too many hash collisions somebody is most likely playing games with us. Hence, if our
         * longest chain is longer than some threshold, let's suggest rotation. */
        if (JOURNAL_HEADER_CONTAINS(f->header, data_hash_chain_depth) &&
            le64toh(f->header->data_hash_chain_depth) > HASH_CHAIN_DEPTH_MAX) {
                log_ratelimit_full(
                        log_level, JOURNAL_LOG_RATELIMIT,
                        "Data hash table of %s has deepest hash chain of length %" PRIu64 ", suggesting rotation.",
                        f->path, le64toh(f->header->data_hash_chain_depth));
                return true;
        }

        if (JOURNAL_HEADER_CONTAINS(f->header, field_hash_chain_depth) &&
            le64toh(f->header->field_hash_chain_depth) > HASH_CHAIN_DEPTH_MAX) {
                log_ratelimit_full(
                        log_level, JOURNAL_LOG_RATELIMIT,
                        "Field hash table of %s has deepest hash chain of length at %" PRIu64 ", suggesting rotation.",
                        f->path, le64toh(f->header->field_hash_chain_depth));
                return true;
        }

        /* Are the data objects properly indexed by field objects? */
        if (JOURNAL_HEADER_CONTAINS(f->header, n_data) &&
            JOURNAL_HEADER_CONTAINS(f->header, n_fields) &&
            le64toh(f->header->n_data) > 0 &&
            le64toh(f->header->n_fields) == 0) {
                log_ratelimit_full(
                        log_level, JOURNAL_LOG_RATELIMIT,
                        "Data objects of %s are not indexed by field objects, suggesting rotation.",
                        f->path);
                return true;
        }

        if (max_file_usec > 0) {
                usec_t t, h;

                h = le64toh(f->header->head_entry_realtime);
                t = now(CLOCK_REALTIME);

                if (h > 0 && t > h + max_file_usec) {
                        log_ratelimit_full(
                                log_level, JOURNAL_LOG_RATELIMIT,
                                "Oldest entry in %s is older than the configured file retention duration (%s), suggesting rotation.",
                                f->path, FORMAT_TIMESPAN(max_file_usec, USEC_PER_SEC));
                        return true;
                }
        }

        return false;
}

static const char * const journal_object_type_table[] = {
        [OBJECT_UNUSED]           = "unused",
        [OBJECT_DATA]             = "data",
        [OBJECT_FIELD]            = "field",
        [OBJECT_ENTRY]            = "entry",
        [OBJECT_DATA_HASH_TABLE]  = "data hash table",
        [OBJECT_FIELD_HASH_TABLE] = "field hash table",
        [OBJECT_ENTRY_ARRAY]      = "entry array",
        [OBJECT_TAG]              = "tag",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(journal_object_type, ObjectType);
