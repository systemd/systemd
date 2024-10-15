/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <inttypes.h>
#include <sys/uio.h>

#if HAVE_GCRYPT
#  include <gcrypt.h>
#endif

#include "sd-event.h"
#include "sd-id128.h"

#include "compress.h"
#include "hashmap.h"
#include "journal-def.h"
#include "mmap-cache.h"
#include "sparse-endian.h"
#include "time-util.h"

typedef struct JournalMetrics {
        /* For all these: UINT64_MAX means "pick automatically", and 0 means "no limit enforced" */
        uint64_t max_size;     /* how large journal files grow at max */
        uint64_t min_size;     /* how large journal files grow at least */
        uint64_t max_use;      /* how much disk space to use in total at max, keep_free permitting */
        uint64_t min_use;      /* how much disk space to use in total at least, even if keep_free says not to */
        uint64_t keep_free;    /* how much to keep free on disk */
        uint64_t n_max_files;  /* how many files to keep around at max */
} JournalMetrics;

typedef enum direction {
        DIRECTION_UP,
        DIRECTION_DOWN,
        _DIRECTION_INVALID = -EINVAL,
} direction_t;

typedef enum LocationType {
        /* The first and last entries, resp. */
        LOCATION_HEAD,
        LOCATION_TAIL,

        /* We already read the entry we currently point to, and the
         * next one to read should probably not be this one again. */
        LOCATION_DISCRETE,

        /* We should seek to the precise location specified, and
         * return it, as we haven't read it yet. */
        LOCATION_SEEK,
} LocationType;

typedef enum OfflineState {
        OFFLINE_JOINED,
        OFFLINE_SYNCING,
        OFFLINE_OFFLINING,
        OFFLINE_CANCEL,
        OFFLINE_AGAIN_FROM_SYNCING,
        OFFLINE_AGAIN_FROM_OFFLINING,
        OFFLINE_DONE,
} OfflineState;

typedef struct JournalFile {
        int fd;
        MMapFileDescriptor *cache_fd;

        mode_t mode;

        int open_flags;
        bool close_fd:1;
        bool archive:1;
        bool strict_order:1;

        direction_t last_direction;
        LocationType location_type;
        uint64_t last_n_entries;

        char *path;
        struct stat last_stat;
        usec_t last_stat_usec;

        Header *header;
        HashItem *data_hash_table;
        HashItem *field_hash_table;

        uint64_t current_offset;
        uint64_t current_seqnum;
        uint64_t current_realtime;
        uint64_t current_monotonic;
        sd_id128_t current_boot_id;
        uint64_t current_xor_hash;

        JournalMetrics metrics;

        sd_event_source *post_change_timer;
        usec_t post_change_timer_period;

        OrderedHashmap *chain_cache;

        pthread_t offline_thread;
        volatile OfflineState offline_state;

        unsigned last_seen_generation;

        uint64_t compress_threshold_bytes;
#if HAVE_COMPRESSION
        void *compress_buffer;
#endif

#if HAVE_GCRYPT
        gcry_md_hd_t hmac;
        bool hmac_running;

        FSSHeader *fss_file;
        size_t fss_file_size;

        uint64_t fss_start_usec;
        uint64_t fss_interval_usec;

        void *fsprg_state;
        size_t fsprg_state_size;

        void *fsprg_seed;
        size_t fsprg_seed_size;
#endif

        /* When we insert this file into the per-boot priority queue 'newest_by_boot_id' in sd_journal, then by these keys */
        sd_id128_t newest_boot_id;
        sd_id128_t newest_machine_id;
        uint64_t newest_monotonic_usec;
        uint64_t newest_realtime_usec;
        unsigned newest_boot_id_prioq_idx;
        uint64_t newest_entry_offset;
        uint8_t newest_state;
} JournalFile;

typedef enum JournalFileFlags {
        JOURNAL_COMPRESS        = 1 << 0,
        JOURNAL_SEAL            = 1 << 1,
        JOURNAL_STRICT_ORDER    = 1 << 2,
        _JOURNAL_FILE_FLAGS_MAX = JOURNAL_COMPRESS|JOURNAL_SEAL|JOURNAL_STRICT_ORDER,
} JournalFileFlags;

typedef struct {
        uint64_t object_offset;
        uint64_t hash;
} EntryItem;

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
                JournalFile **ret);

int journal_file_set_offline_thread_join(JournalFile *f);
JournalFile* journal_file_close(JournalFile *j);
int journal_file_fstat(JournalFile *f);
DEFINE_TRIVIAL_CLEANUP_FUNC(JournalFile*, journal_file_close);

#define ALIGN64(x) (((x) + 7ULL) & ~7ULL)
#define VALID64(x) (((x) & 7ULL) == 0ULL)

/* Use six characters to cover the offsets common in smallish journal
 * files without adding too many zeros. */
#define OFSfmt "%06"PRIx64

static inline bool VALID_REALTIME(uint64_t u) {
        /* This considers timestamps until the year 3112 valid. That should be plenty room... */
        return u > 0 && u < (1ULL << 55);
}

static inline bool VALID_MONOTONIC(uint64_t u) {
        /* This considers timestamps until 1142 years of runtime valid. */
        return u < (1ULL << 55);
}

static inline bool VALID_EPOCH(uint64_t u) {
        /* This allows changing the key for 1142 years, every usec. */
        return u < (1ULL << 55);
}

#define JOURNAL_HEADER_CONTAINS(h, field) \
        (le64toh((h)->header_size) >= offsetof(Header, field) + sizeof((h)->field))

#define JOURNAL_HEADER_SEALED(h) \
        FLAGS_SET(le32toh((h)->compatible_flags), HEADER_COMPATIBLE_SEALED)

#define JOURNAL_HEADER_SEALED_CONTINUOUS(h) \
        FLAGS_SET(le32toh((h)->compatible_flags), HEADER_COMPATIBLE_SEALED_CONTINUOUS)

#define JOURNAL_HEADER_TAIL_ENTRY_BOOT_ID(h) \
        FLAGS_SET(le32toh((h)->compatible_flags), HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID)

#define JOURNAL_HEADER_COMPRESSED_XZ(h) \
        FLAGS_SET(le32toh((h)->incompatible_flags), HEADER_INCOMPATIBLE_COMPRESSED_XZ)

#define JOURNAL_HEADER_COMPRESSED_LZ4(h) \
        FLAGS_SET(le32toh((h)->incompatible_flags), HEADER_INCOMPATIBLE_COMPRESSED_LZ4)

#define JOURNAL_HEADER_COMPRESSED_ZSTD(h) \
        FLAGS_SET(le32toh((h)->incompatible_flags), HEADER_INCOMPATIBLE_COMPRESSED_ZSTD)

#define JOURNAL_HEADER_KEYED_HASH(h) \
        FLAGS_SET(le32toh((h)->incompatible_flags), HEADER_INCOMPATIBLE_KEYED_HASH)

#define JOURNAL_HEADER_COMPACT(h) \
        FLAGS_SET(le32toh((h)->incompatible_flags), HEADER_INCOMPATIBLE_COMPACT)

int journal_file_move_to_object(JournalFile *f, ObjectType type, uint64_t offset, Object **ret);
int journal_file_pin_object(JournalFile *f, Object *o);
int journal_file_read_object_header(JournalFile *f, ObjectType type, uint64_t offset, Object *ret);

int journal_file_tail_end_by_pread(JournalFile *f, uint64_t *ret_offset);
int journal_file_tail_end_by_mmap(JournalFile *f, uint64_t *ret_offset);

static inline uint64_t journal_file_entry_item_object_offset(JournalFile *f, Object *o, size_t i) {
        assert(f);
        assert(o);
        return JOURNAL_HEADER_COMPACT(f->header) ? le32toh(o->entry.items.compact[i].object_offset) :
                                                   le64toh(o->entry.items.regular[i].object_offset);
}

static inline size_t journal_file_entry_item_size(JournalFile *f) {
        assert(f);
        return JOURNAL_HEADER_COMPACT(f->header) ? sizeof_field(Object, entry.items.compact[0]) :
                                                   sizeof_field(Object, entry.items.regular[0]);
}

uint64_t journal_file_entry_n_items(JournalFile *f, Object *o) _pure_;

int journal_file_data_payload(
                JournalFile *f,
                Object *o,
                uint64_t offset,
                const char *field,
                size_t field_length,
                size_t data_threshold,
                void **ret_data,
                size_t *ret_size);

static inline size_t journal_file_data_payload_offset(JournalFile *f) {
        return JOURNAL_HEADER_COMPACT(f->header)
                        ? offsetof(Object, data.compact.payload)
                        : offsetof(Object, data.regular.payload);
}

static inline uint8_t* journal_file_data_payload_field(JournalFile *f, Object *o) {
        return JOURNAL_HEADER_COMPACT(f->header) ? o->data.compact.payload : o->data.regular.payload;
}

uint64_t journal_file_entry_array_n_items(JournalFile *f, Object *o) _pure_;

static inline uint64_t journal_file_entry_array_item(JournalFile *f, Object *o, size_t i) {
        assert(f);
        assert(o);
        return JOURNAL_HEADER_COMPACT(f->header) ? le32toh(o->entry_array.items.compact[i]) :
                                                   le64toh(o->entry_array.items.regular[i]);
}

static inline size_t journal_file_entry_array_item_size(JournalFile *f) {
        assert(f);
        return JOURNAL_HEADER_COMPACT(f->header) ? sizeof(le32_t) : sizeof(le64_t);
}

uint64_t journal_file_hash_table_n_items(Object *o) _pure_;

int journal_file_append_object(JournalFile *f, ObjectType type, uint64_t size, Object **ret_object, uint64_t *ret_offset);
int journal_file_append_entry(
                JournalFile *f,
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const struct iovec iovec[],
                size_t n_iovec,
                uint64_t *seqnum,
                sd_id128_t *seqnum_id,
                Object **ret_object,
                uint64_t *ret_offset);

int journal_file_find_data_object(JournalFile *f, const void *data, uint64_t size, Object **ret_object, uint64_t *ret_offset);
int journal_file_find_data_object_with_hash(JournalFile *f, const void *data, uint64_t size, uint64_t hash, Object **ret_object, uint64_t *ret_offset);

int journal_file_find_field_object(JournalFile *f, const void *field, uint64_t size, Object **ret_object, uint64_t *ret_offset);
int journal_file_find_field_object_with_hash(JournalFile *f, const void *field, uint64_t size, uint64_t hash, Object **ret_object, uint64_t *ret_offset);

void journal_file_reset_location(JournalFile *f);
void journal_file_save_location(JournalFile *f, Object *o, uint64_t offset);
int journal_file_next_entry(JournalFile *f, uint64_t p, direction_t direction, Object **ret_object, uint64_t *ret_offset);

int journal_file_move_to_entry_by_offset(JournalFile *f, uint64_t p, direction_t direction, Object **ret_object, uint64_t *ret_offset);
int journal_file_move_to_entry_by_seqnum(JournalFile *f, uint64_t seqnum, direction_t direction, Object **ret_object, uint64_t *ret_offset);
int journal_file_move_to_entry_by_realtime(JournalFile *f, uint64_t realtime, direction_t direction, Object **ret_object, uint64_t *ret_offset);
int journal_file_move_to_entry_by_monotonic(JournalFile *f, sd_id128_t boot_id, uint64_t monotonic, direction_t direction, Object **ret_object, uint64_t *ret_offset);

int journal_file_move_to_entry_for_data(JournalFile *f, Object *d, direction_t direction, Object **ret_object, uint64_t *ret_offset);

int journal_file_move_to_entry_by_offset_for_data(JournalFile *f, Object *d, uint64_t p, direction_t direction, Object **ret_object, uint64_t *ret_offset);
int journal_file_move_to_entry_by_seqnum_for_data(JournalFile *f, Object *d, uint64_t seqnum, direction_t direction, Object **ret_object, uint64_t *ret_offset);
int journal_file_move_to_entry_by_realtime_for_data(JournalFile *f, Object *d, uint64_t realtime, direction_t direction, Object **ret_object, uint64_t *ret_offset);
int journal_file_move_to_entry_by_monotonic_for_data(JournalFile *f, Object *d, sd_id128_t boot_id, uint64_t monotonic, direction_t direction, Object **ret_object, uint64_t *ret_offset);

int journal_file_copy_entry(JournalFile *from, JournalFile *to, Object *o, uint64_t p, uint64_t *seqnum, sd_id128_t *seqnum_id);

void journal_file_dump(JournalFile *f);
void journal_file_print_header(JournalFile *f);

int journal_file_archive(JournalFile *f, char **ret_previous_path);
int journal_file_parse_uid_from_filename(const char *path, uid_t *uid);

int journal_file_dispose(int dir_fd, const char *fname);

void journal_file_post_change(JournalFile *f);
int journal_file_enable_post_change_timer(JournalFile *f, sd_event *e, usec_t t);

void journal_reset_metrics(JournalMetrics *m);

int journal_file_get_cutoff_realtime_usec(JournalFile *f, usec_t *ret_from, usec_t *ret_to);
int journal_file_get_cutoff_monotonic_usec(JournalFile *f, sd_id128_t boot, usec_t *ret_from, usec_t *ret_to);

bool journal_file_rotate_suggested(JournalFile *f, usec_t max_file_usec, int log_level);

int journal_file_map_data_hash_table(JournalFile *f);
int journal_file_map_field_hash_table(JournalFile *f);

static inline Compression JOURNAL_FILE_COMPRESSION(JournalFile *f) {
        assert(f);

        if (JOURNAL_HEADER_COMPRESSED_XZ(f->header))
                return COMPRESSION_XZ;
        if (JOURNAL_HEADER_COMPRESSED_LZ4(f->header))
                return COMPRESSION_LZ4;
        if (JOURNAL_HEADER_COMPRESSED_ZSTD(f->header))
                return COMPRESSION_ZSTD;
        return COMPRESSION_NONE;
}

uint64_t journal_file_hash_data(JournalFile *f, const void *data, size_t sz);

bool journal_field_valid(const char *p, size_t l, bool allow_protected);

const char* journal_object_type_to_string(ObjectType type) _const_;

static inline Compression COMPRESSION_FROM_OBJECT(const Object *o) {
        assert(o);

        switch (o->object.flags & _OBJECT_COMPRESSED_MASK) {
        case 0:
                return COMPRESSION_NONE;
        case OBJECT_COMPRESSED_XZ:
                return COMPRESSION_XZ;
        case OBJECT_COMPRESSED_LZ4:
                return COMPRESSION_LZ4;
        case OBJECT_COMPRESSED_ZSTD:
                return COMPRESSION_ZSTD;
        default:
                return _COMPRESSION_INVALID;
        }
}

static inline uint8_t COMPRESSION_TO_OBJECT_FLAG(Compression c) {
        switch (c) {
        case COMPRESSION_XZ:
                return OBJECT_COMPRESSED_XZ;
        case COMPRESSION_LZ4:
                return OBJECT_COMPRESSED_LZ4;
        case COMPRESSION_ZSTD:
                return OBJECT_COMPRESSED_ZSTD;
        default:
                return 0;
        }
}

static inline uint32_t COMPRESSION_TO_HEADER_INCOMPATIBLE_FLAG(Compression c) {
        switch (c) {
        case COMPRESSION_XZ:
                return HEADER_INCOMPATIBLE_COMPRESSED_XZ;
        case COMPRESSION_LZ4:
                return HEADER_INCOMPATIBLE_COMPRESSED_LZ4;
        case COMPRESSION_ZSTD:
                return HEADER_INCOMPATIBLE_COMPRESSED_ZSTD;
        default:
                return 0;
        }
}

static inline bool journal_file_writable(JournalFile *f) {
        assert(f);
        return (f->open_flags & O_ACCMODE) != O_RDONLY;
}
