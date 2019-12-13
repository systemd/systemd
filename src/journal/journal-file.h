/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>
#include <sys/uio.h>

#if HAVE_GCRYPT
#  include <gcrypt.h>
#endif

#include "sd-event.h"
#include "sd-id128.h"

#include "hashmap.h"
#include "journal-def.h"
#include "mmap-cache.h"
#include "sparse-endian.h"
#include "time-util.h"

typedef struct JournalMetrics {
        /* For all these: -1 means "pick automatically", and 0 means "no limit enforced" */
        uint64_t max_size;     /* how large journal files grow at max */
        uint64_t min_size;     /* how large journal files grow at least */
        uint64_t max_use;      /* how much disk space to use in total at max, keep_free permitting */
        uint64_t min_use;      /* how much disk space to use in total at least, even if keep_free says not to */
        uint64_t keep_free;    /* how much to keep free on disk */
        uint64_t n_max_files;  /* how many files to keep around at max */
} JournalMetrics;

typedef enum direction {
        DIRECTION_UP,
        DIRECTION_DOWN
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
        LOCATION_SEEK
} LocationType;

typedef enum OfflineState {
        OFFLINE_JOINED,
        OFFLINE_SYNCING,
        OFFLINE_OFFLINING,
        OFFLINE_CANCEL,
        OFFLINE_AGAIN_FROM_SYNCING,
        OFFLINE_AGAIN_FROM_OFFLINING,
        OFFLINE_DONE
} OfflineState;

typedef struct JournalFile {
        int fd;
        MMapFileDescriptor *cache_fd;

        mode_t mode;

        int flags;
        int prot;
        bool writable:1;
        bool compress_xz:1;
        bool compress_lz4:1;
        bool seal:1;
        bool defrag_on_close:1;
        bool close_fd:1;
        bool archive:1;

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
        MMapCache *mmap;

        sd_event_source *post_change_timer;
        usec_t post_change_timer_period;

        OrderedHashmap *chain_cache;

        pthread_t offline_thread;
        volatile OfflineState offline_state;

        unsigned last_seen_generation;

        uint64_t compress_threshold_bytes;
#if HAVE_XZ || HAVE_LZ4
        void *compress_buffer;
        size_t compress_buffer_size;
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
} JournalFile;

int journal_file_open(
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
                JournalFile *template,
                JournalFile **ret);

int journal_file_set_offline(JournalFile *f, bool wait);
bool journal_file_is_offlining(JournalFile *f);
JournalFile* journal_file_close(JournalFile *j);
DEFINE_TRIVIAL_CLEANUP_FUNC(JournalFile*, journal_file_close);

int journal_file_open_reliably(
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                JournalFile *template,
                JournalFile **ret);

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
        (!!(le32toh((h)->compatible_flags) & HEADER_COMPATIBLE_SEALED))

#define JOURNAL_HEADER_COMPRESSED_XZ(h) \
        (!!(le32toh((h)->incompatible_flags) & HEADER_INCOMPATIBLE_COMPRESSED_XZ))

#define JOURNAL_HEADER_COMPRESSED_LZ4(h) \
        (!!(le32toh((h)->incompatible_flags) & HEADER_INCOMPATIBLE_COMPRESSED_LZ4))

int journal_file_move_to_object(JournalFile *f, ObjectType type, uint64_t offset, Object **ret);

uint64_t journal_file_entry_n_items(Object *o) _pure_;
uint64_t journal_file_entry_array_n_items(Object *o) _pure_;
uint64_t journal_file_hash_table_n_items(Object *o) _pure_;

int journal_file_append_object(JournalFile *f, ObjectType type, uint64_t size, Object **ret, uint64_t *offset);
int journal_file_append_entry(
                JournalFile *f,
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const struct iovec iovec[], unsigned n_iovec,
                uint64_t *seqno,
                Object **ret,
                uint64_t *offset);

int journal_file_find_data_object(JournalFile *f, const void *data, uint64_t size, Object **ret, uint64_t *offset);
int journal_file_find_data_object_with_hash(JournalFile *f, const void *data, uint64_t size, uint64_t hash, Object **ret, uint64_t *offset);

int journal_file_find_field_object(JournalFile *f, const void *field, uint64_t size, Object **ret, uint64_t *offset);
int journal_file_find_field_object_with_hash(JournalFile *f, const void *field, uint64_t size, uint64_t hash, Object **ret, uint64_t *offset);

void journal_file_reset_location(JournalFile *f);
void journal_file_save_location(JournalFile *f, Object *o, uint64_t offset);
int journal_file_compare_locations(JournalFile *af, JournalFile *bf);
int journal_file_next_entry(JournalFile *f, uint64_t p, direction_t direction, Object **ret, uint64_t *offset);

int journal_file_next_entry_for_data(JournalFile *f, Object *o, uint64_t p, uint64_t data_offset, direction_t direction, Object **ret, uint64_t *offset);

int journal_file_move_to_entry_by_seqnum(JournalFile *f, uint64_t seqnum, direction_t direction, Object **ret, uint64_t *offset);
int journal_file_move_to_entry_by_realtime(JournalFile *f, uint64_t realtime, direction_t direction, Object **ret, uint64_t *offset);
int journal_file_move_to_entry_by_monotonic(JournalFile *f, sd_id128_t boot_id, uint64_t monotonic, direction_t direction, Object **ret, uint64_t *offset);

int journal_file_move_to_entry_by_offset_for_data(JournalFile *f, uint64_t data_offset, uint64_t p, direction_t direction, Object **ret, uint64_t *offset);
int journal_file_move_to_entry_by_seqnum_for_data(JournalFile *f, uint64_t data_offset, uint64_t seqnum, direction_t direction, Object **ret, uint64_t *offset);
int journal_file_move_to_entry_by_realtime_for_data(JournalFile *f, uint64_t data_offset, uint64_t realtime, direction_t direction, Object **ret, uint64_t *offset);
int journal_file_move_to_entry_by_monotonic_for_data(JournalFile *f, uint64_t data_offset, sd_id128_t boot_id, uint64_t monotonic, direction_t direction, Object **ret, uint64_t *offset);

int journal_file_copy_entry(JournalFile *from, JournalFile *to, Object *o, uint64_t p);

void journal_file_dump(JournalFile *f);
void journal_file_print_header(JournalFile *f);

int journal_file_archive(JournalFile *f);
JournalFile* journal_initiate_close(JournalFile *f, Set *deferred_closes);
int journal_file_rotate(JournalFile **f, bool compress, uint64_t compress_threshold_bytes, bool seal, Set *deferred_closes);

int journal_file_dispose(int dir_fd, const char *fname);

void journal_file_post_change(JournalFile *f);
int journal_file_enable_post_change_timer(JournalFile *f, sd_event *e, usec_t t);

void journal_reset_metrics(JournalMetrics *m);
void journal_default_metrics(JournalMetrics *m, int fd);

int journal_file_get_cutoff_realtime_usec(JournalFile *f, usec_t *from, usec_t *to);
int journal_file_get_cutoff_monotonic_usec(JournalFile *f, sd_id128_t boot, usec_t *from, usec_t *to);

bool journal_file_rotate_suggested(JournalFile *f, usec_t max_file_usec);

int journal_file_map_data_hash_table(JournalFile *f);
int journal_file_map_field_hash_table(JournalFile *f);

static inline bool JOURNAL_FILE_COMPRESS(JournalFile *f) {
        assert(f);
        return f->compress_xz || f->compress_lz4;
}
