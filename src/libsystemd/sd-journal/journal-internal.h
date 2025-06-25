/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journal-file.h"
#include "list.h"
#include "forward.h"
#include "time-util.h"

#define JOURNAL_FILES_MAX 7168u

#define JOURNAL_LOG_RATELIMIT ((const RateLimit) { .interval = 60 * USEC_PER_SEC, .burst = 3 })

typedef struct Match Match;
typedef struct Location Location;
typedef struct Directory Directory;

typedef enum MatchType {
        MATCH_DISCRETE,
        MATCH_OR_TERM,
        MATCH_AND_TERM,
} MatchType;

typedef struct Match {
        MatchType type;
        Match *parent;
        LIST_FIELDS(Match, matches);

        /* For concrete matches */
        char *data;
        size_t size;
        uint64_t hash; /* old-style jenkins hash. New-style siphash is different per file, hence won't be cached here */

        /* For terms */
        LIST_HEAD(Match, matches);
} Match;

typedef struct Location {
        LocationType type;

        bool seqnum_set:1;
        bool realtime_set:1;
        bool monotonic_set:1;
        bool xor_hash_set:1;

        uint64_t seqnum;
        sd_id128_t seqnum_id;

        uint64_t realtime;

        uint64_t monotonic;
        sd_id128_t boot_id;

        uint64_t xor_hash;
} Location;

typedef struct Directory {
        sd_journal *journal;
        char *path;
        int wd;
        bool is_root;
        unsigned last_seen_generation;
} Directory;

typedef struct NewestByBootId {
        sd_id128_t boot_id;
        Prioq *prioq; /* JournalFile objects ordered by monotonic timestamp of last update. */
} NewestByBootId;

typedef struct sd_journal {
        int toplevel_fd;

        char *path;
        char *prefix;
        char *namespace;

        OrderedHashmap *files;
        IteratedCache *files_cache;
        MMapCache *mmap;

        /* a bisectable array of NewestByBootId, ordered by boot id. */
        NewestByBootId *newest_by_boot_id;
        size_t n_newest_by_boot_id;

        Location current_location;

        JournalFile *current_file;
        uint64_t current_field;

        Match *level0, *level1, *level2;
        Set *exclude_syslog_identifiers;

        uint64_t origin_id;

        int inotify_fd;
        unsigned current_invalidate_counter, last_invalidate_counter;
        usec_t last_process_usec;
        unsigned generation;

        /* Iterating through unique fields and their data values */
        char *unique_field;
        JournalFile *unique_file;
        uint64_t unique_offset;

        /* Iterating through known fields */
        JournalFile *fields_file;
        uint64_t fields_offset;
        uint64_t fields_hash_table_index;
        char *fields_buffer;

        int flags;

        bool on_network:1;
        bool no_new_files:1;
        bool no_inotify:1;
        bool unique_file_lost:1; /* File we were iterating over got
                                    removed, and there were no more
                                    files, so sd_j_enumerate_unique
                                    will return a value equal to 0. */
        bool fields_file_lost:1;
        bool has_runtime_files:1;
        bool has_persistent_files:1;

        size_t data_threshold;

        Hashmap *directories_by_path;
        Hashmap *directories_by_wd;

        Hashmap *errors;
} sd_journal;

char* journal_make_match_string(sd_journal *j);
void journal_print_header(sd_journal *j);
int journal_get_directories(sd_journal *j, char ***ret);

int journal_add_match_pair(sd_journal *j, const char *field, const char *value);
int journal_add_matchf(sd_journal *j, const char *format, ...) _printf_(2, 3);

#define JOURNAL_FOREACH_DATA_RETVAL(j, data, l, retval)                     \
        for (sd_journal_restart_data(j); ((retval) = sd_journal_enumerate_data((j), &(data), &(l))) > 0; )

/* All errors that we might encounter while extracting a field that are not real errors,
 * but only mean that the field is too large or we don't support the compression. */
static inline bool JOURNAL_ERRNO_IS_UNAVAILABLE_FIELD(int r) {
        return IN_SET(ABS(r),
                      ENOBUFS,          /* Field or decompressed field too large */
                      E2BIG,            /* Field too large for pointer width */
                      EPROTONOSUPPORT); /* Unsupported compression */
}
