/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <malloc.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-id128.h"
#include "sd-journal.h"

#include "alloc-util.h"
#include "chattr-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hash-funcs.h"
#include "hashmap.h"
#include "io-util.h"
#include "iovec-util.h"
#include "journal-file-util.h"
#include "journal-segmented.h"
#include "log.h"
#include "main-func.h"
#include "memory-util.h"
#include "mkdir.h"
#include "mmap-cache.h"
#include "options.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "siphash24.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "verbs.h"

COMMAND(
        "test-journal-benchmark\0",
        "Compare journal file formats by the I/O they generate and by how fast they can be read.",
);

/* Replays the same entries into one set of journal files per format, the way journald writes them, then runs
 * the same queries against each set. Writeback is emulated in log time: pages that differ from a copy taken
 * at the previous writeback count as written. */

#define ARENA_CHUNK_SIZE (16U * U64_MB)
#define TRACKER_MAP_SIZE (8U * U64_GB)
#define TRACKER_BLOCK_SIZE (256U * U64_KB)

typedef struct Format {
        const char *name;
        const char *compact;
        const char *segmented;
        bool nocow;
} Format;

static const Format formats[] = {
        { "classic",     "0", "0", true  },
        { "compact",     "1", "0", true  },
        { "segmented", "1", "1", false },
};

typedef struct Entry {
        dual_timestamp ts;
        sd_id128_t boot_id;
        size_t first_iovec;
        size_t n_iovec;
        int priority;
} Entry;

typedef struct Workload {
        Entry *entries;
        size_t n_entries;
        struct iovec *iovecs;
        size_t n_iovecs;
        uint64_t payload_bytes;

        uint8_t *arena;
        size_t arena_used;

        /* Parameters for the read tests, picked from the data */
        char *match_rare;
        char *match_common;
        char *match_boot;
        char *match_priority;
        char *match_invocation;
        char *match_message;
        char *match_timestamp;
        char **match_many;
        uint64_t seek_realtime;
} Workload;

typedef struct WriteResult {
        uint64_t n_entries;
        uint64_t payload_bytes;
        uint64_t n_files;
        uint64_t file_bytes;
        uint64_t disk_bytes;
        uint64_t n_extents;
        uint64_t n_writebacks;
        uint64_t n_syncs;
        uint64_t n_rotations;
        uint64_t dirty_pages;
        uint64_t dirty_ranges;
        uint64_t max_dirty_pages;
        uint64_t append_cpu_nsec;
        uint64_t write_usec;
        uint64_t tracker_usec;
        uint64_t io_write_bytes;
        uint64_t io_wchar;
        uint64_t io_syscw;
        uint64_t heap_bytes;
        uint64_t append_p50_nsec;
        uint64_t append_p99_nsec;
        uint64_t append_max_nsec;
        uint64_t n_indexes;
} WriteResult;

typedef struct ReadResult {
        uint64_t n_results;
        uint64_t digest;
        uint64_t cold_usec;
        uint64_t warm_usec;
        uint64_t cold_pages;
        uint64_t cold_read_bytes;
        uint64_t heap_bytes;
} ReadResult;

typedef struct FollowResult {
        uint64_t n_entries;
        uint64_t n_wakeups;
        uint64_t n_results;
        uint64_t cpu_nsec;
        uint64_t wall_usec;
} FollowResult;

#define N_READ_TESTS_MAX 24

typedef struct Report {
        WriteResult write;
        ReadResult read[N_READ_TESTS_MAX];
        FollowResult follow[2];
} Report;

typedef struct Tracker {
        int fd;
        uint8_t *map;
        uint8_t *shadow;
} Tracker;

static char *arg_input = NULL;
static char *arg_output = NULL;
static char **arg_formats = NULL;
static uint64_t arg_entries = 100000;
static uint64_t arg_max_size = 128 * U64_MB;
static usec_t arg_writeback_usec = 30 * USEC_PER_SEC;
static usec_t arg_sync_usec = 5 * USEC_PER_MINUTE;
static bool arg_compress = true;
static bool arg_keep = false;
static bool arg_write = true;
static bool arg_read = true;
static bool arg_follow = true;
static bool arg_real_writeback = false;
static int arg_nocow = -1;
static uint64_t arg_seed = 0x6a6f75726e616cULL;
static uint64_t arg_follow_rate = 1000;

STATIC_DESTRUCTOR_REGISTER(arg_input, freep);
STATIC_DESTRUCTOR_REGISTER(arg_output, freep);
STATIC_DESTRUCTOR_REGISTER(arg_formats, strv_freep);

static const uint8_t digest_key[16] = {
        0x62, 0x65, 0x6e, 0x63, 0x68, 0x6d, 0x61, 0x72, 0x6b, 0x2d, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74,
};

/* Workload */

static void* workload_alloc(Workload *w, size_t size) {
        assert(w);
        assert(size <= ARENA_CHUNK_SIZE);

        /* Chunks are never moved or freed, so the iovecs pointing into them stay valid. */
        if (!w->arena || w->arena_used + size > ARENA_CHUNK_SIZE) {
                w->arena = ASSERT_NOT_NULL(malloc(ARENA_CHUNK_SIZE));
                w->arena_used = 0;
        }

        void *p = w->arena + w->arena_used;
        w->arena_used += size;
        return p;
}

static void workload_add_field(Workload *w, const void *data, size_t size) {
        void *p;

        assert(w);
        assert(data);

        if (size > ARENA_CHUNK_SIZE)
                p = ASSERT_NOT_NULL(malloc(size));
        else
                p = workload_alloc(w, size);
        memcpy(p, data, size);

        ASSERT_NOT_NULL(GREEDY_REALLOC(w->iovecs, w->n_iovecs + 1));
        w->iovecs[w->n_iovecs++] = IOVEC_MAKE(p, size);
        w->payload_bytes += size;

        Entry *e = w->entries + w->n_entries;
        e->n_iovec++;

        if (size == STRLEN("PRIORITY=") + 1 && memcmp(data, "PRIORITY=", STRLEN("PRIORITY=")) == 0) {
                char c = ((const char*) data)[size - 1];
                if (c >= '0' && c <= '7')
                        e->priority = c - '0';
        }
}

static void workload_add_fieldf(Workload *w, const char *format, ...) _printf_(2, 3);
static void workload_add_fieldf(Workload *w, const char *format, ...) {
        _cleanup_free_ char *s = NULL;
        va_list ap;

        va_start(ap, format);
        ASSERT_OK_ERRNO(vasprintf(&s, format, ap));
        va_end(ap);

        workload_add_field(w, s, strlen(s));
}

static void workload_begin_entry(Workload *w, usec_t realtime, usec_t monotonic, sd_id128_t boot_id) {
        assert(w);

        ASSERT_NOT_NULL(GREEDY_REALLOC(w->entries, w->n_entries + 1));

        /* journald rotates when time goes backwards, and entries read from several source files are not
         * strictly ordered by realtime. Clamp them to avoid spurious rotations. */
        if (w->n_entries > 0) {
                const Entry *prev = w->entries + w->n_entries - 1;

                realtime = MAX(realtime, prev->ts.realtime);
                if (sd_id128_equal(prev->boot_id, boot_id))
                        monotonic = MAX(monotonic, prev->ts.monotonic);
        }

        w->entries[w->n_entries] = (Entry) {
                .ts.realtime = realtime,
                .ts.monotonic = monotonic,
                .boot_id = boot_id,
                .first_iovec = w->n_iovecs,
                .priority = -1,
        };
}

static void workload_end_entry(Workload *w) {
        assert(w);

        if (w->entries[w->n_entries].n_iovec > 0)
                w->n_entries++;
}

static int workload_load_journal(Workload *w) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        struct stat st;
        int r;

        assert(w);

        if (stat(arg_input, &st) < 0)
                return log_error_errno(errno, "Failed to stat %s: %m", arg_input);

        if (S_ISDIR(st.st_mode))
                r = sd_journal_open_directory(&j, arg_input, 0);
        else
                r = sd_journal_open_files(&j, (const char*[]) { arg_input, NULL }, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to open %s: %m", arg_input);

        ASSERT_OK(sd_journal_set_data_threshold(j, 0));

        if (arg_entries > 0) {
                ASSERT_OK(sd_journal_seek_tail(j));
                r = sd_journal_previous_skip(j, arg_entries);
        } else {
                ASSERT_OK(sd_journal_seek_head(j));
                r = sd_journal_next(j);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to seek in %s: %m", arg_input);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "No entries in %s.", arg_input);

        do {
                uint64_t realtime, monotonic;
                sd_id128_t boot_id;
                const void *data;
                size_t size;

                ASSERT_OK(sd_journal_get_realtime_usec(j, &realtime));
                ASSERT_OK(sd_journal_get_monotonic_usec(j, &monotonic, &boot_id));

                workload_begin_entry(w, realtime, monotonic, boot_id);
                SD_JOURNAL_FOREACH_DATA(j, data, size)
                        workload_add_field(w, data, size);
                workload_end_entry(w);

                r = sd_journal_next(j);
                if (r < 0)
                        return log_error_errno(r, "Failed to iterate %s: %m", arg_input);
        } while (r > 0);

        return 0;
}

static uint64_t prng(uint64_t *state) {
        /* xorshift64*. Not random_u64(), so that every run generates the same workload. */
        *state ^= *state >> 12;
        *state ^= *state << 25;
        *state ^= *state >> 27;
        return *state * UINT64_C(2685821657736338717);
}

static void workload_generate(Workload *w) {
        enum { N_UNITS = 48, N_TEMPLATES = 256 };
        static const char * const transports[] = { "journal", "stdout", "syslog" };
        uint64_t state = arg_seed, pids[N_UNITS], invocations[N_UNITS];
        usec_t realtime = 1750000000 * USEC_PER_SEC, monotonic = 10 * USEC_PER_SEC;
        sd_id128_t boot_id = SD_ID128_MAKE(5f,6e,7a,98,5c,1d,4e,22,9a,3f,0b,11,22,33,44,55);
        size_t unit = 0;

        assert(w);

        for (size_t i = 0; i < N_UNITS; i++) {
                pids[i] = 300 + prng(&state) % 30000;
                invocations[i] = prng(&state);
        }

        for (uint64_t n = 0; n < arg_entries; n++) {
                uint64_t x = prng(&state), gap;

                /* Bursts from one unit with short gaps, and a long pause now and then */
                if (x % 100 < 70)
                        gap = x % 2000;
                else if (x % 100 < 97)
                        gap = x % USEC_PER_SEC;
                else
                        gap = x % (3 * USEC_PER_MINUTE);

                if (x % 8 == 0)
                        unit = prng(&state) % N_UNITS;

                if (prng(&state) % 5000 == 0) {
                        pids[unit] = 300 + prng(&state) % 30000;
                        invocations[unit] = prng(&state);
                }

                realtime += gap;
                monotonic += gap;

                uint64_t template = prng(&state) % N_TEMPLATES;
                bool unique = prng(&state) % 4 == 0;

                workload_begin_entry(w, realtime, monotonic, boot_id);
                if (unique)
                        workload_add_fieldf(w, "MESSAGE=Request %" PRIu64 " for client %" PRIu64 " took %" PRIu64 "ms (template %" PRIu64 ")",
                                            prng(&state) % 1000000, prng(&state) % 5000, prng(&state) % 900, template);
                else
                        workload_add_fieldf(w, "MESSAGE=Periodic status report of worker %" PRIu64 ": everything is fine", template);
                workload_add_fieldf(w, "PRIORITY=%" PRIu64, template % 16 == 0 ? UINT64_C(3) : template % 5 == 0 ? UINT64_C(4) : UINT64_C(6));
                workload_add_fieldf(w, "SYSLOG_FACILITY=3");
                workload_add_fieldf(w, "SYSLOG_IDENTIFIER=service%zu", unit);
                workload_add_fieldf(w, "TID=%" PRIu64, pids[unit] + template % 4);
                workload_add_fieldf(w, "CODE_FILE=src/service%zu/worker.c", unit % 7);
                workload_add_fieldf(w, "CODE_LINE=%" PRIu64, 100 + template);
                workload_add_fieldf(w, "CODE_FUNC=worker_dispatch_%" PRIu64, template % 32);
                workload_add_fieldf(w, "_TRANSPORT=%s", transports[unit % ELEMENTSOF(transports)]);
                workload_add_fieldf(w, "_PID=%" PRIu64, pids[unit]);
                workload_add_fieldf(w, "_UID=%zu", unit % 5 == 0 ? (size_t) 1000 : (size_t) 0);
                workload_add_fieldf(w, "_GID=%zu", unit % 5 == 0 ? (size_t) 1000 : (size_t) 0);
                workload_add_fieldf(w, "_COMM=service%zu", unit);
                workload_add_fieldf(w, "_EXE=/usr/lib/services/service%zu", unit);
                workload_add_fieldf(w, "_CMDLINE=/usr/lib/services/service%zu --worker --instance=%zu", unit, unit);
                workload_add_fieldf(w, "_CAP_EFFECTIVE=%s", unit % 5 == 0 ? "0" : "1ffffffffff");
                workload_add_fieldf(w, "_SELINUX_CONTEXT=unconfined");
                workload_add_fieldf(w, "_SYSTEMD_CGROUP=/system.slice/service%zu.service", unit);
                workload_add_fieldf(w, "_SYSTEMD_UNIT=service%zu.service", unit);
                workload_add_fieldf(w, "_SYSTEMD_SLICE=system.slice");
                workload_add_fieldf(w, "_SYSTEMD_INVOCATION_ID=%016" PRIx64 "%016" PRIx64, invocations[unit], invocations[unit] * 31);
                workload_add_fieldf(w, "_SOURCE_REALTIME_TIMESTAMP=%" PRIu64, realtime - 17);
                workload_add_fieldf(w, "_BOOT_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(boot_id));
                workload_add_fieldf(w, "_MACHINE_ID=0123456789abcdef0123456789abcdef");
                workload_add_fieldf(w, "_HOSTNAME=benchmark");
                workload_add_fieldf(w, "_RUNTIME_SCOPE=system");
                workload_end_entry(w);
        }
}

static void count_value(Hashmap **h, const struct iovec *iovec) {
        _cleanup_free_ char *s = NULL;
        _cleanup_free_ uint64_t *n = NULL;
        uint64_t *c;

        assert(h);
        assert(iovec);

        if (memchr(iovec->iov_base, 0, iovec->iov_len))
                return;

        s = ASSERT_NOT_NULL(strndup(iovec->iov_base, iovec->iov_len));

        c = hashmap_get(*h, s);
        if (c) {
                (*c)++;
                return;
        }

        n = ASSERT_NOT_NULL(new(uint64_t, 1));
        *n = 1;
        ASSERT_OK(hashmap_ensure_put(h, &string_hash_ops_free_free, s, n));
        TAKE_PTR(s);
        TAKE_PTR(n);
}

static char* pick_value(Hashmap *h, uint64_t target) {
        const char *value, *best = NULL;
        uint64_t *c, best_count = 0;

        /* Returns the value whose count is closest to target. Ties are broken by name, since the hashmap
         * order differs between runs. */

        HASHMAP_FOREACH_KEY(c, value, h) {
                uint64_t a = *c > target ? *c - target : target - *c,
                         b = best_count > target ? best_count - target : target - best_count;

                if (!best || a < b || (a == b && strcmp(value, best) < 0)) {
                        best = value;
                        best_count = *c;
                }
        }

        return best ? ASSERT_NOT_NULL(strdup(best)) : NULL;
}

static void workload_pick_parameters(Workload *w) {
        _cleanup_hashmap_free_ Hashmap *units = NULL, *boots = NULL, *priorities = NULL, *invocations = NULL, *messages = NULL;

        assert(w);

        FOREACH_ARRAY(i, w->iovecs, w->n_iovecs) {
                const char *p = i->iov_base;
                size_t l = i->iov_len;

                if (memory_startswith(p, l, "_SYSTEMD_UNIT="))
                        count_value(&units, i);
                else if (memory_startswith(p, l, "_BOOT_ID="))
                        count_value(&boots, i);
                else if (memory_startswith(p, l, "PRIORITY="))
                        count_value(&priorities, i);
                else if (memory_startswith(p, l, "_SYSTEMD_INVOCATION_ID="))
                        count_value(&invocations, i);
                else if (memory_startswith(p, l, "MESSAGE=") && l < 256)
                        count_value(&messages, i);
        }

        w->match_common = pick_value(units, UINT64_MAX);
        w->match_rare = pick_value(units, MAX(w->n_entries / 1000, UINT64_C(10)));
        w->match_boot = pick_value(boots, UINT64_MAX);
        w->match_priority = pick_value(priorities, w->n_entries / 20);
        w->match_invocation = pick_value(invocations, 50);
        w->match_message = pick_value(messages, UINT64_MAX);
        w->seek_realtime = w->entries[w->n_entries / 2].ts.realtime;

        /* Roughly "journalctl -u a -u b -u c -u d -p info": any unit field of any of the units, ANDed with
         * the priorities up to info. */
        for (unsigned k = 0; k < 4; k++) {
                _cleanup_free_ char *unit = pick_value(units, w->n_entries / (2 + k * 5));
                const char *name;

                if (!unit)
                        break;

                name = unit + STRLEN("_SYSTEMD_UNIT=");
                ASSERT_OK(strv_extendf(&w->match_many, "_SYSTEMD_UNIT=%s", name));
                ASSERT_OK(strv_extend(&w->match_many, "|"));
                ASSERT_OK(strv_extendf(&w->match_many, "COREDUMP_UNIT=%s", name));
                ASSERT_OK(strv_extend(&w->match_many, "|"));
                ASSERT_OK(strv_extendf(&w->match_many, "UNIT=%s", name));
                ASSERT_OK(strv_extend(&w->match_many, "|"));
                ASSERT_OK(strv_extendf(&w->match_many, "OBJECT_SYSTEMD_UNIT=%s", name));
                ASSERT_OK(strv_extend(&w->match_many, "|"));
        }
        if (w->match_many) {
                ASSERT_OK(strv_extend(&w->match_many, "+"));
                for (unsigned p = 0; p <= 6; p++)
                        ASSERT_OK(strv_extendf(&w->match_many, "PRIORITY=%u", p));
        }

        /* A value that only one entry is expected to have */
        const Entry *e = w->entries + w->n_entries / 3;
        for (size_t i = 0; i < e->n_iovec; i++) {
                const struct iovec *v = w->iovecs + e->first_iovec + i;

                if (memory_startswith(v->iov_base, v->iov_len, "_SOURCE_REALTIME_TIMESTAMP=")) {
                        w->match_timestamp = ASSERT_NOT_NULL(strndup(v->iov_base, v->iov_len));
                        break;
                }
        }
}

/* Dirty page tracking */

static void tracker_done(Tracker *t) {
        assert(t);

        if (t->map)
                (void) munmap(t->map, TRACKER_MAP_SIZE);
        t->map = NULL;
        t->fd = safe_close(t->fd);
        if (t->shadow)
                (void) munmap(t->shadow, TRACKER_MAP_SIZE);
        t->shadow = NULL;
}

static void tracker_open(Tracker *t, int fd) {
        assert(t);
        assert(fd >= 0);

        *t = (Tracker) {
                .fd = ASSERT_OK(fd_reopen(fd, O_RDONLY|O_CLOEXEC)),
        };

        /* Map the maximum size once, so the file can grow without remapping. Only the part below EOF may be
         * accessed. */
        t->map = mmap(NULL, TRACKER_MAP_SIZE, PROT_READ, MAP_SHARED|MAP_NORESERVE, t->fd, 0);
        ASSERT_TRUE(t->map != MAP_FAILED);

        /* Keep the copy off the heap, so that heap usage only reflects the journal code. */
        t->shadow = mmap(NULL, TRACKER_MAP_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
        ASSERT_TRUE(t->shadow != MAP_FAILED);
}

static void tracker_writeback(Tracker *t, WriteResult *result) {
        uint64_t n_pages = 0, n_ranges = 0;
        size_t ps = page_size(), size;
        bool in_range = false;
        struct stat st;
        usec_t start;

        assert(t);
        assert(result);

        if (t->fd < 0)
                return;

        start = now(CLOCK_MONOTONIC);

        ASSERT_OK_ERRNO(fstat(t->fd, &st));
        size = PAGE_ALIGN((size_t) st.st_size);
        ASSERT_LE(size, (size_t) TRACKER_MAP_SIZE);

        if (arg_real_writeback)
                (void) fdatasync(t->fd);

        for (size_t block = 0; block < size; block += TRACKER_BLOCK_SIZE) {
                size_t block_size = MIN((size_t) TRACKER_BLOCK_SIZE, size - block);

                if (memcmp(t->map + block, t->shadow + block, block_size) == 0) {
                        in_range = false;
                        continue;
                }

                for (size_t p = block; p < block + block_size; p += ps) {
                        if (memcmp(t->map + p, t->shadow + p, ps) == 0) {
                                in_range = false;
                                continue;
                        }

                        memcpy(t->shadow + p, t->map + p, ps);

                        n_pages++;
                        if (!in_range)
                                n_ranges++;
                        in_range = true;
                }
        }

        result->tracker_usec += usec_sub_unsigned(now(CLOCK_MONOTONIC), start);

        if (n_pages == 0)
                return;

        result->n_writebacks++;
        result->dirty_pages += n_pages;
        result->dirty_ranges += n_ranges;
        result->max_dirty_pages = MAX(result->max_dirty_pages, n_pages);
}

/* Helpers */

static uint64_t heap_in_use(void) {
        struct mallinfo2 mi = mallinfo2();

        return (uint64_t) mi.uordblks + mi.hblkhd;
}

static uint64_t proc_io_field(const char *field) {
        _cleanup_free_ char *s = NULL;
        uint64_t v;

        if (get_proc_field("/proc/self/io", field, &s) < 0)
                return 0;
        if (safe_atou64(s, &v) < 0)
                return 0;

        return v;
}

static uint64_t count_extents(int fd) {
        struct fiemap fm = {
                .fm_length = FIEMAP_MAX_OFFSET,
                .fm_flags = FIEMAP_FLAG_SYNC,
        };

        if (ioctl(fd, FS_IOC_FIEMAP, &fm) < 0)
                return 0;

        return fm.fm_mapped_extents;
}

typedef int (*file_callback_t)(int fd, const struct stat *st, void *userdata);

static int foreach_journal_file(const char *path, file_callback_t callback, void *userdata) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(path);
        assert(callback);

        d = opendir(path);
        if (!d)
                return log_error_errno(errno, "Failed to open %s: %m", path);

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_close_ int fd = -EBADF;
                struct stat st;

                if (!endswith(de->d_name, ".journal"))
                        continue;

                fd = openat(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s/%s: %m", path, de->d_name);

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat %s/%s: %m", path, de->d_name);

                r = callback(fd, &st, userdata);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int account_file(int fd, const struct stat *st, void *userdata) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(journal_file_closep) JournalFile *f = NULL;
        WriteResult *result = ASSERT_PTR(userdata);
        int r;

        result->n_files++;
        result->file_bytes += st->st_size;
        result->n_extents += count_extents(fd);

        /* Only now is st_blocks final: FIEMAP_FLAG_SYNC in count_extents() flushed delayed allocations. */
        struct stat st2;
        ASSERT_OK_ERRNO(fstat(fd, &st2));
        result->disk_bytes += (uint64_t) st2.st_blocks * 512U;

        ASSERT_NOT_NULL(m = mmap_cache_new());
        r = journal_file_open(fd, NULL, O_RDONLY, 0, 0, UINT64_MAX, NULL, m, NULL, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open journal file: %m");

        if (f->segmented)
                result->n_indexes += f->segmented->n_indexes;

        f->close_fd = false;
        return 0;
}

static int evict_file(int fd, const struct stat *st, void *userdata) {
        (void) fsync(fd);

        if (posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) != 0)
                log_debug("Failed to drop page cache, ignoring.");

        return 0;
}

static int count_resident(int fd, const struct stat *st, void *userdata) {
        uint64_t *n = ASSERT_PTR(userdata);
        size_t size = PAGE_ALIGN((size_t) st->st_size), n_pages = size / page_size();
        _cleanup_free_ unsigned char *vec = NULL;
        void *p;

        if (size == 0)
                return 0;

        p = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED)
                return log_error_errno(errno, "Failed to map file: %m");

        vec = ASSERT_NOT_NULL(new(unsigned char, n_pages));
        ASSERT_OK_ERRNO(mincore(p, size, vec));
        ASSERT_OK_ERRNO(munmap(p, size));

        FOREACH_ARRAY(v, vec, n_pages)
                *n += *v & 1;

        return 0;
}

/* Write test */

static bool shall_rotate(int r) {
        return IN_SET(r, -E2BIG, -EFBIG, -EDQUOT, -ENOSPC, -EREMCHG, -ENOTNAM, -EILSEQ, -EBADMSG, -ENODATA, -EADDRNOTAVAIL);
}

static uint64_t sync_file(JournalFile *f, Tracker *tracker, WriteResult *result) {
        uint64_t t = now_nsec(CLOCK_PROCESS_CPUTIME_ID);

        ASSERT_OK(journal_file_set_offline(f, /* wait= */ true));
        tracker_writeback(tracker, result);
        result->n_syncs++;

        /* Returns the CPU time spent, which does not count as time spent appending */
        return now_nsec(CLOCK_PROCESS_CPUTIME_ID) - t;
}

static int write_test(const Workload *w, const char *path, WriteResult *result) {
        _cleanup_(mmap_cache_unrefp) MMapCache *mmap_cache = NULL;
        _cleanup_(journal_file_offline_closep) JournalFile *f = NULL;
        _cleanup_free_ char *fn = NULL;
        JournalFileFlags flags = JOURNAL_STRICT_ORDER | (arg_compress ? JOURNAL_COMPRESS : 0);
        uint64_t seqnum = 0, cpu_excluded = 0, cpu_start, t, heap_start, heap_max = 0;
        _cleanup_free_ uint64_t *latencies = NULL;
        usec_t next_writeback = USEC_INFINITY, sync_deadline = USEC_INFINITY, wall_start;
        sd_id128_t seqnum_id = SD_ID128_NULL;
        bool dirty = false;
        Tracker tracker = { .fd = -EBADF };
        int r;

        assert(w);
        assert(path);
        assert(result);

        JournalMetrics metrics = {
                .max_size = arg_max_size,
                .min_size = UINT64_MAX,
                .max_use = 0,
                .min_use = UINT64_MAX,
                .keep_free = 0,
                .n_max_files = UINT64_MAX,
        };

        ASSERT_NOT_NULL(latencies = new(uint64_t, w->n_entries));
        ASSERT_NOT_NULL(mmap_cache = mmap_cache_new());
        ASSERT_NOT_NULL(fn = path_join(path, "system.journal"));

        heap_start = heap_in_use();

        r = journal_file_open_reliably(fn, O_RDWR|O_CREAT, flags, 0640, UINT64_MAX, &metrics, mmap_cache, /* seqnum_id= */ NULL, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open %s: %m", fn);

        tracker_open(&tracker, f->fd);

        uint64_t write_bytes = proc_io_field("write_bytes"),
                 wchar = proc_io_field("wchar"),
                 syscw = proc_io_field("syscw");

        wall_start = now(CLOCK_MONOTONIC);
        cpu_start = now_nsec(CLOCK_PROCESS_CPUTIME_ID);

        FOREACH_ARRAY(e, w->entries, w->n_entries) {
                bool rotate;

                /* Kernel writeback: once --writeback has passed in log time, all dirty pages are written. */
                if (next_writeback == USEC_INFINITY)
                        next_writeback = usec_add(e->ts.realtime, arg_writeback_usec);
                else if (e->ts.realtime >= next_writeback) {
                        if (dirty) {
                                t = now_nsec(CLOCK_PROCESS_CPUTIME_ID);
                                tracker_writeback(&tracker, result);
                                cpu_excluded += now_nsec(CLOCK_PROCESS_CPUTIME_ID) - t;
                                dirty = false;
                        }

                        next_writeback = usec_add(e->ts.realtime, arg_writeback_usec);
                }

                /* Like journald, sync once --sync has passed since the first write after the last sync. */
                if (e->ts.realtime >= sync_deadline) {
                        cpu_excluded += sync_file(f, &tracker, result);
                        sync_deadline = USEC_INFINITY;
                        dirty = false;
                }

                rotate = journal_file_rotate_suggested(f, 0, LOG_DEBUG);

                for (unsigned attempt = 0;; attempt++) {
                        if (rotate) {
                                Tracker old = TAKE_GENERIC(tracker, Tracker, (Tracker) { .fd = -EBADF });

                                r = journal_file_rotate(&f, mmap_cache, flags, UINT64_MAX, /* seqnum_id= */ NULL, /* deferred_closes= */ NULL);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to rotate %s: %m", fn);

                                t = now_nsec(CLOCK_PROCESS_CPUTIME_ID);
                                tracker_writeback(&old, result);
                                tracker_done(&old);
                                tracker_open(&tracker, f->fd);
                                cpu_excluded += now_nsec(CLOCK_PROCESS_CPUTIME_ID) - t;

                                result->n_rotations++;
                        }

                        usec_t before = now(CLOCK_MONOTONIC);

                        r = journal_file_append_entry(
                                        f,
                                        &e->ts,
                                        &e->boot_id,
                                        w->iovecs + e->first_iovec,
                                        e->n_iovec,
                                        &seqnum,
                                        &seqnum_id,
                                        /* ret_object= */ NULL,
                                        /* ret_offset= */ NULL);

                        latencies[result->n_entries] = usec_sub_unsigned(now(CLOCK_MONOTONIC), before) * NSEC_PER_USEC;

                        if (r >= 0)
                                break;
                        if (attempt > 0 || !shall_rotate(r))
                                return log_error_errno(r, "Failed to append entry: %m");

                        rotate = true;
                }

                dirty = true;
                result->n_entries++;

                if (result->n_entries % 1000 == 0)
                        heap_max = MAX(heap_max, heap_in_use());

                /* Like journald, sync right away after messages of priority crit or higher. */
                if (e->priority >= 0 && e->priority <= LOG_CRIT) {
                        cpu_excluded += sync_file(f, &tracker, result);
                        sync_deadline = USEC_INFINITY;
                        dirty = false;
                } else if (sync_deadline == USEC_INFINITY)
                        sync_deadline = usec_add(e->ts.realtime, arg_sync_usec);
        }

        result->append_cpu_nsec = now_nsec(CLOCK_PROCESS_CPUTIME_ID) - cpu_start - cpu_excluded;
        heap_max = MAX(heap_max, heap_in_use());
        result->heap_bytes = LESS_BY(heap_max, heap_start);

        typesafe_qsort(latencies, result->n_entries, uint64_compare_func);
        if (result->n_entries > 0) {
                result->append_p50_nsec = latencies[result->n_entries / 2];
                result->append_p99_nsec = latencies[result->n_entries * 99 / 100];
                result->append_max_nsec = latencies[result->n_entries - 1];
        }

        f = journal_file_offline_close(f);
        tracker_writeback(&tracker, result);
        tracker_done(&tracker);
        result->n_syncs++;

        /* Includes syncs, rotations, and closing, but not the writeback emulation */
        result->write_usec = LESS_BY(usec_sub_unsigned(now(CLOCK_MONOTONIC), wall_start), result->tracker_usec);
        result->payload_bytes = w->payload_bytes;
        result->io_write_bytes = proc_io_field("write_bytes") - write_bytes;
        result->io_wchar = proc_io_field("wchar") - wchar;
        result->io_syscw = proc_io_field("syscw") - syscw;

        return foreach_journal_file(path, account_file, result);
}

/* Read tests */

typedef struct ReadContext {
        const Workload *workload;
        const char *path;
        uint64_t n_results;
        uint64_t digest;
} ReadContext;

typedef int (*read_test_t)(ReadContext *c, sd_journal *j);

static void digest_entry(ReadContext *c, sd_journal *j, bool all_fields) {
        uint64_t realtime, monotonic, h = 0;
        sd_id128_t boot_id;
        const void *data;
        size_t size;

        ASSERT_OK(sd_journal_get_realtime_usec(j, &realtime));
        ASSERT_OK(sd_journal_get_monotonic_usec(j, &monotonic, &boot_id));

        if (all_fields)
                /* Field order is not part of the API, so combine the hashes with a sum, which ignores it. */
                SD_JOURNAL_FOREACH_DATA(j, data, size)
                        h += siphash24(data, size, digest_key);
        else if (sd_journal_get_data(j, "MESSAGE", &data, &size) >= 0)
                h = siphash24(data, size, digest_key);

        h += realtime * 3 + monotonic * 5 + siphash24(&boot_id, sizeof(boot_id), digest_key);

        c->digest = c->digest * 31 + h;
        c->n_results++;
}

static int digest_entries(ReadContext *c, sd_journal *j, direction_t direction, uint64_t limit, bool all_fields) {
        int r;

        for (uint64_t i = 0; i < limit; i++) {
                r = direction == DIRECTION_DOWN ? sd_journal_next(j) : sd_journal_previous(j);
                if (r <= 0)
                        return r;

                digest_entry(c, j, all_fields);
        }

        return 0;
}

static int read_tail(ReadContext *c, sd_journal *j) {
        ASSERT_OK(sd_journal_seek_tail(j));
        return digest_entries(c, j, DIRECTION_UP, 10, /* all_fields= */ false);
}

static int read_all(ReadContext *c, sd_journal *j, bool all_fields) {
        ASSERT_OK(sd_journal_seek_head(j));
        return digest_entries(c, j, DIRECTION_DOWN, UINT64_MAX, all_fields);
}

static int read_iterate(ReadContext *c, sd_journal *j) {
        return read_all(c, j, /* all_fields= */ true);
}

static int read_match(ReadContext *c, sd_journal *j, const char *match);

static int read_iterate_backwards(ReadContext *c, sd_journal *j) {
        ASSERT_OK(sd_journal_seek_tail(j));
        return digest_entries(c, j, DIRECTION_UP, UINT64_MAX, /* all_fields= */ false);
}

static int read_cursor(ReadContext *c, sd_journal *j) {
        _cleanup_free_ char *cursor = NULL;
        int r;

        ASSERT_OK(sd_journal_seek_realtime_usec(j, c->workload->seek_realtime));
        r = sd_journal_next(j);
        if (r <= 0)
                return r;

        ASSERT_OK(sd_journal_get_cursor(j, &cursor));
        ASSERT_OK(sd_journal_seek_head(j));
        ASSERT_OK(sd_journal_seek_cursor(j, cursor));

        for (unsigned i = 0; i < 20; i++) {
                r = sd_journal_next(j);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (i == 0)
                        ASSERT_OK_POSITIVE(sd_journal_test_cursor(j, cursor));

                digest_entry(c, j, /* all_fields= */ false);
        }

        return 0;
}

static int read_match_timestamp(ReadContext *c, sd_journal *j) {
        return read_match(c, j, c->workload->match_timestamp);
}

static int read_match_many(ReadContext *c, sd_journal *j) {
        if (!c->workload->match_many)
                return 0;

        STRV_FOREACH(m, c->workload->match_many)
                if (streq(*m, "+"))
                        ASSERT_OK(sd_journal_add_conjunction(j));
                else if (streq(*m, "|"))
                        ASSERT_OK(sd_journal_add_disjunction(j));
                else
                        ASSERT_OK(sd_journal_add_match(j, *m, SIZE_MAX));

        return read_all(c, j, /* all_fields= */ false);
}

static int read_match(ReadContext *c, sd_journal *j, const char *match) {
        if (!match)
                return 0;

        ASSERT_OK(sd_journal_add_match(j, match, SIZE_MAX));
        return read_all(c, j, /* all_fields= */ false);
}

static int read_grep(ReadContext *c, sd_journal *j) {
        int r;

        /* Like journalctl --grep=error, but with a substring instead of a regex. Pattern matching costs the
         * same for every format. */

        ASSERT_OK(sd_journal_seek_head(j));

        for (;;) {
                const void *data;
                size_t size;

                r = sd_journal_next(j);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 0;

                r = sd_journal_get_data(j, "MESSAGE", &data, &size);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                if (memmem_safe(data, size, "error", STRLEN("error")))
                        digest_entry(c, j, /* all_fields= */ false);
        }
}

static int read_grep_unit(ReadContext *c, sd_journal *j) {
        if (!c->workload->match_common)
                return 0;

        ASSERT_OK(sd_journal_add_match(j, c->workload->match_common, SIZE_MAX));
        return read_grep(c, j);
}

static int read_match_rare(ReadContext *c, sd_journal *j) {
        return read_match(c, j, c->workload->match_rare);
}

static int read_match_common(ReadContext *c, sd_journal *j) {
        return read_match(c, j, c->workload->match_common);
}

static int read_match_message(ReadContext *c, sd_journal *j) {
        return read_match(c, j, c->workload->match_message);
}

static int read_match_boot_priority(ReadContext *c, sd_journal *j) {
        if (!c->workload->match_boot || !c->workload->match_priority)
                return 0;

        ASSERT_OK(sd_journal_add_match(j, c->workload->match_boot, SIZE_MAX));
        return read_match(c, j, c->workload->match_priority);
}

static int read_status(ReadContext *c, sd_journal *j) {
        if (!c->workload->match_invocation)
                return 0;

        ASSERT_OK(sd_journal_add_match(j, c->workload->match_invocation, SIZE_MAX));
        return read_tail(c, j);
}

static int read_seek(ReadContext *c, sd_journal *j) {
        ASSERT_OK(sd_journal_seek_realtime_usec(j, c->workload->seek_realtime));
        return digest_entries(c, j, DIRECTION_DOWN, 100, /* all_fields= */ false);
}

static int read_unique(ReadContext *c, sd_journal *j) {
        const void *data;
        size_t size;
        int r;

        ASSERT_OK(sd_journal_query_unique(j, "_SYSTEMD_UNIT"));

        for (;;) {
                r = sd_journal_enumerate_unique(j, &data, &size);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 0;

                c->digest += siphash24(data, size, digest_key);
                c->n_results++;
        }
}

static int read_fields(ReadContext *c, sd_journal *j) {
        const char *field;
        int r;

        for (;;) {
                r = sd_journal_enumerate_fields(j, &field);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 0;

                c->digest += siphash24_string(field, digest_key);
                c->n_results++;
        }
}

static const struct {
        const char *name;
        read_test_t func;
} read_tests[] = {
        { "tail-10",             read_tail                },
        { "status-like",         read_status              },
        { "seek-middle-100",     read_seek                },
        { "match-rare-unit",     read_match_rare          },
        { "match-common-unit",   read_match_common        },
        { "match-boot+priority", read_match_boot_priority },
        { "match-message",       read_match_message       },
        { "match-timestamp",     read_match_timestamp     },
        { "match-many-terms",    read_match_many          },
        { "grep-message",        read_grep                },
        { "grep-common-unit",    read_grep_unit           },
        { "cursor",              read_cursor              },
        { "unique-units",        read_unique              },
        { "fields",              read_fields              },
        { "iterate-all",         read_iterate             },
        { "iterate-backwards",   read_iterate_backwards   },
};

assert_cc(ELEMENTSOF(read_tests) <= N_READ_TESTS_MAX);

static int read_test_once(ReadContext *c, read_test_t func, usec_t *ret_usec, uint64_t *ret_heap) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        uint64_t heap = heap_in_use();
        usec_t start;
        int r;

        c->digest = 0;
        c->n_results = 0;

        start = now(CLOCK_MONOTONIC);

        r = sd_journal_open_directory(&j, c->path, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to open %s: %m", c->path);

        ASSERT_OK(sd_journal_set_data_threshold(j, 0));

        r = func(c, j);
        if (r < 0)
                return log_error_errno(r, "Failed to read %s: %m", c->path);

        if (ret_heap)
                *ret_heap = LESS_BY(heap_in_use(), heap);

        sd_journal_close(TAKE_PTR(j));

        *ret_usec = usec_sub_unsigned(now(CLOCK_MONOTONIC), start);
        return 0;
}

static int read_test(const Workload *w, const char *path, Report *report) {
        int r;

        FOREACH_ELEMENT(test, read_tests) {
                ReadResult *result = report->read + (test - read_tests);
                ReadContext c = {
                        .workload = w,
                        .path = path,
                };
                uint64_t read_bytes;

                r = foreach_journal_file(path, evict_file, NULL);
                if (r < 0)
                        return r;

                uint64_t resident = 0;
                r = foreach_journal_file(path, count_resident, &resident);
                if (r < 0)
                        return r;
                if (resident > 0)
                        log_warning("%" PRIu64 " pages are still in the page cache after evicting them, the cold cache figures are not accurate.", resident);

                read_bytes = proc_io_field("read_bytes");

                r = read_test_once(&c, test->func, &result->cold_usec, NULL);
                if (r < 0)
                        return r;

                result->cold_read_bytes = proc_io_field("read_bytes") - read_bytes;

                r = foreach_journal_file(path, count_resident, &result->cold_pages);
                if (r < 0)
                        return r;

                uint64_t digest = c.digest;

                r = read_test_once(&c, test->func, &result->warm_usec, &result->heap_bytes);
                if (r < 0)
                        return r;

                if (c.digest != digest)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Test %s returned different results when run twice.", test->name);

                result->n_results = c.n_results;
                result->digest = c.digest;
        }

        return 0;
}

/* Following a writer */

static int follow_writer(const Workload *w, const char *path, uint64_t n, int ready_fd, int go_fd) {
        _cleanup_(mmap_cache_unrefp) MMapCache *mmap_cache = NULL;
        _cleanup_(journal_file_offline_closep) JournalFile *f = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_free_ char *fn = NULL;
        usec_t start;
        int r;

        JournalMetrics metrics = {
                .max_size = arg_max_size,
                .min_size = UINT64_MAX,
                .max_use = 0,
                .min_use = UINT64_MAX,
                .keep_free = 0,
                .n_max_files = UINT64_MAX,
        };

        ASSERT_NOT_NULL(mmap_cache = mmap_cache_new());
        ASSERT_NOT_NULL(fn = path_join(path, "system.journal"));

        r = journal_file_open_reliably(fn, O_RDWR|O_CREAT, arg_compress ? JOURNAL_COMPRESS : 0, 0640, UINT64_MAX, &metrics, mmap_cache, /* seqnum_id= */ NULL, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open %s: %m", fn);

        /* Like journald, notify readers of changes at most every 250ms. */
        ASSERT_OK(sd_event_default(&e));
        ASSERT_OK(journal_file_enable_post_change_timer(f, e, 250 * USEC_PER_MSEC));

        /* Give the reader a file with one entry to open, then wait until it is ready. */
        r = journal_file_append_entry(f, &w->entries[0].ts, &w->entries[0].boot_id, w->iovecs + w->entries[0].first_iovec, w->entries[0].n_iovec, NULL, NULL, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to append entry: %m");
        journal_file_post_change(f);

        ASSERT_OK(loop_write(ready_fd, &(char) { 'r' }, 1));
        ASSERT_OK(loop_read_exact(go_fd, &(char) { 0 }, 1, /* do_poll= */ true));
        start = now(CLOCK_MONOTONIC);

        for (uint64_t i = 1; i < n; i++) {
                const Entry *entry = w->entries + i;
                usec_t target = start + i * USEC_PER_SEC / arg_follow_rate, t = now(CLOCK_MONOTONIC);

                if (t < target)
                        (void) usleep_safe(target - t);

                r = journal_file_append_entry(f, &entry->ts, &entry->boot_id, w->iovecs + entry->first_iovec, entry->n_iovec, NULL, NULL, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to append entry: %m");

                ASSERT_OK(sd_event_run(e, 0));
        }

        return 0;
}

static int follow_test(const Workload *w, const char *path, const char *match, FollowResult *result) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_(pidref_done) PidRef writer = PIDREF_NULL;
        _cleanup_close_pair_ int ready[2] = EBADF_PAIR, go[2] = EBADF_PAIR;
        _cleanup_free_ char *dir = NULL;
        uint64_t n = MIN(w->n_entries, arg_follow_rate * 5), cpu;
        usec_t start;
        int r;

        ASSERT_NOT_NULL(dir = path_join(path, match ? "follow-none" : "follow-all"));
        (void) rm_rf(dir, REMOVE_ROOT|REMOVE_PHYSICAL);
        ASSERT_OK(mkdir_p(dir, 0755));

        ASSERT_OK_ERRNO(pipe2(ready, O_CLOEXEC));
        ASSERT_OK_ERRNO(pipe2(go, O_CLOEXEC));

        r = ASSERT_OK(pidref_safe_fork("(writer)", FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_REOPEN_LOG, &writer));
        if (r == 0) {
                ready[0] = safe_close(ready[0]);
                go[1] = safe_close(go[1]);
                r = follow_writer(w, dir, n, ready[1], go[0]);
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        ready[1] = safe_close(ready[1]);
        go[0] = safe_close(go[0]);

        ASSERT_OK(loop_read_exact(ready[0], &(char) { 0 }, 1, /* do_poll= */ true));

        r = sd_journal_open_directory(&j, dir, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to open %s: %m", dir);

        if (match)
                ASSERT_OK(sd_journal_add_match(j, match, SIZE_MAX));

        ASSERT_OK(sd_journal_seek_tail(j));
        r = sd_journal_previous(j);
        if (r < 0)
                return log_error_errno(r, "Failed to seek: %m");
        if (r == 0)
                /* Nothing matched yet, so read from the start */
                ASSERT_OK(sd_journal_seek_head(j));

        ASSERT_OK(loop_write(go[1], &(char) { 'g' }, 1));

        cpu = now_nsec(CLOCK_PROCESS_CPUTIME_ID);
        start = now(CLOCK_MONOTONIC);

        /* Like journalctl -f: wait for a change, then read what is new. The writer's pidfd signals the
         * end. */
        for (bool writer_done = false;;) {
                struct pollfd pollfd[2] = {
                        {
                                .fd = sd_journal_get_fd(j),
                                .events = sd_journal_get_events(j),
                        },
                        {
                                .fd = writer.fd,
                                .events = POLLIN,
                        },
                };

                ASSERT_OK(pollfd[0].fd);
                ASSERT_OK(writer.fd);

                r = poll(pollfd, writer_done ? 1 : 2, writer_done ? 0 : 5000);
                if (r < 0 && errno != EINTR)
                        return log_error_errno(errno, "poll() failed: %m");

                if (r > 0 && pollfd[0].revents != 0)
                        result->n_wakeups++;

                r = sd_journal_process(j);
                if (r < 0)
                        return log_error_errno(r, "Failed to process journal events: %m");

                for (;;) {
                        r = sd_journal_next(j);
                        if (r < 0)
                                return log_error_errno(r, "Failed to iterate: %m");
                        if (r == 0)
                                break;

                        result->n_results++;
                }

                if (writer_done)
                        break;

                if (pollfd[1].revents != 0) {
                        r = pidref_wait_for_terminate_and_check("(writer)", &writer, WAIT_LOG);
                        if (r < 0)
                                return r;
                        if (r != EXIT_SUCCESS)
                                return log_error_errno(SYNTHETIC_ERRNO(EPROTO), "Writer failed.");

                        writer_done = true; /* One more round to read what is left */
                }
        }

        result->cpu_nsec = now_nsec(CLOCK_PROCESS_CPUTIME_ID) - cpu;
        result->wall_usec = usec_sub_unsigned(now(CLOCK_MONOTONIC), start);
        result->n_entries = n;

        (void) rm_rf(dir, REMOVE_ROOT|REMOVE_PHYSICAL);
        return 0;
}

/* Driver */

static int run_format(const Workload *w, const Format *format, Report *report) {
        _cleanup_close_pair_ int pipe_fds[2] = EBADF_PAIR;
        _cleanup_free_ char *path = NULL;
        int r;

        assert(w);
        assert(format);
        assert(report);

        ASSERT_NOT_NULL(path = path_join(arg_output, format->name));

        if (arg_write) {
                (void) rm_rf(path, REMOVE_ROOT|REMOVE_PHYSICAL);
                ASSERT_OK(mkdir_p(path, 0755));

                bool nocow = arg_nocow >= 0 ? arg_nocow : format->nocow;
                r = chattr_path(path, nocow ? FS_NOCOW_FL : 0, FS_NOCOW_FL);
                if (r < 0)
                        log_debug_errno(r, "Failed to %s copy-on-write for %s, ignoring: %m", nocow ? "disable" : "enable", path);
        }

        ASSERT_OK_ERRNO(pipe2(pipe_fds, O_CLOEXEC));

        /* One process per format: the journal code caches $SYSTEMD_JOURNAL_COMPACT and
         * $SYSTEMD_JOURNAL_KEYED_HASH per thread, and resource usage stays separate per format. */
        r = ASSERT_OK(pidref_safe_fork("(benchmark)", FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_WAIT|FORK_REOPEN_LOG, NULL));
        if (r == 0) {
                Report child = {};

                pipe_fds[0] = safe_close(pipe_fds[0]);

                ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_KEYED_HASH", "1", /* overwrite= */ true));
                ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", format->compact, /* overwrite= */ true));
                ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_SEGMENTED", format->segmented, /* overwrite= */ true));

                if (arg_write) {
                        r = write_test(w, path, &child.write);
                        if (r < 0)
                                _exit(EXIT_FAILURE);
                }

                if (arg_read) {
                        r = read_test(w, path, &child);
                        if (r < 0)
                                _exit(EXIT_FAILURE);
                }

                if (arg_follow) {
                        r = follow_test(w, arg_output, NULL, child.follow + 0);
                        if (r >= 0)
                                r = follow_test(w, arg_output, "NOSUCHFIELD=nothing", child.follow + 1);
                        if (r < 0)
                                _exit(EXIT_FAILURE);
                }

                r = loop_write(pipe_fds[1], &child, sizeof(child));
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        pipe_fds[1] = safe_close(pipe_fds[1]);

        r = loop_read_exact(pipe_fds[0], report, sizeof(*report), /* do_poll= */ false);
        if (r < 0)
                return log_error_errno(r, "Benchmark of format %s failed: %m", format->name);

        if (!arg_keep && arg_write)
                (void) rm_rf(path, REMOVE_ROOT|REMOVE_PHYSICAL);

        return 0;
}

static const char* ratio(uint64_t value, uint64_t base, char buf[static 16]) {
        if (base == 0)
                return "";

        (void) snprintf(buf, 16, "(%.2fx)", (double) value / (double) base);
        return buf;
}

#define ROW_U64(label, field, scale, unit)                                                                      \
        ({                                                                                                      \
                printf("%-34s", label);                                                                         \
                for (size_t _i = 0; _i < n; _i++) {                                                             \
                        char _buf[16];                                                                          \
                        printf(" %14.*f %-8s",                                                                  \
                               (uint64_t) (scale) == 1 ? 0 : 2,                                                 \
                               (double) reports[_i].write.field / (double) (uint64_t) (scale),                  \
                               _i == 0 ? "" : ratio(reports[_i].write.field, reports[0].write.field, _buf));    \
                }                                                                                               \
                printf(" %s\n", unit);                                                                          \
        })

static void print_read_reports(const Format **used, const Report *reports, size_t n);
static void print_follow_reports(const Format **used, const Report *reports, size_t n);

static void print_reports(const Workload *w, const Format **used, const Report *reports, size_t n) {
        size_t ps = page_size();

        printf("\nWorkload: %zu entries, %zu fields, %s payload, %s of log time\n",
               w->n_entries, w->n_iovecs, FORMAT_BYTES(w->payload_bytes),
               FORMAT_TIMESPAN(w->entries[w->n_entries - 1].ts.realtime - w->entries[0].ts.realtime, USEC_PER_SEC));
        printf("Writeback every %s, sync every %s, maximum file size %s, compression %s\n",
               FORMAT_TIMESPAN(arg_writeback_usec, USEC_PER_SEC), FORMAT_TIMESPAN(arg_sync_usec, USEC_PER_SEC),
               FORMAT_BYTES(arg_max_size), yes_no(arg_compress));

        if (arg_write) {
                printf("\n%-34s", "WRITE");
                for (size_t i = 0; i < n; i++)
                        printf(" %14s %-8s", used[i]->name, "");
                printf("\n");

                ROW_U64("entries", n_entries, 1, "");
                ROW_U64("files", n_files, 1, "");
                ROW_U64("rotations", n_rotations, 1, "");
                ROW_U64("writebacks with dirty pages", n_writebacks, 1, "");
                ROW_U64("syncs", n_syncs, 1, "");
                ROW_U64("dirty pages", dirty_pages, 1, "pages");
                ROW_U64("dirty ranges", dirty_ranges, 1, "ranges");
                ROW_U64("largest writeback", max_dirty_pages, 1, "pages");
                printf("%-34s", "bytes written back");
                for (size_t i = 0; i < n; i++) {
                        char buf[16];
                        printf(" %14.2f %-8s", (double) (reports[i].write.dirty_pages * ps) / (double) U64_MB,
                               i == 0 ? "" : ratio(reports[i].write.dirty_pages, reports[0].write.dirty_pages, buf));
                }
                printf(" MiB\n");
                ROW_U64("file size", file_bytes, U64_MB, "MiB");
                ROW_U64("disk usage", disk_bytes, U64_MB, "MiB");
                ROW_U64("extents", n_extents, 1, "");
                ROW_U64("indexes", n_indexes, 1, "");
                ROW_U64("append CPU time", append_cpu_nsec, NSEC_PER_MSEC, "ms");
                ROW_U64("append latency, median", append_p50_nsec, NSEC_PER_USEC, "us");
                ROW_U64("append latency, 99th percentile", append_p99_nsec, NSEC_PER_USEC, "us");
                ROW_U64("append latency, maximum", append_max_nsec, NSEC_PER_USEC, "us");
                ROW_U64("write time", write_usec, USEC_PER_MSEC, "ms");
                ROW_U64("kernel: write_bytes", io_write_bytes, U64_MB, "MiB");
                ROW_U64("kernel: wchar", io_wchar, U64_MB, "MiB");
                ROW_U64("kernel: write syscalls", io_syscw, 1, "");
                ROW_U64("heap of the writer", heap_bytes, U64_KB, "KiB");

                printf("%-34s", "written back per payload byte");
                for (size_t i = 0; i < n; i++)
                        printf(" %14.2f %-8s", (double) (reports[i].write.dirty_pages * ps) / (double) reports[i].write.payload_bytes, "");
                printf("\n");

                printf("%-34s", "dirty pages per writeback");
                for (size_t i = 0; i < n; i++)
                        printf(" %14.1f %-8s", (double) reports[i].write.dirty_pages / (double) MAX(reports[i].write.n_writebacks, UINT64_C(1)), "");
                printf("\n");

                printf("%-34s", "dirty ranges per writeback");
                for (size_t i = 0; i < n; i++)
                        printf(" %14.1f %-8s", (double) reports[i].write.dirty_ranges / (double) MAX(reports[i].write.n_writebacks, UINT64_C(1)), "");
                printf("\n");

                printf("%-34s", "append CPU time per entry");
                for (size_t i = 0; i < n; i++)
                        printf(" %14.0f %-8s", (double) reports[i].write.append_cpu_nsec / (double) MAX(reports[i].write.n_entries, UINT64_C(1)), "");
                printf(" ns\n");
        }

        if (arg_read)
                print_read_reports(used, reports, n);

        if (arg_follow)
                print_follow_reports(used, reports, n);
}

static void print_read_reports(const Format **used, const Report *reports, size_t n) {
        static const struct {
                const char *title;
                const char *unit;
                size_t offset;
                uint64_t scale;
        } tables[] = {
                { "READ, cold page cache: time",        "ms",    offsetof(ReadResult, cold_usec),       USEC_PER_MSEC },
                { "READ, cold page cache: pages read",  "pages", offsetof(ReadResult, cold_pages),      1             },
                { "READ, cold page cache: bytes read",  "KiB",   offsetof(ReadResult, cold_read_bytes), U64_KB        },
                { "READ, warm page cache: time",        "ms",    offsetof(ReadResult, warm_usec),       USEC_PER_MSEC },
                { "READ: heap of the reader",           "KiB",   offsetof(ReadResult, heap_bytes),      U64_KB        },
        };

        FOREACH_ELEMENT(t, tables) {
                printf("\n%-34s", t->title);
                for (size_t i = 0; i < n; i++)
                        printf(" %14s %-8s", used[i]->name, "");
                printf("\n");

                for (size_t k = 0; k < ELEMENTSOF(read_tests); k++) {
                        printf("%-34s", read_tests[k].name);

                        for (size_t i = 0; i < n; i++) {
                                uint64_t v = *(const uint64_t*) ((const uint8_t*) (reports[i].read + k) + t->offset),
                                         base = *(const uint64_t*) ((const uint8_t*) (reports[0].read + k) + t->offset);
                                char buf[16];

                                printf(" %14.*f %-8s", t->scale == 1 ? 0 : 2, (double) v / (double) t->scale,
                                       i == 0 ? "" : ratio(v, base, buf));
                        }

                        printf(" %s\n", t->unit);
                }
        }

        printf("\n%-34s", "READ: results");
        for (size_t i = 0; i < n; i++)
                printf(" %14s %-8s", used[i]->name, "");
        printf("\n");

        for (size_t k = 0; k < ELEMENTSOF(read_tests); k++) {
                printf("%-34s", read_tests[k].name);
                for (size_t i = 0; i < n; i++)
                        printf(" %14" PRIu64 " %-8s", reports[i].read[k].n_results,
                               reports[i].read[k].digest == reports[0].read[k].digest ? "" : "DIFFERS");
                printf("\n");
        }
}

static void print_follow_reports(const Format **used, const Report *reports, size_t n) {
        FOREACH_ARRAY(f, reports[0].follow, 2) {
                size_t k = f - reports[0].follow;

                printf("\n%-34s", k == 0 ? "FOLLOW, reading everything" : "FOLLOW, matching nothing");
                for (size_t i = 0; i < n; i++)
                        printf(" %14s %-8s", used[i]->name, "");
                printf("\n");

                printf("%-34s", "entries written");
                for (size_t i = 0; i < n; i++)
                        printf(" %14" PRIu64 " %-8s", reports[i].follow[k].n_entries, "");
                printf("\n");

                printf("%-34s", "entries read");
                for (size_t i = 0; i < n; i++)
                        printf(" %14" PRIu64 " %-8s", reports[i].follow[k].n_results, "");
                printf("\n");

                printf("%-34s", "wakeups");
                for (size_t i = 0; i < n; i++)
                        printf(" %14" PRIu64 " %-8s", reports[i].follow[k].n_wakeups, "");
                printf("\n");

                printf("%-34s", "wakeups per second");
                for (size_t i = 0; i < n; i++)
                        printf(" %14.1f %-8s", (double) reports[i].follow[k].n_wakeups * USEC_PER_SEC / (double) MAX(reports[i].follow[k].wall_usec, UINT64_C(1)), "");
                printf("\n");

                printf("%-34s", "CPU time of the reader");
                for (size_t i = 0; i < n; i++)
                        printf(" %14.2f %-8s", (double) reports[i].follow[k].cpu_nsec / NSEC_PER_MSEC, "");
                printf(" ms\n");

                printf("%-34s", "CPU use of the reader");
                for (size_t i = 0; i < n; i++)
                        printf(" %14.2f %-8s", 100.0 * (double) reports[i].follow[k].cpu_nsec / NSEC_PER_USEC / (double) MAX(reports[i].follow[k].wall_usec, UINT64_C(1)), "");
                printf(" %%\n");
        }
}

static int run(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        Workload w = {};
        int r;

        test_setup_logging(LOG_INFO);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_LONG("input", "PATH",
                            "Replay the entries of this journal directory or file (default: synthetic entries)"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_input);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("output", "PATH",
                            "Directory to create the journal files in (default: a new directory in /var/tmp/)"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_output);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("entries", "N",
                            "Number of entries to write, taken from the end of the input, 0 for all (default: 100000)"):
                        r = safe_atou64(opts.arg, &arg_entries);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --entries=%s: %m", opts.arg);
                        break;

                OPTION_LONG("formats", "LIST",
                            "Comma-separated formats to compare: classic, compact, segmented (default: all)"):
                        r = strv_split_and_extend(&arg_formats, opts.arg, ",", /* filter_duplicates= */ true);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION_LONG("max-size", "BYTES", "Maximum size of a journal file (default: 128M)"):
                        r = parse_size(opts.arg, 1024, &arg_max_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --max-size=%s: %m", opts.arg);
                        break;

                OPTION_LONG("writeback", "TIME", "Emulated kernel writeback interval, in log time (default: 30s)"):
                        r = parse_sec(opts.arg, &arg_writeback_usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --writeback=%s: %m", opts.arg);
                        break;

                OPTION_LONG("sync", "TIME", "Emulated journald sync interval, in log time (default: 5min)"):
                        r = parse_sec(opts.arg, &arg_sync_usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --sync=%s: %m", opts.arg);
                        break;

                OPTION_LONG("compress", "BOOL", "Enable compression (default: yes)"):
                        r = parse_boolean_argument("--compress=", opts.arg, &arg_compress);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("nocow", "BOOL",
                            "Disable copy-on-write for the journal files (default: auto, only for classic and compact)"):
                        r = parse_tristate_argument_with_auto("--nocow=", opts.arg, &arg_nocow);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("write", "BOOL", "Run the write tests (default: yes)"):
                        r = parse_boolean_argument("--write=", opts.arg, &arg_write);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("read", "BOOL", "Run the read tests (default: yes)"):
                        r = parse_boolean_argument("--read=", opts.arg, &arg_read);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("follow", "BOOL", "Run the follow tests (default: yes)"):
                        r = parse_boolean_argument("--follow=", opts.arg, &arg_follow);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("follow-rate", "N", "Entries per second in the follow tests (default: 1000)"):
                        r = safe_atou64(opts.arg, &arg_follow_rate);
                        if (r < 0 || arg_follow_rate == 0)
                                return log_error_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL), "Failed to parse --follow-rate=%s: %m", opts.arg);
                        break;

                OPTION_LONG("real-writeback", "BOOL",
                            "Also fdatasync() the file at each emulated writeback, so the kernel I/O counters are meaningful (default: no)"):
                        r = parse_boolean_argument("--real-writeback=", opts.arg, &arg_real_writeback);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("keep", NULL, "Do not remove the journal files afterwards"):
                        arg_keep = true;
                        break;

                OPTION_LONG("seed", "N", "Seed for the synthetic entries"):
                        r = safe_atou64(opts.arg, &arg_seed);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --seed=%s: %m", opts.arg);
                        break;
                }

        /* journal_file_open() requires a valid machine id */
        if (sd_id128_get_machine(NULL) < 0)
                return log_tests_skipped("No valid machine ID found");

        if (!arg_output) {
                r = mkdtemp_malloc("/var/tmp/test-journal-benchmark-XXXXXX", &tmp);
                if (r < 0)
                        return log_error_errno(r, "Failed to create output directory: %m");

                arg_output = ASSERT_NOT_NULL(strdup(tmp));
                if (arg_keep)
                        tmp = mfree(tmp);
        }

        if (arg_input)
                r = workload_load_journal(&w);
        else {
                if (arg_entries == 0)
                        arg_entries = 100000;

                workload_generate(&w);
                r = 0;
        }
        if (r < 0)
                return r;
        if (w.n_entries == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "Nothing to write.");

        workload_pick_parameters(&w);

        log_info("Output directory: %s", arg_output);
        log_info("Matches: %s, %s, %s, %s, %s, %s, %s",
                 strna(w.match_rare), strna(w.match_common), strna(w.match_boot),
                 strna(w.match_priority), strna(w.match_invocation), strna(w.match_message), strna(w.match_timestamp));

        const Format *used[ELEMENTSOF(formats)];
        Report reports[ELEMENTSOF(formats)] = {};
        size_t n = 0;

        FOREACH_ELEMENT(format, formats) {
                if (arg_formats && !strv_contains(arg_formats, format->name))
                        continue;

                log_info("Running format %s...", format->name);

                r = run_format(&w, format, reports + n);
                if (r < 0)
                        return r;

                used[n++] = format;
        }

        if (n == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No known format selected.");

        print_reports(&w, used, reports, n);

        for (size_t i = 1; arg_read && i < n; i++)
                for (size_t k = 0; k < ELEMENTSOF(read_tests); k++)
                        if (reports[i].read[k].digest != reports[0].read[k].digest ||
                            reports[i].read[k].n_results != reports[0].read[k].n_results)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Test %s returned different results for format %s than for format %s.",
                                                       read_tests[k].name, used[i]->name, used[0]->name);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
