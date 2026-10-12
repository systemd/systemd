/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "io-util.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-verify.h"
#include "mmap-cache.h"
#include "tmpfile-util.h"

#define ENTRIES_MAX 256U

static void make_file(char *name, const uint8_t *data, size_t size) {
        _cleanup_close_ int fd = -EBADF;

        /* sd_journal_open_files() refuses files without a name, so the input goes to a temporary file
         * instead of a memfd. */
        assert_se((fd = mkostemp_safe(name)) >= 0);
        assert_se(loop_write(fd, data, size) >= 0);
}

static void read_journal(const char *name) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_free_ char *cursor = NULL, *match = NULL;
        uint64_t realtime = 0, monotonic = 0;
        sd_id128_t boot_id = SD_ID128_NULL;
        const void *data;
        const char *field;
        size_t size, match_size = 0;
        unsigned n;

        if (sd_journal_open_files(&j, (const char*[]) { name, NULL }, 0) < 0)
                return;

        n = 0;
        SD_JOURNAL_FOREACH(j) {
                if (n++ >= ENTRIES_MAX)
                        break;

                (void) sd_journal_get_realtime_usec(j, &realtime);
                (void) sd_journal_get_monotonic_usec(j, &monotonic, &boot_id);

                SD_JOURNAL_FOREACH_DATA(j, data, size)
                        if (!match && size > 0 && size < 4096 && memchr(data, '=', size)) {
                                match = memdup(data, size);
                                match_size = size;
                        }

                if (!cursor)
                        (void) sd_journal_get_cursor(j, &cursor);
        }

        n = 0;
        SD_JOURNAL_FOREACH_BACKWARDS(j) {
                if (n++ >= ENTRIES_MAX)
                        break;

                (void) sd_journal_get_data(j, "MESSAGE", &data, &size);
        }

        if (sd_journal_seek_realtime_usec(j, realtime) >= 0) {
                (void) sd_journal_next(j);
                (void) sd_journal_previous_skip(j, 3);
        }

        if (sd_journal_seek_monotonic_usec(j, boot_id, monotonic) >= 0) {
                (void) sd_journal_previous(j);
                (void) sd_journal_next_skip(j, 3);
        }

        if (cursor && sd_journal_seek_cursor(j, cursor) >= 0) {
                (void) sd_journal_next(j);
                (void) sd_journal_test_cursor(j, cursor);
        }

        if (match && sd_journal_add_match(j, match, match_size) >= 0) {
                n = 0;
                SD_JOURNAL_FOREACH(j)
                        if (n++ >= ENTRIES_MAX)
                                break;

                (void) sd_journal_add_disjunction(j);
                (void) sd_journal_add_match(j, "PRIORITY=6", SIZE_MAX);
                (void) sd_journal_add_conjunction(j);
                (void) sd_journal_add_match(j, "_BOOT_ID=00000000000000000000000000000000", SIZE_MAX);

                n = 0;
                SD_JOURNAL_FOREACH_BACKWARDS(j)
                        if (n++ >= ENTRIES_MAX)
                                break;

                if (sd_journal_seek_monotonic_usec(j, boot_id, monotonic) >= 0)
                        (void) sd_journal_next(j);

                sd_journal_flush_matches(j);

                _cleanup_free_ char *unique = memdup_suffix0(match, (const char*) memchr(match, '=', match_size) - match);
                if (unique && sd_journal_query_unique(j, unique) >= 0) {
                        n = 0;
                        SD_JOURNAL_FOREACH_UNIQUE(j, data, size)
                                if (n++ >= ENTRIES_MAX)
                                        break;
                }
        }

        n = 0;
        SD_JOURNAL_FOREACH_FIELD(j, field)
                if (n++ >= ENTRIES_MAX)
                        break;
}

static void verify_journal(MMapCache *m, const char *name) {
        JournalFile *f = NULL;

        if (journal_file_open(-EBADF, name, O_RDONLY, 0, 0, UINT64_MAX, NULL, m, NULL, &f) < 0)
                return;

        (void) journal_file_verify(f, NULL, NULL, NULL, NULL, /* show_progress= */ false);
        (void) journal_file_close(f);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/fuzz-journal-file.XXXXXX";

        if (outside_size_range(size, sizeof(Header), 1024 * 1024))
                return 0;

        fuzz_setup_logging();

        assert_se(m = mmap_cache_new());

        make_file(name, data, size);
        read_journal(name);
        verify_journal(m, name);

        return 0;
}
