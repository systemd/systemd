/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "chattr-util.h"
#include "iovec-util.h"
#include "journal-file-util.h"
#include "journal-internal.h"
#include "parse-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "time-util.h"

#define N_ENTRIES 200u

static void verify_contents(sd_journal *j, unsigned skip) {
        unsigned i;

        ASSERT_NOT_NULL(j);

        i = 0;
        SD_JOURNAL_FOREACH(j) {
                const void *d;
                char *k, *c;
                size_t l;
                unsigned u = 0;

                ASSERT_OK(sd_journal_get_cursor(j, &k));
                printf("cursor: %s\n", k);
                free(k);

                ASSERT_OK(sd_journal_get_data(j, "MAGIC", &d, &l));
                printf("\t%.*s\n", (int) l, (const char*) d);

                ASSERT_OK(sd_journal_get_data(j, "NUMBER", &d, &l));
                ASSERT_NOT_NULL(k = strndup(d, l));
                printf("\t%s\n", k);

                if (skip > 0) {
                        ASSERT_OK(safe_atou(k + 7, &u));
                        ASSERT_EQ(i, u);
                        i += skip;
                }

                free(k);

                ASSERT_OK(sd_journal_get_cursor(j, &c));
                ASSERT_OK_POSITIVE(sd_journal_test_cursor(j, c));
                free(c);
        }

        if (skip > 0)
                ASSERT_EQ(i, N_ENTRIES);
}

static void run_test(void) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        JournalFile *one, *two, *three;
        char t[] = "/var/tmp/journal-stream-XXXXXX";
        unsigned i;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        char *z;
        const void *data;
        size_t l;
        dual_timestamp previous_ts = DUAL_TIMESTAMP_NULL;

        ASSERT_NOT_NULL(m = mmap_cache_new());

        ASSERT_NOT_NULL(mkdtemp(t));
        ASSERT_OK_ERRNO(chdir(t));
        (void) chattr_path(t, FS_NOCOW_FL, FS_NOCOW_FL);

        ASSERT_OK_ZERO(journal_file_open(-EBADF, "one.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0666, UINT64_MAX, NULL, m, NULL, &one));
        ASSERT_OK_ZERO(journal_file_open(-EBADF, "two.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0666, UINT64_MAX, NULL, m, NULL, &two));
        ASSERT_OK_ZERO(journal_file_open(-EBADF, "three.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0666, UINT64_MAX, NULL, m, NULL, &three));

        for (i = 0; i < N_ENTRIES; i++) {
                char *p, *q;
                dual_timestamp ts;
                struct iovec iovec[2];

                dual_timestamp_now(&ts);

                if (ts.monotonic <= previous_ts.monotonic)
                        ts.monotonic = previous_ts.monotonic + 1;

                if (ts.realtime <= previous_ts.realtime)
                        ts.realtime = previous_ts.realtime + 1;

                previous_ts = ts;

                ASSERT_OK_ERRNO(asprintf(&p, "NUMBER=%u", i));
                iovec[0] = IOVEC_MAKE(p, strlen(p));

                ASSERT_OK_ERRNO(asprintf(&q, "MAGIC=%s", i % 5 == 0 ? "quux" : "waldo"));

                iovec[1] = IOVEC_MAKE(q, strlen(q));

                if (i % 10 == 0)
                        ASSERT_OK_ZERO(journal_file_append_entry(three, &ts, NULL, iovec, 2, NULL, NULL, NULL, NULL));
                else {
                        if (i % 3 == 0)
                                ASSERT_OK_ZERO(journal_file_append_entry(two, &ts, NULL, iovec, 2, NULL, NULL, NULL, NULL));

                        ASSERT_OK_ZERO(journal_file_append_entry(one, &ts, NULL, iovec, 2, NULL, NULL, NULL, NULL));
                }

                free(p);
                free(q);
        }

        (void) journal_file_offline_close(one);
        (void) journal_file_offline_close(two);
        (void) journal_file_offline_close(three);

        ASSERT_OK(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE));

        ASSERT_OK(sd_journal_add_match(j, "MAGIC=quux", SIZE_MAX));
        SD_JOURNAL_FOREACH_BACKWARDS(j) {
                _cleanup_free_ char *c;

                ASSERT_OK(sd_journal_get_data(j, "NUMBER", &data, &l));
                printf("\t%.*s\n", (int) l, (const char*) data);

                ASSERT_OK(sd_journal_get_cursor(j, &c));
                ASSERT_OK_POSITIVE(sd_journal_test_cursor(j, c));
        }

        SD_JOURNAL_FOREACH(j) {
                _cleanup_free_ char *c;

                ASSERT_OK(sd_journal_get_data(j, "NUMBER", &data, &l));
                printf("\t%.*s\n", (int) l, (const char*) data);

                ASSERT_OK(sd_journal_get_cursor(j, &c));
                ASSERT_OK_POSITIVE(sd_journal_test_cursor(j, c));
        }

        sd_journal_flush_matches(j);

        verify_contents(j, 1);

        printf("NEXT TEST\n");
        ASSERT_OK(sd_journal_add_match(j, "MAGIC=quux", SIZE_MAX));

        ASSERT_NOT_NULL(z = journal_make_match_string(j));
        printf("resulting match expression is: %s\n", z);
        free(z);

        verify_contents(j, 5);

        printf("NEXT TEST\n");
        sd_journal_flush_matches(j);
        ASSERT_OK(sd_journal_add_match(j, "MAGIC=waldo", SIZE_MAX));
        ASSERT_OK(sd_journal_add_match(j, "NUMBER=10", SIZE_MAX));
        ASSERT_OK(sd_journal_add_match(j, "NUMBER=11", SIZE_MAX));
        ASSERT_OK(sd_journal_add_match(j, "NUMBER=12", SIZE_MAX));

        ASSERT_NOT_NULL(z = journal_make_match_string(j));
        printf("resulting match expression is: %s\n", z);
        free(z);

        verify_contents(j, 0);

        ASSERT_OK(sd_journal_query_unique(j, "NUMBER"));
        SD_JOURNAL_FOREACH_UNIQUE(j, data, l)
                printf("%.*s\n", (int) l, (const char*) data);

        ASSERT_OK(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL));
}

int main(int argc, char *argv[]) {

        /* journal_file_open() requires a valid machine id */
        if (access("/etc/machine-id", F_OK) != 0)
                return log_tests_skipped("/etc/machine-id not found");

        test_setup_logging(LOG_DEBUG);

        /* Run this test multiple times with different configurations of features. */

        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_KEYED_HASH", "0", 1));
        run_test();

        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_KEYED_HASH", "1", 1));
        run_test();

        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1));
        run_test();

        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1));
        run_test();

        return 0;
}
