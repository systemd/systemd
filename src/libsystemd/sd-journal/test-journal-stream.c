/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "chattr-util.h"
#include "iovec-util.h"
#include "journal-file-util.h"
#include "journal-internal.h"
#include "log.h"
#include "parse-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "time-util.h"

#define N_ENTRIES 200

static void verify_contents(sd_journal *j, unsigned skip) {
        unsigned i;

        assert_se(j);

        i = 0;
        SD_JOURNAL_FOREACH(j) {
                const void *d;
                char *k, *c;
                size_t l;
                unsigned u = 0;

                assert_se(sd_journal_get_cursor(j, &k) >= 0);
                printf("cursor: %s\n", k);
                free(k);

                assert_se(sd_journal_get_data(j, "MAGIC", &d, &l) >= 0);
                printf("\t%.*s\n", (int) l, (const char*) d);

                assert_se(sd_journal_get_data(j, "NUMBER", &d, &l) >= 0);
                assert_se(k = strndup(d, l));
                printf("\t%s\n", k);

                if (skip > 0) {
                        assert_se(safe_atou(k + 7, &u) >= 0);
                        assert_se(i == u);
                        i += skip;
                }

                free(k);

                assert_se(sd_journal_get_cursor(j, &c) >= 0);
                assert_se(sd_journal_test_cursor(j, c) > 0);
                free(c);
        }

        if (skip > 0)
                assert_se(i == N_ENTRIES);
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

        m = mmap_cache_new();
        assert_se(m != NULL);

        assert_se(mkdtemp(t));
        assert_se(chdir(t) >= 0);
        (void) chattr_path(t, FS_NOCOW_FL, FS_NOCOW_FL);

        assert_se(journal_file_open(-EBADF, "one.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0666, UINT64_MAX, NULL, m, NULL, &one) == 0);
        assert_se(journal_file_open(-EBADF, "two.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0666, UINT64_MAX, NULL, m, NULL, &two) == 0);
        assert_se(journal_file_open(-EBADF, "three.journal", O_RDWR|O_CREAT, JOURNAL_COMPRESS, 0666, UINT64_MAX, NULL, m, NULL, &three) == 0);

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

                assert_se(asprintf(&p, "NUMBER=%u", i) >= 0);
                iovec[0] = IOVEC_MAKE(p, strlen(p));

                assert_se(asprintf(&q, "MAGIC=%s", i % 5 == 0 ? "quux" : "waldo") >= 0);

                iovec[1] = IOVEC_MAKE(q, strlen(q));

                if (i % 10 == 0)
                        assert_se(journal_file_append_entry(three, &ts, NULL, iovec, 2, NULL, NULL, NULL, NULL) == 0);
                else {
                        if (i % 3 == 0)
                                assert_se(journal_file_append_entry(two, &ts, NULL, iovec, 2, NULL, NULL, NULL, NULL) == 0);

                        assert_se(journal_file_append_entry(one, &ts, NULL, iovec, 2, NULL, NULL, NULL, NULL) == 0);
                }

                free(p);
                free(q);
        }

        (void) journal_file_offline_close(one);
        (void) journal_file_offline_close(two);
        (void) journal_file_offline_close(three);

        assert_se(sd_journal_open_directory(&j, t, SD_JOURNAL_ASSUME_IMMUTABLE) >= 0);

        assert_se(sd_journal_add_match(j, "MAGIC=quux", SIZE_MAX) >= 0);
        SD_JOURNAL_FOREACH_BACKWARDS(j) {
                _cleanup_free_ char *c;

                assert_se(sd_journal_get_data(j, "NUMBER", &data, &l) >= 0);
                printf("\t%.*s\n", (int) l, (const char*) data);

                assert_se(sd_journal_get_cursor(j, &c) >= 0);
                assert_se(sd_journal_test_cursor(j, c) > 0);
        }

        SD_JOURNAL_FOREACH(j) {
                _cleanup_free_ char *c;

                assert_se(sd_journal_get_data(j, "NUMBER", &data, &l) >= 0);
                printf("\t%.*s\n", (int) l, (const char*) data);

                assert_se(sd_journal_get_cursor(j, &c) >= 0);
                assert_se(sd_journal_test_cursor(j, c) > 0);
        }

        sd_journal_flush_matches(j);

        verify_contents(j, 1);

        printf("NEXT TEST\n");
        assert_se(sd_journal_add_match(j, "MAGIC=quux", SIZE_MAX) >= 0);

        assert_se(z = journal_make_match_string(j));
        printf("resulting match expression is: %s\n", z);
        free(z);

        verify_contents(j, 5);

        printf("NEXT TEST\n");
        sd_journal_flush_matches(j);
        assert_se(sd_journal_add_match(j, "MAGIC=waldo", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "NUMBER=10", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "NUMBER=11", SIZE_MAX) >= 0);
        assert_se(sd_journal_add_match(j, "NUMBER=12", SIZE_MAX) >= 0);

        assert_se(z = journal_make_match_string(j));
        printf("resulting match expression is: %s\n", z);
        free(z);

        verify_contents(j, 0);

        assert_se(sd_journal_query_unique(j, "NUMBER") >= 0);
        SD_JOURNAL_FOREACH_UNIQUE(j, data, l)
                printf("%.*s\n", (int) l, (const char*) data);

        assert_se(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

int main(int argc, char *argv[]) {

        /* journal_file_open() requires a valid machine id */
        if (access("/etc/machine-id", F_OK) != 0)
                return log_tests_skipped("/etc/machine-id not found");

        test_setup_logging(LOG_DEBUG);

        /* Run this test multiple times with different configurations of features. */

        assert_se(setenv("SYSTEMD_JOURNAL_KEYED_HASH", "0", 1) >= 0);
        run_test();

        assert_se(setenv("SYSTEMD_JOURNAL_KEYED_HASH", "1", 1) >= 0);
        run_test();

        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1) >= 0);
        run_test();

        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1) >= 0);
        run_test();

        return 0;
}
