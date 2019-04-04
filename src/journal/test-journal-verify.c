/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "chattr-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "journal-file.h"
#include "journal-verify.h"
#include "log.h"
#include "rm-rf.h"
#include "terminal-util.h"
#include "tests.h"
#include "util.h"

#define N_ENTRIES 6000
#define RANDOM_RANGE 77

static void bit_toggle(const char *fn, uint64_t p) {
        uint8_t b;
        ssize_t r;
        int fd;

        fd = open(fn, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        r = pread(fd, &b, 1, p/8);
        assert_se(r == 1);

        b ^= 1 << (p % 8);

        r = pwrite(fd, &b, 1, p/8);
        assert_se(r == 1);

        safe_close(fd);
}

static int raw_verify(const char *fn, const char *verification_key) {
        JournalFile *f;
        int r;

        r = journal_file_open(-1, fn, O_RDONLY, 0666, true, (uint64_t) -1, !!verification_key, NULL, NULL, NULL, NULL, &f);
        if (r < 0)
                return r;

        r = journal_file_verify(f, verification_key, NULL, NULL, NULL, false);
        (void) journal_file_close(f);

        return r;
}

int main(int argc, char *argv[]) {
        char t[] = "/var/tmp/journal-XXXXXX";
        unsigned n;
        JournalFile *f;
        const char *verification_key = argv[1];
        usec_t from = 0, to = 0, total = 0;
        char a[FORMAT_TIMESTAMP_MAX];
        char b[FORMAT_TIMESTAMP_MAX];
        char c[FORMAT_TIMESPAN_MAX];
        struct stat st;
        uint64_t p;

        /* journal_file_open requires a valid machine id */
        if (access("/etc/machine-id", F_OK) != 0)
                return log_tests_skipped("/etc/machine-id not found");

        test_setup_logging(LOG_DEBUG);

        assert_se(mkdtemp(t));
        assert_se(chdir(t) >= 0);
        (void) chattr_path(t, FS_NOCOW_FL, FS_NOCOW_FL, NULL);

        log_info("Generating...");

        assert_se(journal_file_open(-1, "test.journal", O_RDWR|O_CREAT, 0666, true, (uint64_t) -1, !!verification_key, NULL, NULL, NULL, NULL, &f) == 0);

        for (n = 0; n < N_ENTRIES; n++) {
                struct iovec iovec;
                struct dual_timestamp ts;
                char *test;

                dual_timestamp_get(&ts);

                assert_se(asprintf(&test, "RANDOM=%lu", random() % RANDOM_RANGE));

                iovec = IOVEC_MAKE_STRING(test);

                assert_se(journal_file_append_entry(f, &ts, NULL, &iovec, 1, NULL, NULL, NULL) == 0);

                free(test);
        }

        (void) journal_file_close(f);

        log_info("Verifying...");

        assert_se(journal_file_open(-1, "test.journal", O_RDONLY, 0666, true, (uint64_t) -1, !!verification_key, NULL, NULL, NULL, NULL, &f) == 0);
        /* journal_file_print_header(f); */
        journal_file_dump(f);

        assert_se(journal_file_verify(f, verification_key, &from, &to, &total, true) >= 0);

        if (verification_key && JOURNAL_HEADER_SEALED(f->header))
                log_info("=> Validated from %s to %s, %s missing",
                         format_timestamp(a, sizeof(a), from),
                         format_timestamp(b, sizeof(b), to),
                         format_timespan(c, sizeof(c), total > to ? total - to : 0, 0));

        (void) journal_file_close(f);

        if (verification_key) {
                log_info("Toggling bits...");

                assert_se(stat("test.journal", &st) >= 0);

                for (p = 38448*8+0; p < ((uint64_t) st.st_size * 8); p ++) {
                        bit_toggle("test.journal", p);

                        log_info("[ %"PRIu64"+%"PRIu64"]", p / 8, p % 8);

                        if (raw_verify("test.journal", verification_key) >= 0)
                                log_notice(ANSI_HIGHLIGHT_RED ">>>> %"PRIu64" (bit %"PRIu64") can be toggled without detection." ANSI_NORMAL, p / 8, p % 8);

                        bit_toggle("test.journal", p);
                }
        }

        log_info("Exiting...");

        assert_se(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);

        return 0;
}
