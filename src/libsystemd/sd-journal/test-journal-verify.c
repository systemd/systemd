/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "ansi-color.h"
#include "chattr-util.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "journal-file-util.h"
#include "journal-verify.h"
#include "log.h"
#include "mmap-cache.h"
#include "rm-rf.h"
#include "strv.h"
#include "terminal-util.h"
#include "tests.h"

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
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        JournalFile *f;
        int r;

        m = mmap_cache_new();
        assert_se(m != NULL);

        r = journal_file_open(
                        /* fd= */ -EBADF,
                        fn,
                        O_RDONLY,
                        JOURNAL_COMPRESS|(verification_key ? JOURNAL_SEAL : 0),
                        0666,
                        /* compress_threshold_bytes= */ UINT64_MAX,
                        /* metrics= */ NULL,
                        m,
                        /* template= */ NULL,
                        &f);
        if (r < 0)
                return r;

        r = journal_file_verify(f, verification_key, NULL, NULL, NULL, false);
        (void) journal_file_close(f);

        return r;
}

static int run_test(const char *verification_key, ssize_t max_iterations) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        char t[] = "/var/tmp/journal-XXXXXX";
        struct stat st;
        JournalFile *f;
        JournalFile *df;
        usec_t from = 0, to = 0, total = 0;
        uint64_t start, end;
        int r;

        m = mmap_cache_new();
        assert_se(m != NULL);

        /* journal_file_open() requires a valid machine id */
        if (sd_id128_get_machine(NULL) < 0)
                return log_tests_skipped("No valid machine ID found");

        test_setup_logging(LOG_DEBUG);

        assert_se(mkdtemp(t));
        assert_se(chdir(t) >= 0);
        (void) chattr_path(t, FS_NOCOW_FL, FS_NOCOW_FL, NULL);

        log_info("Generating a test journal");

        assert_se(journal_file_open(
                                /* fd= */ -EBADF,
                                "test.journal",
                                O_RDWR|O_CREAT,
                                JOURNAL_COMPRESS|(verification_key ? JOURNAL_SEAL : 0),
                                0666,
                                /* compress_threshold_bytes= */ UINT64_MAX,
                                /* metrics= */ NULL,
                                m,
                                /* template= */ NULL,
                                &df) == 0);

        for (size_t n = 0; n < N_ENTRIES; n++) {
                _cleanup_free_ char *test = NULL;
                struct iovec iovec;
                struct dual_timestamp ts;

                dual_timestamp_now(&ts);
                assert_se(asprintf(&test, "RANDOM=%li", random() % RANDOM_RANGE));
                iovec = IOVEC_MAKE_STRING(test);
                assert_se(journal_file_append_entry(
                                        df,
                                        &ts,
                                        /* boot_id= */ NULL,
                                        &iovec,
                                        /* n_iovec= */ 1,
                                        /* seqnum= */ NULL,
                                        /* seqnum_id= */ NULL,
                                        /* ret_object= */ NULL,
                                        /* ret_offset= */ NULL) == 0);
        }

        (void) journal_file_offline_close(df);

        log_info("Verifying with key: %s", strna(verification_key));

        assert_se(journal_file_open(
                                /* fd= */ -EBADF,
                                "test.journal",
                                O_RDONLY,
                                JOURNAL_COMPRESS|(verification_key ? JOURNAL_SEAL : 0),
                                0666,
                                /* compress_threshold_bytes= */ UINT64_MAX,
                                /* metrics= */ NULL,
                                m,
                                /* template= */ NULL,
                                &f) == 0);
        journal_file_print_header(f);
        journal_file_dump(f);

        assert_se(journal_file_verify(f, verification_key, &from, &to, &total, true) >= 0);

        if (verification_key && JOURNAL_HEADER_SEALED(f->header))
                log_info("=> Validated from %s to %s, %s missing",
                         FORMAT_TIMESTAMP(from),
                         FORMAT_TIMESTAMP(to),
                         FORMAT_TIMESPAN(total > to ? total - to : 0, 0));

        (void) journal_file_close(f);
        assert_se(stat("test.journal", &st) >= 0);

        start = 38448 * 8 + 0;
        end = max_iterations < 0 ? (uint64_t)st.st_size * 8 : start + max_iterations;
        log_info("Toggling bits %"PRIu64 " to %"PRIu64, start, end);

        for (uint64_t p = start; p < end; p++) {
                bit_toggle("test.journal", p);

                if (max_iterations < 0)
                        log_info("[ %"PRIu64"+%"PRIu64"]", p / 8, p % 8);

                r = raw_verify("test.journal", verification_key);
                /* Suppress the notice when running in the limited (CI) mode */
                if (verification_key && max_iterations < 0 && r >= 0)
                        log_notice(ANSI_HIGHLIGHT_RED ">>>> %"PRIu64" (bit %"PRIu64") can be toggled without detection." ANSI_NORMAL, p / 8, p % 8);

                bit_toggle("test.journal", p);
        }

        assert_se(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);

        return 0;
}

int main(int argc, char *argv[]) {
        const char *verification_key = NULL;
        int max_iterations = 512;

        if (argc > 1) {
                /* Don't limit the number of iterations when the verification key
                 * is provided on the command line, we want to do that only in CIs */
                verification_key = argv[1];
                max_iterations = -1;
        }

        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1) >= 0);
        run_test(verification_key, max_iterations);

        assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1) >= 0);
        run_test(verification_key, max_iterations);

#if HAVE_GCRYPT
        /* If we're running without any arguments and we're compiled with gcrypt
         * check the journal verification stuff with a valid key as well */
        if (argc <= 1) {
                verification_key = "c262bd-85187f-0b1b04-877cc5/1c7af8-35a4e900";

                assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1) >= 0);
                run_test(verification_key, max_iterations);

                assert_se(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1) >= 0);
                run_test(verification_key, max_iterations);
        }
#endif

        return 0;
}
