/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "chattr-util.h"
#include "format-table.h"
#include "iovec-util.h"
#include "journal-file-util.h"
#include "log.h"
#include "mmap-cache.h"
#include "options.h"
#include "parse-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

static int journal_append_message(JournalFile *mj, const char *message) {
        struct iovec iovec;
        struct dual_timestamp ts;

        assert(mj);
        assert(message);

        dual_timestamp_now(&ts);
        iovec = IOVEC_MAKE_STRING(message);
        return journal_file_append_entry(
                                mj,
                                &ts,
                                /* boot_id= */ NULL,
                                &iovec,
                                /* n_iovec= */ 1,
                                /* seqnum= */ NULL,
                                /* seqnum_id= */ NULL,
                                /* ret_object= */ NULL,
                                /* ret_offset= */ NULL);
}

static int journal_corrupt_and_append(uint64_t start_offset, uint64_t step) {
        _cleanup_(mmap_cache_unrefp) MMapCache *mmap_cache = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tempdir = NULL;
        _cleanup_(journal_file_offline_closep) JournalFile *mj = NULL;
        uint64_t start, end;
        int r;

        ASSERT_NOT_NULL(mmap_cache = mmap_cache_new());

        /* journal_file_open() requires a valid machine id */
        if (sd_id128_get_machine(NULL) < 0)
                return log_tests_skipped("No valid machine ID found");

        ASSERT_OK(mkdtemp_malloc("/tmp/journal-append-XXXXXX", &tempdir));
        ASSERT_OK_ERRNO(chdir(tempdir));
        (void) chattr_path(tempdir, FS_NOCOW_FL, FS_NOCOW_FL);

        log_debug("Opening journal %s/system.journal", tempdir);

        r = journal_file_open(
                        /* fd= */ -EBADF,
                        "system.journal",
                        O_RDWR|O_CREAT,
                        JOURNAL_COMPRESS,
                        0644,
                        /* compress_threshold_bytes= */ UINT64_MAX,
                        /* metrics= */ NULL,
                        mmap_cache,
                        /* template= */ NULL,
                        &mj);
        if (r < 0)
                return log_error_errno(r, "Failed to open the journal: %m");

        ASSERT_NOT_NULL(mj);

        /* Add a couple of initial messages */
        for (int i = 0; i < 10; i++) {
                _cleanup_free_ char *message = NULL;

                ASSERT_OK_ERRNO(asprintf(&message, "MESSAGE=Initial message %d", i));
                r = journal_append_message(mj, message);
                if (r < 0)
                        return log_error_errno(r, "Failed to write to the journal: %m");
        }

        start = start_offset == UINT64_MAX ? random_u64() % mj->last_stat.st_size : start_offset;
        end = (uint64_t) mj->last_stat.st_size;

        /* Print the initial offset at which we start flipping bits, which can be
         * later used to reproduce a potential fail */
        log_info("Start offset: %" PRIu64 ", corrupt-step: %" PRIu64, start, step);
        fflush(stdout);

        if (start >= end)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Start offset >= journal size, can't continue");

        for (uint64_t offset = start; offset < end; offset += step) {
                _cleanup_free_ char *message = NULL;
                uint8_t b;

                /* Flip a bit in the journal file */
                ASSERT_EQ(pread(mj->fd, &b, 1, offset), 1);
                b |= 0x1;
                ASSERT_EQ(pwrite(mj->fd, &b, 1, offset), 1);

                /* Close and reopen the journal to flush all caches and remap
                 * the corrupted journal */
                mj = journal_file_offline_close(mj);
                r = journal_file_open(
                                /* fd= */ -EBADF,
                                "system.journal",
                                O_RDWR|O_CREAT,
                                JOURNAL_COMPRESS,
                                0644,
                                /* compress_threshold_bytes= */ UINT64_MAX,
                                /* metrics= */ NULL,
                                mmap_cache,
                                /* template= */ NULL,
                                &mj);
                if (r < 0) {
                        /* The corrupted journal might get rejected during reopening
                         * if it's corrupted enough (especially its header), so
                         * treat this as a success if it doesn't crash */
                        log_info_errno(r, "Failed to reopen the journal: %m");
                        break;
                }

                /* Try to write something to the (possibly corrupted) journal */
                ASSERT_OK_ERRNO(asprintf(&message, "MESSAGE=Hello world %" PRIu64, offset));
                r = journal_append_message(mj, message);
                if (r < 0) {
                        /* We care only about crashes or sanitizer errors,
                         * failing to write without any crash is a success */
                        log_info_errno(r, "Failed to write to the journal: %m");
                        break;
                }
        }

        return 0;
}

int main(int argc, char *argv[]) {
        uint64_t start_offset = UINT64_MAX;
        uint64_t iterations = 100;
        uint64_t iteration_step = 1;
        uint64_t corrupt_step = 31;
        bool sequential = false, run_one = false;
        int r;

        test_setup_logging(LOG_DEBUG);

        OptionParser state = { argc, argv };
        const char *arg;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP: {
                        _cleanup_(table_unrefp) Table *options = NULL;

                        r = option_parser_get_help_table(&options);
                        if (r < 0)
                                return r;

                        printf("Syntax:\n"
                               "  %s [OPTION...]\n"
                               "\nOptions:\n",
                               program_invocation_short_name);

                        r = table_print_or_warn(options);
                        if (r < 0)
                                return r;

                        return 0;
                }

                OPTION_LONG("start-offset", "OFFSET",
                            "Offset at which to start corrupting the journal "
                            "(default: random offset is picked, unless --sequential is used"
                            " - in that case we use 0 + iteration)"):
                        r = safe_atou64(arg, &start_offset);
                        if (r < 0)
                                return log_error_errno(r, "Invalid starting offset: %m");
                        break;

                OPTION_LONG("iterations", "ITER",
                            "Number of iterations to perform before exiting (default: 100)"):
                        r = safe_atou64(arg, &iterations);
                        if (r < 0)
                                return log_error_errno(r, "Invalid value for iterations: %m");
                        break;

                OPTION_LONG("corrupt-step", "STEP",
                            "Corrupt every n-th byte starting from OFFSET (default: 31)"):
                        r = safe_atou64(arg, &corrupt_step);
                        if (r < 0)
                                return log_error_errno(r, "Invalid value for corrupt-step: %m");
                        break;

                OPTION_LONG("iteration-step", "STEP", "Iteration step (default: 1)"):
                        r = safe_atou64(arg, &iteration_step);
                        if (r < 0)
                                return log_error_errno(r, "Invalid value for iteration-step: %m");
                        break;

                OPTION_LONG("sequential", NULL,
                            "Go through offsets sequentially instead of picking a random one on each iteration. "
                            "Goes through offsets [OFFSET, ITER) if --start-offset= is used, [0, ITER) otherwise "
                            "(default: false)"):
                        sequential = true;
                        break;

                OPTION_LONG("run-one", "OFFSET",
                            "Single shot mode for reproducing issues. "
                            "Takes the same offset as --start-offset= and does only one iteration"):
                        r = safe_atou64(arg, &start_offset);
                        if (r < 0)
                                return log_error_errno(r, "Invalid offset: %m");

                        run_one = true;
                        break;
                }

        if (run_one)
                /* Reproducer mode */
                return journal_corrupt_and_append(start_offset, corrupt_step);

        for (uint64_t i = 0; i < iterations; i++) {
                uint64_t offset = UINT64_MAX;

                log_info("Iteration #%" PRIu64 ", step: %" PRIu64, i, iteration_step);

                if (sequential)
                        offset = (start_offset == UINT64_MAX ? 0 : start_offset) + i * iteration_step;

                r = journal_corrupt_and_append(offset, corrupt_step);
                if (r < 0)
                        return EXIT_FAILURE;
                if (r > 0)
                        /* Reached the end of the journal file */
                        break;
        }

        return EXIT_SUCCESS;
}
