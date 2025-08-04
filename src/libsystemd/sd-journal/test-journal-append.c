/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

#include "chattr-util.h"
#include "iovec-util.h"
#include "journal-file-util.h"
#include "log.h"
#include "mmap-cache.h"
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

        mmap_cache = mmap_cache_new();
        assert_se(mmap_cache);

        /* journal_file_open() requires a valid machine id */
        if (sd_id128_get_machine(NULL) < 0)
                return log_tests_skipped("No valid machine ID found");

        assert_se(mkdtemp_malloc("/tmp/journal-append-XXXXXX", &tempdir) >= 0);
        assert_se(chdir(tempdir) >= 0);
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

        assert_se(mj);

        /* Add a couple of initial messages */
        for (int i = 0; i < 10; i++) {
                _cleanup_free_ char *message = NULL;

                assert_se(asprintf(&message, "MESSAGE=Initial message %d", i) >= 0);
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
                r = pread(mj->fd, &b, 1, offset);
                assert_se(r == 1);
                b |= 0x1;
                r = pwrite(mj->fd, &b, 1, offset);
                assert_se(r == 1);

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
                assert_se(asprintf(&message, "MESSAGE=Hello world %" PRIu64, offset) >= 0);
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
        int c, r;

        test_setup_logging(LOG_DEBUG);

        enum {
                ARG_START_OFFSET = 0x1000,
                ARG_ITERATIONS,
                ARG_ITERATION_STEP,
                ARG_CORRUPT_STEP,
                ARG_SEQUENTIAL,
                ARG_RUN_ONE,
        };

        static const struct option options[] = {
                { "help",                no_argument,       NULL, 'h'                     },
                { "start-offset",        required_argument, NULL, ARG_START_OFFSET        },
                { "iterations",          required_argument, NULL, ARG_ITERATIONS          },
                { "iteration-step",      required_argument, NULL, ARG_ITERATION_STEP      },
                { "corrupt-step",        required_argument, NULL, ARG_CORRUPT_STEP        },
                { "sequential",          no_argument,       NULL, ARG_SEQUENTIAL          },
                { "run-one",             required_argument, NULL, ARG_RUN_ONE             },
                {}
        };

        assert_se(argc >= 0);
        assert_se(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        printf("Syntax:\n"
                               "  %s [OPTION...]\n"
                               "Options:\n"
                               "    --start-offset=OFFSET   Offset at which to start corrupting the journal\n"
                               "                            (default: random offset is picked, unless\n"
                               "                            --sequential is used - in that case we use 0 + iteration)\n"
                               "    --iterations=ITER       Number of iterations to perform before exiting\n"
                               "                            (default: 100)\n"
                               "    --iteration-step=STEP   Iteration step (default: 1)\n"
                               "    --corrupt-step=STEP     Corrupt every n-th byte starting from OFFSET (default: 31)\n"
                               "    --sequential            Go through offsets sequentially instead of picking\n"
                               "                            a random one on each iteration. If set, we go through\n"
                               "                            offsets <0; ITER), or <OFFSET, ITER) if --start-offset=\n"
                               "                            is set (default: false)\n"
                               "    --run-one=OFFSET        Single shot mode for reproducing issues. Takes the same\n"
                               "                            offset as --start-offset= and does only one iteration\n"
                               , program_invocation_short_name);
                        return 0;

                case ARG_START_OFFSET:
                        r = safe_atou64(optarg, &start_offset);
                        if (r < 0)
                                return log_error_errno(r, "Invalid starting offset: %m");
                        break;

                case ARG_ITERATIONS:
                        r = safe_atou64(optarg, &iterations);
                        if (r < 0)
                                return log_error_errno(r, "Invalid value for iterations: %m");
                        break;

                case ARG_CORRUPT_STEP:
                        r = safe_atou64(optarg, &corrupt_step);
                        if (r < 0)
                                return log_error_errno(r, "Invalid value for corrupt-step: %m");
                        break;

                case ARG_ITERATION_STEP:
                        r = safe_atou64(optarg, &iteration_step);
                        if (r < 0)
                                return log_error_errno(r, "Invalid value for iteration-step: %m");
                        break;

                case ARG_SEQUENTIAL:
                        sequential = true;
                        break;

                case ARG_RUN_ONE:
                        r = safe_atou64(optarg, &start_offset);
                        if (r < 0)
                                return log_error_errno(r, "Invalid offset: %m");

                        run_one = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
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
