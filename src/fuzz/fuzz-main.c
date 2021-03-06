/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fileio.h"
#include "fuzz.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"
#include "tests.h"

/* This is a test driver for the systemd fuzzers that provides main function
 * for regression testing outside of oss-fuzz (https://github.com/google/oss-fuzz)
 *
 * It reads files named on the command line and passes them one by one into the
 * fuzzer that it is compiled into. */

/* This one was borrowed from
 * https://github.com/google/oss-fuzz/blob/646fca1b506b056db3a60d32c4a1a7398f171c94/infra/base-images/base-runner/bad_build_check#L19
 */
#define NUMBER_OF_RUNS 4

int main(int argc, char **argv) {
        int r;

        test_setup_logging(LOG_DEBUG);

        unsigned number_of_runs = NUMBER_OF_RUNS;

        const char *v = getenv("SYSTEMD_FUZZ_RUNS");
        if (!isempty(v)) {
                r = safe_atou(v, &number_of_runs);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse SYSTEMD_FUZZ_RUNS=%s: %m", v);
        }

        for (int i = 1; i < argc; i++) {
                _cleanup_free_ char *buf = NULL;
                size_t size;
                char *name;

                name = argv[i];
                r = read_full_file(name, &buf, &size);
                if (r < 0) {
                        log_error_errno(r, "Failed to open '%s': %m", name);
                        return EXIT_FAILURE;
                }
                printf("%s... ", name);
                fflush(stdout);
                for (unsigned j = 0; j < number_of_runs; j++)
                        if (LLVMFuzzerTestOneInput((uint8_t*)buf, size) == EXIT_TEST_SKIP)
                                return EXIT_TEST_SKIP;
                printf("ok\n");
        }

        return EXIT_SUCCESS;
}
