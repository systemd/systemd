/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "log.h"
#include "fileio.h"
#include "fuzz.h"
#include "tests.h"

/* This is a test driver for the systemd fuzzers that provides main function
 * for regression testing outside of oss-fuzz (https://github.com/google/oss-fuzz)
 *
 * It reads files named on the command line and passes them one by one into the
 * fuzzer that it is compiled into. */

int main(int argc, char **argv) {
        int i, r;
        size_t size;
        char *name;

        test_setup_logging(LOG_DEBUG);

        for (i = 1; i < argc; i++) {
                _cleanup_free_ char *buf = NULL;

                name = argv[i];
                r = read_full_file(name, &buf, &size);
                if (r < 0) {
                        log_error_errno(r, "Failed to open '%s': %m", name);
                        return EXIT_FAILURE;
                }
                printf("%s... ", name);
                fflush(stdout);
                (void) LLVMFuzzerTestOneInput((uint8_t*)buf, size);
                printf("ok\n");
        }

        return EXIT_SUCCESS;
}
