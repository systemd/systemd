/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright 2018 Jonathan Rudenberg

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "alloc-util.h"
#include "log.h"
#include "fileio.h"
#include "fuzz.h"

/* This is a test driver for the systemd fuzzers that provides main function
 * for regression testing outside of oss-fuzz (https://github.com/google/oss-fuzz)
 *
 * It reads files named on the command line and passes them one by one into the
 * fuzzer that it is compiled into. */

int main(int argc, char **argv) {
        int i, r;
        size_t size;
        char *name;

        log_set_max_level(LOG_DEBUG);
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
                (void)LLVMFuzzerTestOneInput((uint8_t*)buf, size);
                printf("ok\n");
        }
        return EXIT_SUCCESS;
}
