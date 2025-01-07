/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "log.h"
#include "shift-uid.h"
#include "user-util.h"
#include "string-util.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        uid_t shift, range;
        int r;

        test_setup_logging(LOG_DEBUG);

        if (argc != 4) {
                log_error("Expected PATH SHIFT RANGE parameters.");
                return EXIT_FAILURE;
        }

        r = parse_uid(argv[2], &shift);
        if (r < 0) {
                log_error_errno(r, "Failed to parse UID shift %s.", argv[2]);
                return EXIT_FAILURE;
        }

        r = parse_gid(argv[3], &range);
        if (r < 0) {
                log_error_errno(r, "Failed to parse UID range %s.", argv[3]);
                return EXIT_FAILURE;
        }

        r = path_patch_uid(argv[1], shift, range);
        if (r < 0) {
                log_error_errno(r, "Failed to patch directory tree: %m");
                return EXIT_FAILURE;
        }

        log_info("Changed: %s", yes_no(r));

        return EXIT_SUCCESS;
}
