/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nspawn-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(systemd_installation_has_version) {
        int r;

        FOREACH_STRING(version, "0", "231", STRINGIFY(PROJECT_VERSION), "999") {
                r = systemd_installation_has_version(saved_argv[1], version);
                assert_se(r >= 0);
                log_info("%s has systemd >= %s: %s",
                         saved_argv[1] ?: "Current installation", version, yes_no(r));
        }
}

/* This program can be called with a path to an installation root.
 * For example: build/test-nspawn-util /var/lib/machines/rawhide
 */
DEFINE_TEST_MAIN(LOG_DEBUG);
