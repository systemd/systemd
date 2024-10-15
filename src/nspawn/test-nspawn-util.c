/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nspawn-util.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(systemd_installation_has_version) {
        int r;

        FOREACH_STRING(version, "0", "231", PROJECT_VERSION_FULL, "999") {
                r = systemd_installation_has_version(saved_argv[1], version);
                /* The build environment may not have a systemd installation. */
                if (r == -ENOENT)
                        continue;
                ASSERT_OK(r);
                log_info("%s has systemd >= %s: %s",
                         saved_argv[1] ?: "Current installation", version, yes_no(r));
        }

        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        ASSERT_OK(mkdtemp_malloc(NULL, &t));

        ASSERT_ERROR(systemd_installation_has_version(t, PROJECT_VERSION_FULL), ENOENT);
}

/* This program can be called with a path to an installation root.
 * For example: build/test-nspawn-util /var/lib/machines/rawhide
 */
DEFINE_TEST_MAIN(LOG_DEBUG);
