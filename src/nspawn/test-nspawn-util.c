/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nspawn-util.h"
#include "string-util.h"
#include "tests.h"

TEST(systemd_installation_has_version) {
        static const unsigned versions[] = {0, 231, PROJECT_VERSION, 999};
        int r;

        for (size_t i = 0; i < ELEMENTSOF(versions); i++) {
                r = systemd_installation_has_version(saved_argv[1], versions[i]);
                assert_se(r >= 0);
                log_info("%s has systemd >= %u: %s",
                         saved_argv[1] ?: "Current installation", versions[i], yes_no(r));
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
