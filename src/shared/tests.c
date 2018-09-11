/* SPDX-License-Identifier: LGPL-2.1+ */

#include <alloc-util.h>
#include <fs-util.h>
#include <libgen.h>
#include <stdlib.h>
#include <util.h>

#include "tests.h"
#include "path-util.h"

char* setup_fake_runtime_dir(void) {
        char t[] = "/tmp/fake-xdg-runtime-XXXXXX", *p;

        assert_se(mkdtemp(t));
        assert_se(setenv("XDG_RUNTIME_DIR", t, 1) >= 0);
        assert_se(p = strdup(t));

        return p;
}

bool test_is_running_from_builddir(char **exedir) {
        _cleanup_free_ char *s = NULL;
        bool r;

        /* Check if we're running from the builddir. Optionally, this returns
         * the path to the directory where the binary is located. */

        assert_se(readlink_and_make_absolute("/proc/self/exe", &s) >= 0);
        r = path_startswith(s, ABS_BUILD_DIR);

        if (exedir) {
                dirname(s);
                *exedir = TAKE_PTR(s);
        }

        return r;
}

const char* get_testdata_dir(const char *suffix) {
        const char *env;
        /* convenience: caller does not need to free result */
        static char testdir[PATH_MAX];

        /* if the env var is set, use that */
        env = getenv("SYSTEMD_TEST_DATA");
        testdir[sizeof(testdir) - 1] = '\0';
        if (env) {
                if (access(env, F_OK) < 0) {
                        fputs("ERROR: $SYSTEMD_TEST_DATA directory does not exist\n", stderr);
                        exit(EXIT_FAILURE);
                }
                strncpy(testdir, env, sizeof(testdir) - 1);
        } else {
                _cleanup_free_ char *exedir = NULL;

                /* Check if we're running from the builddir. If so, use the compiled in path. */
                if (test_is_running_from_builddir(&exedir))
                        assert_se(snprintf(testdir, sizeof(testdir), "%s/test", ABS_SRC_DIR) > 0);
                else
                        /* Try relative path, according to the install-test layout */
                        assert_se(snprintf(testdir, sizeof(testdir), "%s/testdata", exedir) > 0);

                /* test this without the suffix, as it may contain a glob */
                if (access(testdir, F_OK) < 0) {
                        fputs("ERROR: Cannot find testdata directory, set $SYSTEMD_TEST_DATA\n", stderr);
                        exit(EXIT_FAILURE);
                }
        }

        strncpy(testdir + strlen(testdir), suffix, sizeof(testdir) - strlen(testdir) - 1);
        return testdir;
}
