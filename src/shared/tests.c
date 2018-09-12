/* SPDX-License-Identifier: LGPL-2.1+ */

#include <alloc-util.h>
#include <fs-util.h>
#include <libgen.h>
#include <stdlib.h>
#include <util.h>

#include "alloc-util.h"
#include "fileio.h"
#include "path-util.h"
#include "strv.h"
#include "tests.h"

char* setup_fake_runtime_dir(void) {
        char t[] = "/tmp/fake-xdg-runtime-XXXXXX", *p;

        assert_se(mkdtemp(t));
        assert_se(setenv("XDG_RUNTIME_DIR", t, 1) >= 0);
        assert_se(p = strdup(t));

        return p;
}

static void load_testdata_env(void) {
        static bool called = false;
        _cleanup_free_ char *s = NULL;
        _cleanup_free_ char *envpath = NULL;
        _cleanup_strv_free_ char **pairs = NULL;
        char **k, **v;

        if (called)
                return;
        called = true;

        assert_se(readlink_and_make_absolute("/proc/self/exe", &s) >= 0);
        dirname(s);

        envpath = path_join(NULL, s, "systemd-runtest.env");
        if (load_env_file_pairs(NULL, envpath, NULL, &pairs) < 0)
                return;

        STRV_FOREACH_PAIR(k, v, pairs)
                setenv(*k, *v, 0);
}

const char* get_testdata_dir(void) {
        const char *env;

        load_testdata_env();

        /* if the env var is set, use that */
        env = getenv("SYSTEMD_TEST_DATA");
        if (!env)
                env = SYSTEMD_TEST_DATA;
        if (access(env, F_OK) < 0) {
                fprintf(stderr, "ERROR: $SYSTEMD_TEST_DATA directory [%s] does not exist\n", env);
                exit(EXIT_FAILURE);
        }

        return env;
}

const char* get_catalog_dir(void) {
        const char *env;

        load_testdata_env();

        /* if the env var is set, use that */
        env = getenv("SYSTEMD_CATALOG_DIR");
        if (!env)
                env = SYSTEMD_CATALOG_DIR;
        if (access(env, F_OK) < 0) {
                fprintf(stderr, "ERROR: $SYSTEMD_CATALOG_DIR directory [%s] does not exist\n", env);
                exit(EXIT_FAILURE);
        }
        return env;
}
