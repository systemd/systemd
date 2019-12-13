/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdlib.h>
#include <sys/stat.h>

#include "log.h"
#include "path-lookup.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static void test_paths(UnitFileScope scope) {
        char template[] = "/tmp/test-path-lookup.XXXXXXX";

        _cleanup_(lookup_paths_free) LookupPaths lp_without_env = {};
        _cleanup_(lookup_paths_free) LookupPaths lp_with_env = {};
        char *systemd_unit_path;

        assert_se(mkdtemp(template));

        assert_se(unsetenv("SYSTEMD_UNIT_PATH") == 0);
        assert_se(lookup_paths_init(&lp_without_env, scope, 0, NULL) >= 0);
        assert_se(!strv_isempty(lp_without_env.search_path));
        lookup_paths_log(&lp_without_env);

        systemd_unit_path = strjoina(template, "/systemd-unit-path");
        assert_se(setenv("SYSTEMD_UNIT_PATH", systemd_unit_path, 1) == 0);
        assert_se(lookup_paths_init(&lp_with_env, scope, 0, NULL) == 0);
        assert_se(strv_length(lp_with_env.search_path) == 1);
        assert_se(streq(lp_with_env.search_path[0], systemd_unit_path));
        lookup_paths_log(&lp_with_env);
        assert_se(strv_equal(lp_with_env.search_path, STRV_MAKE(systemd_unit_path)));

        assert_se(rm_rf(template, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

static void test_user_and_global_paths(void) {
        _cleanup_(lookup_paths_free) LookupPaths lp_global = {}, lp_user = {};
        char **u, **g, **p;
        unsigned k = 0;

        assert_se(unsetenv("SYSTEMD_UNIT_PATH") == 0);
        assert_se(unsetenv("XDG_DATA_DIRS") == 0);
        assert_se(unsetenv("XDG_CONFIG_DIRS") == 0);

        assert_se(lookup_paths_init(&lp_global, UNIT_FILE_GLOBAL, 0, NULL) == 0);
        assert_se(lookup_paths_init(&lp_user, UNIT_FILE_USER, 0, NULL) == 0);
        g = lp_global.search_path;
        u = lp_user.search_path;

        /* Go over all entries in global search path, and verify
         * that they also exist in the user search path. Skip any
         * entries in user search path which don't exist in the global
         * one, but not vice versa. */
        log_info("/* %s */", __func__);
        STRV_FOREACH(p, g) {
                while (u[k] && !streq(*p, u[k])) {
                        log_info("+ %s", u[k]);
                        k++;
                }
                log_info("  %s", *p);
                assert(u[k]); /* If NULL, we didn't find a matching entry */
                k++;
        }
        STRV_FOREACH(p, u + k)
                log_info("+ %s", *p);
}

static void print_generator_binary_paths(UnitFileScope scope) {
        _cleanup_strv_free_ char **paths;
        char **dir;

        log_info("Generators dirs (%s):", scope == UNIT_FILE_SYSTEM ? "system" : "user");

        paths = generator_binary_paths(scope);
        STRV_FOREACH(dir, paths)
                log_info("        %s", *dir);
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_paths(UNIT_FILE_SYSTEM);
        test_paths(UNIT_FILE_USER);
        test_paths(UNIT_FILE_GLOBAL);

        test_user_and_global_paths();

        print_generator_binary_paths(UNIT_FILE_SYSTEM);
        print_generator_binary_paths(UNIT_FILE_USER);

        return EXIT_SUCCESS;
}
