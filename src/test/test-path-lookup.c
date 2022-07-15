/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>

#include "log.h"
#include "path-lookup.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_paths_one(LookupScope scope) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_(lookup_paths_free) LookupPaths lp_without_env = {};
        _cleanup_(lookup_paths_free) LookupPaths lp_with_env = {};
        char *systemd_unit_path;

        assert_se(mkdtemp_malloc("/tmp/test-path-lookup.XXXXXXX", &tmp) >= 0);

        assert_se(unsetenv("SYSTEMD_UNIT_PATH") == 0);
        assert_se(lookup_paths_init(&lp_without_env, scope, 0, NULL) >= 0);
        assert_se(!strv_isempty(lp_without_env.search_path));
        lookup_paths_log(&lp_without_env);

        systemd_unit_path = strjoina(tmp, "/systemd-unit-path");
        assert_se(setenv("SYSTEMD_UNIT_PATH", systemd_unit_path, 1) == 0);
        assert_se(lookup_paths_init(&lp_with_env, scope, 0, NULL) == 0);
        assert_se(strv_length(lp_with_env.search_path) == 1);
        assert_se(streq(lp_with_env.search_path[0], systemd_unit_path));
        lookup_paths_log(&lp_with_env);
        assert_se(strv_equal(lp_with_env.search_path, STRV_MAKE(systemd_unit_path)));
}

TEST(paths) {
        test_paths_one(LOOKUP_SCOPE_SYSTEM);
        test_paths_one(LOOKUP_SCOPE_USER);
        test_paths_one(LOOKUP_SCOPE_GLOBAL);
}

TEST(user_and_global_paths) {
        _cleanup_(lookup_paths_free) LookupPaths lp_global = {}, lp_user = {};
        char **u, **g;
        unsigned k = 0;

        assert_se(unsetenv("SYSTEMD_UNIT_PATH") == 0);
        assert_se(unsetenv("XDG_DATA_DIRS") == 0);
        assert_se(unsetenv("XDG_CONFIG_DIRS") == 0);

        assert_se(lookup_paths_init(&lp_global, LOOKUP_SCOPE_GLOBAL, 0, NULL) == 0);
        assert_se(lookup_paths_init(&lp_user, LOOKUP_SCOPE_USER, 0, NULL) == 0);
        g = lp_global.search_path;
        u = lp_user.search_path;

        /* Go over all entries in global search path, and verify
         * that they also exist in the user search path. Skip any
         * entries in user search path which don't exist in the global
         * one, but not vice versa. */
        STRV_FOREACH(p, g) {
                while (u[k] && !streq(*p, u[k])) {
                        log_info("+ %s", u[k]);
                        k++;
                }
                log_info("  %s", *p);
                assert_se(u[k]); /* If NULL, we didn't find a matching entry */
                k++;
        }
        STRV_FOREACH(p, u + k)
                log_info("+ %s", *p);
}

static void test_generator_binary_paths_one(LookupScope scope) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_strv_free_ char **gp_without_env = NULL;
        _cleanup_strv_free_ char **env_gp_without_env = NULL;
        _cleanup_strv_free_ char **gp_with_env = NULL;
        _cleanup_strv_free_ char **env_gp_with_env = NULL;
        char *systemd_generator_path = NULL;
        char *systemd_env_generator_path = NULL;

        assert_se(mkdtemp_malloc("/tmp/test-path-lookup.XXXXXXX", &tmp) >= 0);

        assert_se(unsetenv("SYSTEMD_GENERATOR_PATH") == 0);
        assert_se(unsetenv("SYSTEMD_ENVIRONMENT_GENERATOR_PATH") == 0);

        gp_without_env = generator_binary_paths(scope);
        env_gp_without_env = env_generator_binary_paths(scope == LOOKUP_SCOPE_SYSTEM ? true : false);

        log_info("Generators dirs (%s):", scope == LOOKUP_SCOPE_SYSTEM ? "system" : "user");
        STRV_FOREACH(dir, gp_without_env)
                log_info("        %s", *dir);

        log_info("Environment generators dirs (%s):", scope == LOOKUP_SCOPE_SYSTEM ? "system" : "user");
        STRV_FOREACH(dir, env_gp_without_env)
                log_info("        %s", *dir);

        assert_se(!strv_isempty(gp_without_env));
        assert_se(!strv_isempty(env_gp_without_env));

        systemd_generator_path = strjoina(tmp, "/systemd-generator-path");
        systemd_env_generator_path = strjoina(tmp, "/systemd-environment-generator-path");
        assert_se(setenv("SYSTEMD_GENERATOR_PATH", systemd_generator_path, 1) == 0);
        assert_se(setenv("SYSTEMD_ENVIRONMENT_GENERATOR_PATH", systemd_env_generator_path, 1) == 0);

        gp_with_env = generator_binary_paths(scope);
        env_gp_with_env = env_generator_binary_paths(scope == LOOKUP_SCOPE_SYSTEM ? true : false);

        log_info("Generators dirs (%s):", scope == LOOKUP_SCOPE_SYSTEM ? "system" : "user");
        STRV_FOREACH(dir, gp_with_env)
                log_info("        %s", *dir);

        log_info("Environment generators dirs (%s):", scope == LOOKUP_SCOPE_SYSTEM ? "system" : "user");
        STRV_FOREACH(dir, env_gp_with_env)
                log_info("        %s", *dir);

        assert_se(strv_equal(gp_with_env, STRV_MAKE(systemd_generator_path)));
        assert_se(strv_equal(env_gp_with_env, STRV_MAKE(systemd_env_generator_path)));
}

TEST(generator_binary_paths) {
        test_generator_binary_paths_one(LOOKUP_SCOPE_SYSTEM);
        test_generator_binary_paths_one(LOOKUP_SCOPE_USER);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
