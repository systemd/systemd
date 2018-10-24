/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <util.h>

/* When we include libgen.h because we need dirname() we immediately
 * undefine basename() since libgen.h defines it as a macro to the POSIX
 * version which is really broken. We prefer GNU basename(). */
#include <libgen.h>
#undef basename

#include "alloc-util.h"
#include "env-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
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

bool slow_tests_enabled(void) {
        int r;

        r = getenv_bool("SYSTEMD_SLOW_TESTS");
        if (r >= 0)
                return r;

        if (r != -ENXIO)
                log_warning_errno(r, "Cannot parse $SYSTEMD_SLOW_TESTS, ignoring.");
        return SYSTEMD_SLOW_TESTS_DEFAULT;
}

void test_setup_logging(int level) {
        log_set_max_level(level);
        log_parse_environment();
        log_open();
}

int log_tests_skipped(const char *message) {
        log_notice("%s: %s, skipping tests.",
                   program_invocation_short_name, message);
        return EXIT_TEST_SKIP;
}

int log_tests_skipped_errno(int r, const char *message) {
        log_notice_errno(r, "%s: %s, skipping tests: %m",
                         program_invocation_short_name, message);
        return EXIT_TEST_SKIP;
}

bool have_namespaces(void) {
        siginfo_t si = {};
        pid_t pid;

        /* Checks whether namespaces are available. In some cases they aren't. We do this by calling unshare(), and we
         * do so in a child process in order not to affect our own process. */

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                /* child */
                if (unshare(CLONE_NEWNS) < 0)
                        _exit(EXIT_FAILURE);

                if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        assert_se(waitid(P_PID, pid, &si, WEXITED) >= 0);
        assert_se(si.si_code == CLD_EXITED);

        if (si.si_status == EXIT_SUCCESS)
                return true;

        if (si.si_status == EXIT_FAILURE)
                return false;

        assert_not_reached("unexpected exit code");
}
