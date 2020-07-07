/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <util.h>

/* When we include libgen.h because we need dirname() we immediately
 * undefine basename() since libgen.h defines it as a macro to the POSIX
 * version which is really broken. We prefer GNU basename(). */
#include <libgen.h>
#undef basename

#include "alloc-util.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "env-file.h"
#include "env-util.h"
#include "fs-util.h"
#include "log.h"
#include "namespace-util.h"
#include "path-util.h"
#include "random-util.h"
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

        envpath = path_join(s, "systemd-runtest.env");
        if (load_env_file_pairs(NULL, envpath, &pairs) < 0)
                return;

        STRV_FOREACH_PAIR(k, v, pairs)
                setenv(*k, *v, 0);
}

int get_testdata_dir(const char *suffix, char **ret) {
        const char *dir;
        char *p;

        load_testdata_env();

        /* if the env var is set, use that */
        dir = getenv("SYSTEMD_TEST_DATA");
        if (!dir)
                dir = SYSTEMD_TEST_DATA;
        if (access(dir, F_OK) < 0)
                return log_error_errno(errno, "ERROR: $SYSTEMD_TEST_DATA directory [%s] not accessible: %m", dir);

        p = path_join(dir, suffix);
        if (!p)
                return log_oom();

        *ret = p;
        return 0;
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
                if (detach_mount_namespace() < 0)
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

bool can_memlock(void) {
        /* Let's see if we can mlock() a larger blob of memory. BPF programs are charged against
         * RLIMIT_MEMLOCK, hence let's first make sure we can lock memory at all, and skip the test if we
         * cannot. Why not check RLIMIT_MEMLOCK explicitly? Because in container environments the
         * RLIMIT_MEMLOCK value we see might not match the RLIMIT_MEMLOCK value actually in effect. */

        void *p = mmap(NULL, CAN_MEMLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);
        if (p == MAP_FAILED)
                return false;

        bool b = mlock(p, CAN_MEMLOCK_SIZE) >= 0;
        if (b)
                assert_se(munlock(p, CAN_MEMLOCK_SIZE) >= 0);

        assert_se(munmap(p, CAN_MEMLOCK_SIZE) >= 0);
        return b;
}

int enter_cgroup_subroot(char **ret_cgroup) {
        _cleanup_free_ char *cgroup_root = NULL, *cgroup_subroot = NULL;
        CGroupMask supported;
        int r;

        r = cg_pid_get_path(NULL, 0, &cgroup_root);
        if (r == -ENOMEDIUM)
                return log_warning_errno(r, "cg_pid_get_path(NULL, 0, ...) failed: %m");
        assert(r >= 0);

        assert_se(asprintf(&cgroup_subroot, "%s/%" PRIx64, cgroup_root, random_u64()) >= 0);
        assert_se(cg_mask_supported(&supported) >= 0);

        /* If this fails, then we don't mind as the later cgroup operations will fail too, and it's fine if
         * we handle any errors at that point. */

        r = cg_create_everywhere(supported, _CGROUP_MASK_ALL, cgroup_subroot);
        if (r < 0)
                return r;

        r = cg_attach_everywhere(supported, cgroup_subroot, 0, NULL, NULL);
        if (r < 0)
                return r;

        if (ret_cgroup)
                *ret_cgroup = TAKE_PTR(cgroup_subroot);
        return 0;
}
