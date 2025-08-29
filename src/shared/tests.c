/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"

#include "alloc-util.h"
#include "argv-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "coredump-util.h"
#include "env-file.h"
#include "env-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "namespace-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "random-util.h"
#include "rlimit-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "uid-range.h"

char* setup_fake_runtime_dir(void) {
        char *t;

        ASSERT_OK(mkdtemp_malloc("/tmp/fake-xdg-runtime-XXXXXX", &t));
        ASSERT_OK(setenv("XDG_RUNTIME_DIR", t, /* overwrite = */ true));
        return t;
}

static void load_testdata_env(void) {
        static bool called = false;
        _cleanup_free_ char *s = NULL, *d = NULL, *envpath = NULL;
        _cleanup_strv_free_ char **pairs = NULL;
        int r;

        if (called)
                return;
        called = true;

        ASSERT_OK(readlink_and_make_absolute("/proc/self/exe", &s));
        ASSERT_OK(path_extract_directory(s, &d));
        ASSERT_NOT_NULL(envpath = path_join(d, "systemd-runtest.env"));

        r = load_env_file_pairs(NULL, envpath, &pairs);
        if (r < 0) {
                log_debug_errno(r, "Reading %s failed, ignoring: %m", envpath);
                return;
        }

        STRV_FOREACH_PAIR(k, v, pairs)
                ASSERT_OK(setenv(*k, *v, /* overwrite = */ false));
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
        log_set_assert_return_is_critical(true);
        log_set_max_level(level);
        log_setup();
}

int write_tmpfile(char *pattern, const char *contents) {
        _cleanup_close_ int fd = -EBADF;

        assert(pattern);
        assert(contents);

        fd = mkostemp_safe(pattern);
        if (fd < 0)
                return fd;

        ssize_t l = strlen(contents);
        errno = 0;
        if (write(fd, contents, l) != l)
                return errno_or_else(EIO);
        return 0;
}

bool have_namespaces(void) {
        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        int r;

        /* Checks whether namespaces are available. In some cases they aren't. We do this by calling unshare(), and we
         * do so in a child process in order not to affect our own process. */

        ASSERT_OK(r = pidref_safe_fork("(have_namespace)", /* flags = */ 0, &pid));
        if (r == 0) {
                /* child */
                if (detach_mount_namespace() < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(r = pidref_wait_for_terminate_and_check("(have_namespace)", &pid, /* flags = */ 0));
        if (r == EXIT_SUCCESS)
                return true;

        if (r == EXIT_FAILURE)
                return false;

        assert_not_reached();
}

bool userns_has_single_user(void) {
        _cleanup_(uid_range_freep) UIDRange *uidrange = NULL, *gidrange = NULL;

        /* Check if we're in a user namespace with only a single user mapped in. We special case this
         * scenario in a few tests because it's the only kind of namespace that can be created unprivileged
         * and as such happens more often than not, so we make sure to deal with it so that all tests pass
         * in such environments. */

        if (uid_range_load_userns(NULL, UID_RANGE_USERNS_INSIDE, &uidrange) < 0)
                return false;

        if (uid_range_load_userns(NULL, GID_RANGE_USERNS_INSIDE, &gidrange) < 0)
                return false;

        return uidrange->n_entries == 1 && uidrange->entries[0].nr == 1 &&
                gidrange->n_entries == 1 && gidrange->entries[0].nr == 1;
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
                ASSERT_OK(munlock(p, CAN_MEMLOCK_SIZE));

        ASSERT_OK(munmap(p, CAN_MEMLOCK_SIZE));
        return b;
}

static int allocate_scope(void) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *scope = NULL, *cgroup_root = NULL;
        const char *object;
        int r;

        /* Let's try to run this test in a scope of its own, with delegation turned on, so that PID 1 doesn't
         * interfere with our cgroup management. */
        if (cg_pid_get_path(NULL, 0, &cgroup_root) >= 0 && cg_is_delegated(cgroup_root) && stderr_is_journal()) {
                log_debug("Already running as a unit with delegated cgroup, not allocating a cgroup subroot.");
                return 0;
        }

        if (geteuid() == 0)
                r = sd_bus_default_system(&bus);
        else
                r = sd_bus_default_user(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        if (asprintf(&scope, "%s-%" PRIx64 ".scope", program_invocation_short_name, random_u64()) < 0)
                return log_oom();

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        /* Name and Mode */
        r = sd_bus_message_append(m, "ss", scope, "fail");
        if (r < 0)
                return bus_log_create_error(r);

        /* Properties */
        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, (uint32_t) getpid_cached());
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "(sv)", "Delegate", "b", 1);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "(sv)", "CollectMode", "s", "inactive-or-failed");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        /* Auxiliary units */
        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start transient scope unit: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, BUS_WAIT_JOBS_LOG_ERROR, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int enter_cgroup(char **ret_cgroup, bool enter_subroot) {
        _cleanup_free_ char *cgroup_root = NULL, *cgroup_subroot = NULL;
        CGroupMask supported;
        int r;

        r = cg_is_ready();
        if (r < 0)
                return r;
        if (r == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(ENOMEDIUM), "cgroupfs is not mounted.");

        r = allocate_scope();
        if (r < 0)
                log_warning_errno(r, "Couldn't allocate a scope unit for this test, proceeding without.");

        r = cg_pid_get_path(NULL, 0, &cgroup_root);
        if (IN_SET(r, -ENOMEDIUM, -ENOENT))
                return log_warning_errno(r, "cg_pid_get_path(NULL, 0, ...) failed: %m");
        ASSERT_OK(r);

        if (enter_subroot)
                ASSERT_OK(asprintf(&cgroup_subroot, "%s/%" PRIx64, cgroup_root, random_u64()));
        else
                ASSERT_NOT_NULL(cgroup_subroot = strdup(cgroup_root));

        ASSERT_OK(cg_mask_supported(&supported));

        /* If this fails, then we don't mind as the later cgroup operations will fail too, and it's fine if
         * we handle any errors at that point. */

        r = cg_create_and_attach(cgroup_subroot, 0);
        if (r < 0)
                return r;

        if (ret_cgroup)
                *ret_cgroup = TAKE_PTR(cgroup_subroot);

        return 0;
}

int enter_cgroup_subroot(char **ret_cgroup) {
        return enter_cgroup(ret_cgroup, true);
}

int enter_cgroup_root(char **ret_cgroup) {
        return enter_cgroup(ret_cgroup, false);
}

int define_hex_ptr_internal(const char *hex, void **name, size_t *name_len) {
        return unhexmem_full(hex, strlen_ptr(hex), false, name, name_len);
}

const char* ci_environment(void) {
        /* We return a string because we might want to provide multiple bits of information later on: not
         * just the general CI environment type, but also whether we're sanitizing or not, etc. The caller is
         * expected to use strstr on the returned value. */
        static const char *ans = POINTER_MAX;
        int r;

        if (ans != POINTER_MAX)
                return ans;

        /* We allow specifying the environment with $CITYPE. Nobody uses this so far, but we are ready. */
        const char *citype = getenv("CITYPE");
        if (!isempty(citype))
                return (ans = citype);

        if (getenv_bool("TRAVIS") > 0)
                return (ans = "travis");
        if (getenv_bool("SEMAPHORE") > 0)
                return (ans = "semaphore");
        if (getenv_bool("GITHUB_ACTIONS") > 0)
                return (ans = "github-actions");
        if (getenv("AUTOPKGTEST_ARTIFACTS") || getenv("AUTOPKGTEST_TMP"))
                return (ans = "autopkgtest");
        if (getenv("SALSA_CI_IMAGES"))
                return (ans = "salsa-ci");

        FOREACH_STRING(var, "CI", "CONTINOUS_INTEGRATION") {
                /* Those vars are booleans according to Semaphore and Travis docs:
                 * https://docs.travis-ci.com/user/environment-variables/#default-environment-variables
                 * https://docs.semaphoreci.com/ci-cd-environment/environment-variables/#ci
                 */
                r = getenv_bool(var);
                if (r > 0)
                        return (ans = "unknown"); /* Some other unknown thing */
                if (r == 0)
                        return (ans = NULL);
        }

        return (ans = NULL);
}

int run_test_table(const TestFunc *start, const TestFunc *end) {
        _cleanup_strv_free_ char **tests = NULL;
        int r = EXIT_SUCCESS;
        bool ran = false;
        const char *e;

        if (!start)
                return r;

        e = getenv("TESTFUNCS");
        if (e) {
                r = strv_split_full(&tests, e, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse $TESTFUNCS: %m");
        }

        for (const TestFunc *t = ALIGN_PTR(start); t + 1 <= end; t = ALIGN_PTR(t + 1)) {

                if (tests && !strv_contains(tests, t->name))
                        continue;

                if (t->sd_booted && sd_booted() <= 0) {
                        log_info("/* systemd not booted, skipping %s */", t->name);
                        if (t->has_ret && r == EXIT_SUCCESS)
                                r = EXIT_TEST_SKIP;
                } else {
                        log_info("/* %s */", t->name);

                        if (t->has_ret) {
                                int r2 = t->f.int_func();
                                if (r == EXIT_SUCCESS)
                                        r = r2;
                        } else
                                t->f.void_func();
                }

                ran = true;
        }

        if (!ran)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "No matching tests found.");

        return r;
}

void test_prepare(int argc, char *argv[], int log_level) {
        save_argc_argv(argc, argv);
        test_setup_logging(log_level);
}

int assert_signal_internal(void) {
        siginfo_t siginfo = {};
        int r;

        r = fork();
        if (r < 0)
                return -errno;

        if (r == 0) {
                /* Speed things up by never even attempting to generate a coredump */
                (void) set_dumpable(SUID_DUMP_DISABLE);

                /* But still set an rlimit just in case */
                (void) setrlimit(RLIMIT_CORE, &RLIMIT_MAKE_CONST(0));
                return 0;
        }

        r = wait_for_terminate(r, &siginfo);
        if (r < 0)
                return r;

        return siginfo.si_status;
}


void log_test_failed_internal(const char *file, int line, const char *func, const char *format, ...) {
        va_list ap;

        va_start(ap, format);
        DISABLE_WARNING_FORMAT_NONLITERAL;
        log_internalv(LOG_ERR, 0, file, line, func, format, ap);
        REENABLE_WARNING;
        va_end(ap);

        abort();
}
