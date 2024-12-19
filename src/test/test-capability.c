/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_CAPABILITY_C

#include "alloc-util.h"
#include "capability-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "missing_prctl.h"
#include "parse-util.h"
#include "process-util.h"
#include "string-util.h"
#include "tests.h"

static uid_t test_uid = -1;
static gid_t test_gid = -1;

#if HAS_FEATURE_ADDRESS_SANITIZER
/* Keep CAP_SYS_PTRACE when running under Address Sanitizer */
static const uint64_t test_flags = UINT64_C(1) << CAP_SYS_PTRACE;
#else
/* We keep CAP_DAC_OVERRIDE to avoid errors with gcov when doing test coverage */
static const uint64_t test_flags = UINT64_C(1) << CAP_DAC_OVERRIDE;
#endif

/* verify cap_last_cap() against /proc/sys/kernel/cap_last_cap */
static void test_last_cap_file(void) {
        _cleanup_free_ char *content = NULL;
        unsigned long val = 0;
        int r;

        r = read_one_line_file("/proc/sys/kernel/cap_last_cap", &content);
        if (r == -ENOENT || ERRNO_IS_NEG_PRIVILEGE(r)) /* kernel pre 3.2 or no access */
                return;
        ASSERT_OK(r);

        r = safe_atolu(content, &val);
        ASSERT_OK(r);
        assert_se(val != 0);
        ASSERT_EQ(val, cap_last_cap());
}

/* verify cap_last_cap() against syscall probing */
static void test_last_cap_probe(void) {
        unsigned long p = (unsigned long)CAP_LAST_CAP;

        if (prctl(PR_CAPBSET_READ, p) < 0) {
                for (p--; p > 0; p--)
                        if (prctl(PR_CAPBSET_READ, p) >= 0)
                                break;
        } else {
                for (;; p++)
                        if (prctl(PR_CAPBSET_READ, p+1) < 0)
                                break;
        }

        assert_se(p != 0);
        ASSERT_EQ(p, cap_last_cap());
}

static void fork_test(void (*test_func)(void)) {
        pid_t pid = 0;

        pid = fork();
        assert_se(pid >= 0);
        if (pid == 0) {
                test_func();
                exit(EXIT_SUCCESS);
        } else if (pid > 0) {
                int status;

                assert_se(waitpid(pid, &status, 0) > 0);
                assert_se(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        }
}

static void show_capabilities(void) {
        cap_t caps;
        char *text;

        caps = cap_get_proc();
        assert_se(caps);

        text = cap_to_text(caps, NULL);
        assert_se(text);

        log_info("Capabilities:%s", text);
        cap_free(caps);
        cap_free(text);
}

static int setup_tests(bool *run_ambient) {
        struct passwd *nobody;
        int r;

        nobody = getpwnam(NOBODY_USER_NAME);
        if (!nobody)
                return log_warning_errno(SYNTHETIC_ERRNO(ENOENT), "Couldn't find 'nobody' user.");

        test_uid = nobody->pw_uid;
        test_gid = nobody->pw_gid;

        r = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        /* There's support for PR_CAP_AMBIENT if the prctl() call succeeded or error code was something else
         * than EINVAL. The EINVAL check should be good enough to rule out false positives. */
        *run_ambient = r >= 0 || errno != EINVAL;

        return 0;
}

static void test_drop_privileges_keep_net_raw(void) {
        int sock;

        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        assert_se(sock >= 0);
        safe_close(sock);

        assert_se(drop_privileges(test_uid, test_gid, test_flags | (1ULL << CAP_NET_RAW)) >= 0);
        assert_se(getuid() == test_uid);
        assert_se(getgid() == test_gid);
        show_capabilities();

        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        ASSERT_OK(sock);
        safe_close(sock);
}

static void test_drop_privileges_dontkeep_net_raw(void) {
        int sock;

        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        ASSERT_OK(sock);
        safe_close(sock);

        assert_se(drop_privileges(test_uid, test_gid, test_flags) >= 0);
        assert_se(getuid() == test_uid);
        assert_se(getgid() == test_gid);
        show_capabilities();

        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        ASSERT_LT(sock, 0);
}

static void test_drop_privileges_fail(void) {
        assert_se(drop_privileges(test_uid, test_gid, test_flags) >= 0);
        assert_se(getuid() == test_uid);
        assert_se(getgid() == test_gid);

        ASSERT_LT(drop_privileges(test_uid, test_gid, test_flags), 0);
        ASSERT_LT(drop_privileges(0, 0, test_flags), 0);
}

static void test_drop_privileges(void) {
        fork_test(test_drop_privileges_fail);

        if (have_effective_cap(CAP_NET_RAW) <= 0) /* The remaining two tests only work if we have CAP_NET_RAW
                                                   * in the first place. If we are run in some restricted
                                                   * container environment we might not. */
                return;

        fork_test(test_drop_privileges_keep_net_raw);
        fork_test(test_drop_privileges_dontkeep_net_raw);
}

static void test_have_effective_cap(void) {
        ASSERT_GT(have_effective_cap(CAP_KILL), 0);
        ASSERT_GT(have_effective_cap(CAP_CHOWN), 0);

        ASSERT_OK(drop_privileges(test_uid, test_gid, test_flags | (1ULL << CAP_KILL)));
        assert_se(getuid() == test_uid);
        assert_se(getgid() == test_gid);

        ASSERT_GT(have_effective_cap(CAP_KILL), 0);
        assert_se(have_effective_cap(CAP_CHOWN) == 0);
}

static void test_update_inherited_set(void) {
        cap_t caps;
        uint64_t set = 0;
        cap_flag_value_t fv;

        caps = cap_get_proc();
        assert_se(caps);

        set = (UINT64_C(1) << CAP_CHOWN);

        assert_se(!capability_update_inherited_set(caps, set));
        assert_se(!cap_get_flag(caps, CAP_CHOWN, CAP_INHERITABLE, &fv));
        assert_se(fv == CAP_SET);

        cap_free(caps);
}

static void test_apply_ambient_caps(void) {
        cap_t caps;
        uint64_t set = 0;
        cap_flag_value_t fv;

        assert_se(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0) == 0);

        set = (UINT64_C(1) << CAP_CHOWN);

        assert_se(!capability_ambient_set_apply(set, true));

        caps = cap_get_proc();
        assert_se(caps);
        assert_se(!cap_get_flag(caps, CAP_CHOWN, CAP_INHERITABLE, &fv));
        assert_se(fv == CAP_SET);
        cap_free(caps);

        assert_se(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0) == 1);

        assert_se(!capability_ambient_set_apply(0, true));
        caps = cap_get_proc();
        assert_se(caps);
        assert_se(!cap_get_flag(caps, CAP_CHOWN, CAP_INHERITABLE, &fv));
        assert_se(fv == CAP_CLEAR);
        cap_free(caps);

        assert_se(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0) == 0);
}

static void test_ensure_cap_64_bit(void) {
        _cleanup_free_ char *content = NULL;
        unsigned long p = 0;
        int r;

        r = read_one_line_file("/proc/sys/kernel/cap_last_cap", &content);
        if (r == -ENOENT || ERRNO_IS_NEG_PRIVILEGE(r)) /* kernel pre 3.2 or no access */
                return;
        ASSERT_OK(r);

        ASSERT_OK(safe_atolu(content, &p));

        /* If caps don't fit into 64-bit anymore, we have a problem, fail the test. */
        assert_se(p <= 63);

        /* Also check for the header definition */
        assert_cc(CAP_LAST_CAP <= 63);
}

static void test_capability_get_ambient(void) {
        uint64_t c;
        int r;

        ASSERT_OK(capability_get_ambient(&c));

        r = prctl(PR_CAPBSET_READ, CAP_MKNOD);
        if (r <= 0)
                return (void) log_tests_skipped("Lacking CAP_MKNOD, skipping getambient test.");
        r = prctl(PR_CAPBSET_READ, CAP_LINUX_IMMUTABLE);
        if (r <= 0)
                return (void) log_tests_skipped("Lacking CAP_LINUX_IMMUTABLE, skipping getambient test.");

        r = safe_fork("(getambient)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_WAIT|FORK_LOG, NULL);
        ASSERT_OK(r);

        if (r == 0) {
                int x, y;
                /* child */
                assert_se(capability_get_ambient(&c) >= 0);

                x = capability_ambient_set_apply(
                                (UINT64_C(1) << CAP_MKNOD)|
                                (UINT64_C(1) << CAP_LINUX_IMMUTABLE),
                                /* also_inherit= */ true);
                assert_se(x >= 0 || ERRNO_IS_PRIVILEGE(x));

                assert_se(capability_get_ambient(&c) >= 0);
                assert_se(x < 0 || FLAGS_SET(c, UINT64_C(1) << CAP_MKNOD));
                assert_se(x < 0 || FLAGS_SET(c, UINT64_C(1) << CAP_LINUX_IMMUTABLE));
                assert_se(x < 0 || !FLAGS_SET(c, UINT64_C(1) << CAP_SETPCAP));

                y = capability_bounding_set_drop(
                                ((UINT64_C(1) << CAP_LINUX_IMMUTABLE)|
                                 (UINT64_C(1) << CAP_SETPCAP)),
                                /* right_now= */ true);
                assert_se(y >= 0 || ERRNO_IS_PRIVILEGE(y));

                assert_se(capability_get_ambient(&c) >= 0);
                assert_se(x < 0 || y < 0 || !FLAGS_SET(c, UINT64_C(1) << CAP_MKNOD));
                assert_se(x < 0 || y < 0 || FLAGS_SET(c, UINT64_C(1) << CAP_LINUX_IMMUTABLE));
                assert_se(x < 0 || y < 0 || !FLAGS_SET(c, UINT64_C(1) << CAP_SETPCAP));

                y = capability_bounding_set_drop(
                                (UINT64_C(1) << CAP_SETPCAP),
                                /* right_now= */ true);
                assert_se(y >= 0 || ERRNO_IS_PRIVILEGE(y));

                assert_se(capability_get_ambient(&c) >= 0);
                assert_se(x < 0 || y < 0 || !FLAGS_SET(c, UINT64_C(1) << CAP_MKNOD));
                assert_se(x < 0 || y < 0 || !FLAGS_SET(c, UINT64_C(1) << CAP_LINUX_IMMUTABLE));
                assert_se(x < 0 || y < 0 || !FLAGS_SET(c, UINT64_C(1) << CAP_SETPCAP));

                _exit(EXIT_SUCCESS);
        }
}

static void test_pidref_get_capability(void) {
        CapabilityQuintet q = CAPABILITY_QUINTET_NULL;

        assert_se(pidref_get_capability(&PIDREF_MAKE_FROM_PID(getpid_cached()), &q) >= 0);

        assert_se(q.effective != CAP_MASK_UNSET);
        assert_se(q.inheritable != CAP_MASK_UNSET);
        assert_se(q.permitted != CAP_MASK_UNSET);
        assert_se(q.effective != CAP_MASK_UNSET);
        assert_se(q.ambient != CAP_MASK_UNSET);
}

int main(int argc, char *argv[]) {
        bool run_ambient;

        test_setup_logging(LOG_DEBUG);

        test_ensure_cap_64_bit();

        test_last_cap_file();
        test_last_cap_probe();

        if (getuid() != 0)
                return log_tests_skipped("not running as root");

        if (setup_tests(&run_ambient) < 0)
                return log_tests_skipped("setup failed");

        show_capabilities();

        if (!userns_has_single_user())
                test_drop_privileges();

        test_update_inherited_set();

        if (!userns_has_single_user())
                fork_test(test_have_effective_cap);

        if (run_ambient)
                fork_test(test_apply_ambient_caps);

        test_capability_get_ambient();

        test_pidref_get_capability();

        return 0;
}
