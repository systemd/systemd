/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "pidref.h"

#define TEST_CAPABILITY_C

#include "alloc-util.h"
#include "capability-list.h"
#include "capability-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "parse-util.h"
#include "process-util.h"
#include "tests.h"

static uid_t test_uid = -1;
static gid_t test_gid = -1;
static bool run_ambient = false;

#if HAS_FEATURE_ADDRESS_SANITIZER
/* Keep CAP_SYS_PTRACE when running under Address Sanitizer */
static const uint64_t test_flags = UINT64_C(1) << CAP_SYS_PTRACE;
#else
/* We keep CAP_DAC_OVERRIDE to avoid errors with gcov when doing test coverage */
static const uint64_t test_flags = UINT64_C(1) << CAP_DAC_OVERRIDE;
#endif

static void show_capabilities(void) {
        _cleanup_free_ char *e = NULL, *p = NULL, *i = NULL;
        CapabilityQuintet q;

        ASSERT_OK(capability_get(&q));
        ASSERT_OK(capability_set_to_string(q.effective, &e));
        ASSERT_OK(capability_set_to_string(q.permitted, &p));
        ASSERT_OK(capability_set_to_string(q.inheritable, &i));

        log_info("Capabilities:e=%s p=%s, i=%s", e, p, i);
}

/* verify cap_last_cap() against /proc/sys/kernel/cap_last_cap */
TEST(last_cap_file) {
        _cleanup_free_ char *content = NULL;
        unsigned long val = 0;
        int r;

        r = read_one_line_file("/proc/sys/kernel/cap_last_cap", &content);
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                return (void) log_tests_skipped_errno(r, "Failed to /proc/sys/kernel/cap_last_cap");
        ASSERT_OK(r);

        ASSERT_OK(safe_atolu(content, &val));
        ASSERT_NE(val, 0UL);
        ASSERT_EQ(val, cap_last_cap());
}

/* verify cap_last_cap() against syscall probing */
TEST(last_cap_probe) {
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

        ASSERT_NE(p, 0UL);
        ASSERT_EQ(p, cap_last_cap());
}

static void test_drop_privileges_keep_net_raw(void) {
        int sock;

        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        ASSERT_OK_ERRNO(sock);
        safe_close(sock);

        ASSERT_OK(drop_privileges(test_uid, test_gid, test_flags | (1ULL << CAP_NET_RAW)));
        ASSERT_EQ(getuid(), test_uid);
        ASSERT_EQ(getgid(), test_gid);
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

        ASSERT_OK(drop_privileges(test_uid, test_gid, test_flags));
        ASSERT_EQ(getuid(), test_uid);
        ASSERT_EQ(getgid(), test_gid);
        show_capabilities();

        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        ASSERT_LT(sock, 0);
}

static void test_drop_privileges_fail(void) {
        ASSERT_OK(drop_privileges(test_uid, test_gid, test_flags));
        ASSERT_EQ(getuid(), test_uid);
        ASSERT_EQ(getgid(), test_gid);

        ASSERT_FAIL(drop_privileges(test_uid, test_gid, test_flags));
        ASSERT_FAIL(drop_privileges(0, 0, test_flags));
}

TEST(drop_privileges) {
        int r;

        if (getuid() != 0)
                return (void) log_tests_skipped("not running as root");
        if (userns_has_single_user())
                return (void) log_tests_skipped("running in single-user user namespace");

        r = ASSERT_OK(pidref_safe_fork("test-cap", FORK_WAIT|FORK_DEATHSIG_SIGKILL|FORK_LOG, /* ret= */ NULL));
        if (r == 0) {
                test_drop_privileges_fail();
                _exit(EXIT_SUCCESS);
        }

        if (have_effective_cap(CAP_NET_RAW) <= 0) /* The remaining two tests only work if we have CAP_NET_RAW
                                                   * in the first place. If we are run in some restricted
                                                   * container environment we might not. */
                return;

        r = ASSERT_OK(pidref_safe_fork("test-cap", FORK_WAIT|FORK_DEATHSIG_SIGKILL|FORK_LOG, /* ret= */ NULL));
        if (r == 0) {
                test_drop_privileges_keep_net_raw();
                _exit(EXIT_SUCCESS);
        }

        r = ASSERT_OK(pidref_safe_fork("test-cap", FORK_WAIT|FORK_DEATHSIG_SIGKILL|FORK_LOG, /* ret= */ NULL));
        if (r == 0) {
                test_drop_privileges_dontkeep_net_raw();
                _exit(EXIT_SUCCESS);
        }
}

static void test_have_effective_cap_impl(void) {
        ASSERT_GT(have_effective_cap(CAP_KILL), 0);
        ASSERT_GT(have_effective_cap(CAP_CHOWN), 0);

        ASSERT_OK(drop_privileges(test_uid, test_gid, test_flags | (1ULL << CAP_KILL)));
        ASSERT_EQ(getuid(), test_uid);
        ASSERT_EQ(getgid(), test_gid);

        ASSERT_GT(have_effective_cap(CAP_KILL), 0);
        ASSERT_EQ(have_effective_cap(CAP_CHOWN), 0);
}

TEST(have_effective_cap) {
        int r;

        if (getuid() != 0)
                return (void) log_tests_skipped("not running as root");
        if (userns_has_single_user())
                return (void) log_tests_skipped("running in single-user user namespace");

        r = ASSERT_OK(pidref_safe_fork("test-cap", FORK_WAIT|FORK_DEATHSIG_SIGKILL|FORK_LOG, /* ret= */ NULL));
        if (r == 0) {
                test_have_effective_cap_impl();
                _exit(EXIT_SUCCESS);
        }
}

static void test_apply_ambient_caps_impl(void) {
        ASSERT_OK_EQ_ERRNO(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0), 0);

        ASSERT_OK(capability_ambient_set_apply(UINT64_C(1) << CAP_CHOWN, /* also_inherit= */ true));
        ASSERT_OK_POSITIVE(have_inheritable_cap(CAP_CHOWN));

        ASSERT_OK_EQ_ERRNO(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0), 1);

        ASSERT_OK(capability_ambient_set_apply(0, /* also_inherit= */ true));
        ASSERT_OK_ZERO(have_inheritable_cap(CAP_CHOWN));

        ASSERT_OK_EQ_ERRNO(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0), 0);
}

TEST(apply_ambient_caps) {
        int r;

        if (getuid() != 0)
                return (void) log_tests_skipped("not running as root");
        if (!run_ambient)
                return (void) log_tests_skipped("ambient caps not supported");

        r = ASSERT_OK(pidref_safe_fork("test-cap", FORK_WAIT|FORK_DEATHSIG_SIGKILL|FORK_LOG, /* ret= */ NULL));
        if (r == 0) {
                test_apply_ambient_caps_impl();
                _exit(EXIT_SUCCESS);
        }
}

TEST(ensure_cap_64_bit) {
        _cleanup_free_ char *content = NULL;
        unsigned long p = 0;
        int r;

        r = read_one_line_file("/proc/sys/kernel/cap_last_cap", &content);
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                return (void) log_tests_skipped_errno(r, "Failed to /proc/sys/kernel/cap_last_cap");
        ASSERT_OK(r);

        ASSERT_OK(safe_atolu(content, &p));

        /* If caps don't fit into 64-bit anymore, we have a problem, fail the test. Moreover, we use
         * UINT64_MAX as unset, hence it must be smaller than or equals to 62 (CAP_LIMIT). */
        ASSERT_LE(p, (unsigned long) CAP_LIMIT);
}

TEST(capability_get_ambient) {
        uint64_t c;
        int r;

        if (getuid() != 0)
                return (void) log_tests_skipped("not running as root");

        ASSERT_OK(capability_get_ambient(&c));

        r = prctl(PR_CAPBSET_READ, CAP_MKNOD);
        if (r <= 0)
                return (void) log_tests_skipped("Lacking CAP_MKNOD, skipping getambient test.");
        r = prctl(PR_CAPBSET_READ, CAP_LINUX_IMMUTABLE);
        if (r <= 0)
                return (void) log_tests_skipped("Lacking CAP_LINUX_IMMUTABLE, skipping getambient test.");

        r = ASSERT_OK(pidref_safe_fork(
                        "(getambient)",
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_WAIT|FORK_LOG,
                        /* ret= */ NULL));

        if (r == 0) {
                int x, y;
                /* child */
                ASSERT_OK(capability_get_ambient(&c));

                x = capability_ambient_set_apply(
                                (UINT64_C(1) << CAP_MKNOD)|
                                (UINT64_C(1) << CAP_LINUX_IMMUTABLE),
                                /* also_inherit= */ true);
                ASSERT_TRUE(x >= 0 || ERRNO_IS_PRIVILEGE(x));

                ASSERT_OK(capability_get_ambient(&c));
                ASSERT_TRUE(x < 0 || FLAGS_SET(c, UINT64_C(1) << CAP_MKNOD));
                ASSERT_TRUE(x < 0 || FLAGS_SET(c, UINT64_C(1) << CAP_LINUX_IMMUTABLE));
                ASSERT_TRUE(x < 0 || !FLAGS_SET(c, UINT64_C(1) << CAP_SETPCAP));

                y = capability_bounding_set_drop(
                                ((UINT64_C(1) << CAP_LINUX_IMMUTABLE)|
                                 (UINT64_C(1) << CAP_SETPCAP)),
                                /* right_now= */ true);
                ASSERT_TRUE(y >= 0 || ERRNO_IS_PRIVILEGE(y));

                ASSERT_OK(capability_get_ambient(&c));
                ASSERT_TRUE(x < 0 || y < 0 || !FLAGS_SET(c, UINT64_C(1) << CAP_MKNOD));
                ASSERT_TRUE(x < 0 || y < 0 || FLAGS_SET(c, UINT64_C(1) << CAP_LINUX_IMMUTABLE));
                ASSERT_TRUE(x < 0 || y < 0 || !FLAGS_SET(c, UINT64_C(1) << CAP_SETPCAP));

                y = capability_bounding_set_drop(
                                (UINT64_C(1) << CAP_SETPCAP),
                                /* right_now= */ true);
                ASSERT_TRUE(y >= 0 || ERRNO_IS_PRIVILEGE(y));

                ASSERT_OK(capability_get_ambient(&c));
                ASSERT_TRUE(x < 0 || y < 0 || !FLAGS_SET(c, UINT64_C(1) << CAP_MKNOD));
                ASSERT_TRUE(x < 0 || y < 0 || !FLAGS_SET(c, UINT64_C(1) << CAP_LINUX_IMMUTABLE));
                ASSERT_TRUE(x < 0 || y < 0 || !FLAGS_SET(c, UINT64_C(1) << CAP_SETPCAP));

                _exit(EXIT_SUCCESS);
        }
}

TEST(pidref_get_capability) {
        CapabilityQuintet q = CAPABILITY_QUINTET_NULL;

        if (getuid() != 0)
                return (void) log_tests_skipped("not running as root");

        ASSERT_OK(pidref_get_capability(&PIDREF_MAKE_FROM_PID(getpid_cached()), &q));

        ASSERT_NE(q.effective, CAP_MASK_UNSET);
        ASSERT_NE(q.inheritable, CAP_MASK_UNSET);
        ASSERT_NE(q.permitted, CAP_MASK_UNSET);
        ASSERT_NE(q.effective, CAP_MASK_UNSET);
        ASSERT_NE(q.ambient, CAP_MASK_UNSET);
}

static int intro(void) {
        /* Try to set up nobody user/ambient caps for tests that need them.
         * Not finding nobody is non-fatal — those tests will skip themselves. */
        struct passwd *nobody = getpwnam(NOBODY_USER_NAME);
        if (nobody) {
                test_uid = nobody->pw_uid;
                test_gid = nobody->pw_gid;
        }

        int r = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        /* There's support for PR_CAP_AMBIENT if the prctl() call succeeded or error code was something else
         * than EINVAL. The EINVAL check should be good enough to rule out false positives. */
        run_ambient = r >= 0 || errno != EINVAL;

        if (getuid() == 0)
                show_capabilities();

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
