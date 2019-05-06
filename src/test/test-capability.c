/* SPDX-License-Identifier: LGPL-2.1+ */

#include <netinet/in.h>
#include <pwd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "capability-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "missing_prctl.h"
#include "parse-util.h"
#include "tests.h"
#include "util.h"

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
        assert_se(r >= 0);

        r = safe_atolu(content, &val);
        assert_se(r >= 0);
        assert_se(val != 0);
        assert_se(val == cap_last_cap());
}

/* verify cap_last_cap() against syscall probing */
static void test_last_cap_probe(void) {
        unsigned long p = (unsigned long)CAP_LAST_CAP;

        if (prctl(PR_CAPBSET_READ, p) < 0) {
                for (p--; p > 0; p --)
                        if (prctl(PR_CAPBSET_READ, p) >= 0)
                                break;
        } else {
                for (;; p++)
                        if (prctl(PR_CAPBSET_READ, p+1) < 0)
                                break;
        }

        assert_se(p != 0);
        assert_se(p == cap_last_cap());
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
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Could not find nobody user: %m");

        test_uid = nobody->pw_uid;
        test_gid = nobody->pw_gid;

        *run_ambient = false;

        r = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

        /* There's support for PR_CAP_AMBIENT if the prctl() call
         * succeeded or error code was something else than EINVAL. The
         * EINVAL check should be good enough to rule out false
         * positives. */

        if (r >= 0 || errno != EINVAL)
                *run_ambient = true;

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
        assert_se(sock >= 0);
        safe_close(sock);
}

static void test_drop_privileges_dontkeep_net_raw(void) {
        int sock;

        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        assert_se(sock >= 0);
        safe_close(sock);

        assert_se(drop_privileges(test_uid, test_gid, test_flags) >= 0);
        assert_se(getuid() == test_uid);
        assert_se(getgid() == test_gid);
        show_capabilities();

        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        assert_se(sock < 0);
}

static void test_drop_privileges_fail(void) {
        assert_se(drop_privileges(test_uid, test_gid, test_flags) >= 0);
        assert_se(getuid() == test_uid);
        assert_se(getgid() == test_gid);

        assert_se(drop_privileges(test_uid, test_gid, test_flags) < 0);
        assert_se(drop_privileges(0, 0, test_flags) < 0);
}

static void test_drop_privileges(void) {
        fork_test(test_drop_privileges_keep_net_raw);
        fork_test(test_drop_privileges_dontkeep_net_raw);
        fork_test(test_drop_privileges_fail);
}

static void test_have_effective_cap(void) {
        assert_se(have_effective_cap(CAP_KILL));
        assert_se(have_effective_cap(CAP_CHOWN));

        assert_se(drop_privileges(test_uid, test_gid, test_flags | (1ULL << CAP_KILL)) >= 0);
        assert_se(getuid() == test_uid);
        assert_se(getgid() == test_gid);

        assert_se(have_effective_cap(CAP_KILL));
        assert_se(!have_effective_cap(CAP_CHOWN));
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
        assert(fv == CAP_SET);

        cap_free(caps);
}

static void test_set_ambient_caps(void) {
        cap_t caps;
        uint64_t set = 0;
        cap_flag_value_t fv;

        assert_se(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0) == 0);

        set = (UINT64_C(1) << CAP_CHOWN);

        assert_se(!capability_ambient_set_apply(set, true));

        caps = cap_get_proc();
        assert_se(!cap_get_flag(caps, CAP_CHOWN, CAP_INHERITABLE, &fv));
        assert(fv == CAP_SET);
        cap_free(caps);

        assert_se(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0) == 1);
}

static void test_ensure_cap_64bit(void) {
        _cleanup_free_ char *content = NULL;
        unsigned long p = 0;
        int r;

        r = read_one_line_file("/proc/sys/kernel/cap_last_cap", &content);
        if (r == -ENOENT) /* kernel pre 3.2 */
                return;
        assert_se(r >= 0);

        assert_se(safe_atolu(content, &p) >= 0);

        /* If caps don't fit into 64bit anymore, we have a problem, fail the test. */
        assert_se(p <= 63);

        /* Also check for the header definition */
        assert_se(CAP_LAST_CAP <= 63);
}

int main(int argc, char *argv[]) {
        bool run_ambient;

        test_setup_logging(LOG_INFO);

        test_ensure_cap_64bit();

        test_last_cap_file();
        test_last_cap_probe();

        log_info("have ambient caps: %s", yes_no(ambient_capabilities_supported()));

        if (getuid() != 0)
                return log_tests_skipped("not running as root");

        if (setup_tests(&run_ambient) < 0)
                return log_tests_skipped("setup failed");

        show_capabilities();

        test_drop_privileges();
        test_update_inherited_set();

        fork_test(test_have_effective_cap);

        if (run_ambient)
                fork_test(test_set_ambient_caps);

        return 0;
}
