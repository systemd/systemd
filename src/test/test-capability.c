/***
  This file is part of systemd

  Copyright 2014 Ronny Chevalier

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/in.h>
#include <pwd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "capability-util.h"
#include "fd-util.h"
#include "macro.h"
#include "util.h"

static uid_t test_uid = -1;
static gid_t test_gid = -1;

/* We keep CAP_DAC_OVERRIDE to avoid errors with gcov when doing test coverage */
static uint64_t test_flags = 1ULL << CAP_DAC_OVERRIDE;

static void fork_test(void (*test_func)(void)) {
        pid_t pid = 0;

        pid = fork();
        assert_se(pid >= 0);
        if (pid == 0) {
                test_func();
                exit(0);
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

        nobody = getpwnam("nobody");
        if (!nobody) {
                log_error_errno(errno, "Could not find nobody user: %m");
                return -EXIT_TEST_SKIP;
        }
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
        assert_se(!cap_get_flag(caps, CAP_CHOWN, CAP_INHERITABLE, &fv));
        assert(fv == CAP_CLEAR);

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

        caps = cap_get_proc();
        assert_se(caps);
        assert_se(!cap_get_flag(caps, CAP_CHOWN, CAP_INHERITABLE, &fv));
        assert(fv == CAP_CLEAR);
        cap_free(caps);

        assert_se(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0) == 0);

        set = (UINT64_C(1) << CAP_CHOWN);

        assert_se(!capability_ambient_set_apply(set, true));

        caps = cap_get_proc();
        assert_se(!cap_get_flag(caps, CAP_CHOWN, CAP_INHERITABLE, &fv));
        assert(fv == CAP_SET);
        cap_free(caps);

        assert_se(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0) == 1);
}

int main(int argc, char *argv[]) {
        int r;
        bool run_ambient;

        log_parse_environment();
        log_open();

        if (getuid() != 0)
                return EXIT_TEST_SKIP;

        r = setup_tests(&run_ambient);
        if (r < 0)
                return -r;

        show_capabilities();

        test_drop_privileges();
        test_update_inherited_set();

        fork_test(test_have_effective_cap);

        if (run_ambient)
                fork_test(test_set_ambient_caps);

        return 0;
}
