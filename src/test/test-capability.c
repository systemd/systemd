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

#include <sys/wait.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pwd.h>
#include <unistd.h>

#include "capability.h"
#include "util.h"
#include "macro.h"

static uid_t test_uid = -1;
static gid_t test_gid = -1;
// We keep CAP_DAC_OVERRIDE to avoid errors with gcov when doing test coverage
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

static int setup_tests(void) {
        struct passwd *nobody;

        nobody = getpwnam("nobody");
        if (!nobody) {
                log_error_errno(errno, "Could not find nobody user: %m");
                return -EXIT_TEST_SKIP;
        }
        test_uid = nobody->pw_uid;
        test_gid = nobody->pw_gid;

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

int main(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        if (getuid() != 0)
                return EXIT_TEST_SKIP;

        r = setup_tests();
        if (r < 0)
                return -r;

        show_capabilities();

        test_drop_privileges();
        fork_test(test_have_effective_cap);

        return 0;
}
