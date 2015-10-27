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

#include "sd-id128.h"

#include "alloc-util.h"
#include "apparmor-util.h"
#include "architecture.h"
#include "audit-util.h"
#include "condition.h"
#include "hostname-util.h"
#include "ima-util.h"
#include "log.h"
#include "macro.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "util.h"

static void test_condition_test_path(void) {
        Condition *condition;

        condition = condition_new(CONDITION_PATH_EXISTS, "/bin/sh", false, false);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS, "/bin/s?", false, false);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS_GLOB, "/bin/s?", false, false);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS_GLOB, "/bin/s?", false, true);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS, "/thiscertainlywontexist", false, false);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS, "/thiscertainlywontexist", false, true);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_DIRECTORY, "/bin", false, false);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_DIRECTORY_NOT_EMPTY, "/bin", false, false);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_FILE_NOT_EMPTY, "/bin/sh", false, false);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_FILE_IS_EXECUTABLE, "/bin/sh", false, false);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_FILE_IS_EXECUTABLE, "/etc/passwd", false, false);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/proc", false, false);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/", false, false);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/bin", false, false);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_READ_WRITE, "/tmp", false, false);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_SYMBOLIC_LINK, "/dev/stdout", false, false);
        assert_se(condition_test(condition));
        condition_free(condition);
}

static void test_condition_test_ac_power(void) {
        Condition *condition;

        condition = condition_new(CONDITION_AC_POWER, "true", false, false);
        assert_se(condition_test(condition) == on_ac_power());
        condition_free(condition);

        condition = condition_new(CONDITION_AC_POWER, "false", false, false);
        assert_se(condition_test(condition) != on_ac_power());
        condition_free(condition);

        condition = condition_new(CONDITION_AC_POWER, "false", false, true);
        assert_se(condition_test(condition) == on_ac_power());
        condition_free(condition);
}

static void test_condition_test_host(void) {
        Condition *condition;
        sd_id128_t id;
        int r;
        char sid[SD_ID128_STRING_MAX];
        _cleanup_free_ char *hostname = NULL;

        r = sd_id128_get_machine(&id);
        assert_se(r >= 0);
        assert_se(sd_id128_to_string(id, sid));

        condition = condition_new(CONDITION_HOST, sid, false, false);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_HOST, "garbage value jjjjjjjjjjjjjj", false, false);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_HOST, sid, false, true);
        assert_se(!condition_test(condition));
        condition_free(condition);

        hostname = gethostname_malloc();
        assert_se(hostname);

        condition = condition_new(CONDITION_HOST, hostname, false, false);
        assert_se(condition_test(condition));
        condition_free(condition);
}

static void test_condition_test_architecture(void) {
        Condition *condition;
        const char *sa;
        int a;

        a = uname_architecture();
        assert_se(a >= 0);

        sa = architecture_to_string(a);
        assert_se(sa);

        condition = condition_new(CONDITION_ARCHITECTURE, sa, false, false);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_ARCHITECTURE, "garbage value", false, false);
        assert_se(condition_test(condition) < 0);
        condition_free(condition);

        condition = condition_new(CONDITION_ARCHITECTURE, sa, false, true);
        assert_se(!condition_test(condition));
        condition_free(condition);
}

static void test_condition_test_kernel_command_line(void) {
        Condition *condition;

        condition = condition_new(CONDITION_KERNEL_COMMAND_LINE, "thisreallyshouldntbeonthekernelcommandline", false, false);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_COMMAND_LINE, "andthis=neither", false, false);
        assert_se(!condition_test(condition));
        condition_free(condition);
}

static void test_condition_test_null(void) {
        Condition *condition;

        condition = condition_new(CONDITION_NULL, NULL, false, false);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_NULL, NULL, false, true);
        assert_se(!condition_test(condition));
        condition_free(condition);
}

static void test_condition_test_security(void) {
        Condition *condition;

        condition = condition_new(CONDITION_SECURITY, "garbage oifdsjfoidsjoj", false, false);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "selinux", false, true);
        assert_se(condition_test(condition) != mac_selinux_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "ima", false, false);
        assert_se(condition_test(condition) == use_ima());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "apparmor", false, false);
        assert_se(condition_test(condition) == mac_apparmor_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "smack", false, false);
        assert_se(condition_test(condition) == mac_smack_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "audit", false, false);
        assert_se(condition_test(condition) == use_audit());
        condition_free(condition);
}


int main(int argc, char *argv[]) {
        log_parse_environment();
        log_open();

        test_condition_test_path();
        test_condition_test_ac_power();
        test_condition_test_host();
        test_condition_test_architecture();
        test_condition_test_kernel_command_line();
        test_condition_test_null();
        test_condition_test_security();

        return 0;
}
