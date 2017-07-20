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

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "apparmor-util.h"
#include "architecture.h"
#include "audit-util.h"
#include "condition.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "ima-util.h"
#include "log.h"
#include "macro.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "strv.h"
#include "virt.h"
#include "util.h"
#include "user-util.h"

static void test_condition_test_path(void) {
        Condition *condition;

        condition = condition_new(CONDITION_PATH_EXISTS, "/bin/sh", false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS, "/bin/s?", false, false);
        assert_se(condition);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS_GLOB, "/bin/s?", false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS_GLOB, "/bin/s?", false, true);
        assert_se(condition);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS, "/thiscertainlywontexist", false, false);
        assert_se(condition);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS, "/thiscertainlywontexist", false, true);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_DIRECTORY, "/bin", false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_DIRECTORY_NOT_EMPTY, "/bin", false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_FILE_NOT_EMPTY, "/bin/sh", false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_FILE_IS_EXECUTABLE, "/bin/sh", false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_FILE_IS_EXECUTABLE, "/etc/passwd", false, false);
        assert_se(condition);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/proc", false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/", false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/bin", false, false);
        assert_se(condition);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_READ_WRITE, "/tmp", false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_SYMBOLIC_LINK, "/dev/stdout", false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);
}

static void test_condition_test_ac_power(void) {
        Condition *condition;

        condition = condition_new(CONDITION_AC_POWER, "true", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == on_ac_power());
        condition_free(condition);

        condition = condition_new(CONDITION_AC_POWER, "false", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) != on_ac_power());
        condition_free(condition);

        condition = condition_new(CONDITION_AC_POWER, "false", false, true);
        assert_se(condition);
        assert_se(condition_test(condition) == on_ac_power());
        condition_free(condition);
}

static void test_condition_test_host(void) {
        _cleanup_free_ char *hostname = NULL;
        char sid[SD_ID128_STRING_MAX];
        Condition *condition;
        sd_id128_t id;
        int r;

        r = sd_id128_get_machine(&id);
        assert_se(r >= 0);
        assert_se(sd_id128_to_string(id, sid));

        condition = condition_new(CONDITION_HOST, sid, false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_HOST, "garbage value jjjjjjjjjjjjjj", false, false);
        assert_se(condition);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_HOST, sid, false, true);
        assert_se(condition);
        assert_se(!condition_test(condition));
        condition_free(condition);

        hostname = gethostname_malloc();
        assert_se(hostname);

        /* if hostname looks like an id128 then skip testing it */
        if (id128_is_valid(hostname))
                log_notice("hostname is an id128, skipping test");
        else {
                condition = condition_new(CONDITION_HOST, hostname, false, false);
                assert_se(condition);
                assert_se(condition_test(condition));
                condition_free(condition);
        }
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
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_ARCHITECTURE, "garbage value", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_ARCHITECTURE, sa, false, true);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);
}

static void test_condition_test_kernel_command_line(void) {
        Condition *condition;

        condition = condition_new(CONDITION_KERNEL_COMMAND_LINE, "thisreallyshouldntbeonthekernelcommandline", false, false);
        assert_se(condition);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_COMMAND_LINE, "andthis=neither", false, false);
        assert_se(condition);
        assert_se(!condition_test(condition));
        condition_free(condition);
}

static void test_condition_test_null(void) {
        Condition *condition;

        condition = condition_new(CONDITION_NULL, NULL, false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_NULL, NULL, false, true);
        assert_se(condition);
        assert_se(!condition_test(condition));
        condition_free(condition);
}

static void test_condition_test_security(void) {
        Condition *condition;

        condition = condition_new(CONDITION_SECURITY, "garbage oifdsjfoidsjoj", false, false);
        assert_se(condition);
        assert_se(!condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "selinux", false, true);
        assert_se(condition);
        assert_se(condition_test(condition) != mac_selinux_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "ima", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == use_ima());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "apparmor", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == mac_apparmor_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "smack", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == mac_smack_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "audit", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == use_audit());
        condition_free(condition);
}

static void test_condition_test_virtualization(void) {
        Condition *condition;
        const char *virt;
        int r;

        condition = condition_new(CONDITION_VIRTUALIZATION, "garbage oifdsjfoidsjoj", false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionVirtualization=garbage → %i", r);
        assert_se(r == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_VIRTUALIZATION, "container", false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionVirtualization=container → %i", r);
        assert_se(r == !!detect_container());
        condition_free(condition);

        condition = condition_new(CONDITION_VIRTUALIZATION, "vm", false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionVirtualization=vm → %i", r);
        assert_se(r == (detect_vm() && !detect_container()));
        condition_free(condition);

        condition = condition_new(CONDITION_VIRTUALIZATION, "private-users", false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionVirtualization=private-users → %i", r);
        assert_se(r == !!running_in_userns());
        condition_free(condition);

        NULSTR_FOREACH(virt,
                       "kvm\0"
                       "qemu\0"
                       "bochs\0"
                       "xen\0"
                       "uml\0"
                       "vmware\0"
                       "oracle\0"
                       "microsoft\0"
                       "zvm\0"
                       "parallels\0"
                       "bhyve\0"
                       "vm_other\0") {

                condition = condition_new(CONDITION_VIRTUALIZATION, virt, false, false);
                assert_se(condition);
                r = condition_test(condition);
                log_info("ConditionVirtualization=%s → %i", virt, r);
                assert_se(r >= 0);
                condition_free(condition);
        }
}

static void test_condition_test_user(void) {
        Condition *condition;
        char* uid;
        char* username;
        int r;

        condition = condition_new(CONDITION_USER, "garbage oifdsjfoidsjoj", false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionUser=garbage → %i", r);
        assert_se(r == 0);
        condition_free(condition);

        assert_se(asprintf(&uid, "%"PRIu32, UINT32_C(0xFFFF)) > 0);
        condition = condition_new(CONDITION_USER, uid, false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionUser=%s → %i", uid, r);
        assert_se(r == 0);
        condition_free(condition);
        free(uid);

        assert_se(asprintf(&uid, "%u", (unsigned)getuid()) > 0);
        condition = condition_new(CONDITION_USER, uid, false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionUser=%s → %i", uid, r);
        assert_se(r > 0);
        condition_free(condition);
        free(uid);

        assert_se(asprintf(&uid, "%u", (unsigned)getuid()+1) > 0);
        condition = condition_new(CONDITION_USER, uid, false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionUser=%s → %i", uid, r);
        assert_se(r == 0);
        condition_free(condition);
        free(uid);

        username = getusername_malloc();
        assert_se(username);
        condition = condition_new(CONDITION_USER, username, false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionUser=%s → %i", username, r);
        assert_se(r > 0);
        condition_free(condition);
        free(username);

        username = (char*)(geteuid() == 0 ? NOBODY_USER_NAME : "root");
        condition = condition_new(CONDITION_USER, username, false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionUser=%s → %i", username, r);
        assert_se(r == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_USER, "@system", false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionUser=@system → %i", r);
        if (getuid() < SYSTEM_UID_MAX || geteuid() < SYSTEM_UID_MAX)
                assert_se(r > 0);
        else
                assert_se(r == 0);
        condition_free(condition);
}

static void test_condition_test_group(void) {
        Condition *condition;
        char* gid;
        char* groupname;
        gid_t *gids, max_gid;
        int ngroups_max, r, i;

        assert_se(0 < asprintf(&gid, "%u", UINT32_C(0xFFFF)));
        condition = condition_new(CONDITION_GROUP, gid, false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionGroup=%s → %i", gid, r);
        assert_se(r == 0);
        condition_free(condition);
        free(gid);

        assert_se(0 < asprintf(&gid, "%u", getgid()));
        condition = condition_new(CONDITION_GROUP, gid, false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionGroup=%s → %i", gid, r);
        assert_se(r > 0);
        condition_free(condition);
        free(gid);

        ngroups_max = sysconf(_SC_NGROUPS_MAX);
        assert(ngroups_max > 0);

        gids = alloca(sizeof(gid_t) * ngroups_max);

        r = getgroups(ngroups_max, gids);
        assert(r >= 0);

        max_gid = getgid();
        for (i = 0; i < r; i++) {
                assert_se(0 < asprintf(&gid, "%u", gids[i]));
                condition = condition_new(CONDITION_GROUP, gid, false, false);
                assert_se(condition);
                r = condition_test(condition);
                log_info("ConditionGroup=%s → %i", gid, r);
                assert_se(r > 0);
                condition_free(condition);
                free(gid);
                max_gid = gids[i] > max_gid ? gids[i] : max_gid;

                groupname = gid_to_name(gids[i]);
                assert_se(groupname);
                condition = condition_new(CONDITION_GROUP, groupname, false, false);
                assert_se(condition);
                r = condition_test(condition);
                log_info("ConditionGroup=%s → %i", groupname, r);
                assert_se(r > 0);
                condition_free(condition);
                free(groupname);
                max_gid = gids[i] > max_gid ? gids[i] : max_gid;
        }

        assert_se(0 < asprintf(&gid, "%u", max_gid+1));
        condition = condition_new(CONDITION_GROUP, gid, false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionGroup=%s → %i", gid, r);
        assert_se(r == 0);
        condition_free(condition);
        free(gid);

        groupname = (char*)(geteuid() == 0 ? NOBODY_GROUP_NAME : "root");
        condition = condition_new(CONDITION_GROUP, groupname, false, false);
        assert_se(condition);
        r = condition_test(condition);
        log_info("ConditionGroup=%s → %i", groupname, r);
        assert_se(r == 0);
        condition_free(condition);
}

int main(int argc, char *argv[]) {
        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        test_condition_test_path();
        test_condition_test_ac_power();
        test_condition_test_host();
        test_condition_test_architecture();
        test_condition_test_kernel_command_line();
        test_condition_test_null();
        test_condition_test_security();
        test_condition_test_virtualization();
        test_condition_test_user();
        test_condition_test_group();

        return 0;
}
