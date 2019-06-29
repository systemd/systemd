/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "apparmor-util.h"
#include "architecture.h"
#include "audit-util.h"
#include "cgroup-util.h"
#include "condition.h"
#include "cpu-set-util.h"
#include "efivars.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "ima-util.h"
#include "limits-util.h"
#include "log.h"
#include "macro.h"
#include "nulstr-util.h"
#include "process-util.h"
#include "selinux-util.h"
#include "set.h"
#include "smack-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tomoyo-util.h"
#include "user-util.h"
#include "virt.h"

static void test_condition_test_path(void) {
        Condition *condition;

        condition = condition_new(CONDITION_PATH_EXISTS, "/bin/sh", false, false);
        assert_se(condition);
        assert_se(condition_test(condition));
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS, "/bin/s?", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS_GLOB, "/bin/s?", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS_GLOB, "/bin/s?", false, true);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS, "/thiscertainlywontexist", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS, "/thiscertainlywontexist", false, true);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_DIRECTORY, "/bin", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_DIRECTORY_NOT_EMPTY, "/bin", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_FILE_NOT_EMPTY, "/bin/sh", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_FILE_IS_EXECUTABLE, "/bin/sh", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_FILE_IS_EXECUTABLE, "/etc/passwd", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/proc", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/bin", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_READ_WRITE, "/tmp", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_SYMBOLIC_LINK, "/dev/stdout", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);
}

static void test_condition_test_control_group_controller(void) {
        Condition *condition;
        CGroupMask system_mask;
        CGroupController controller;
        _cleanup_free_ char *controller_name = NULL;
        int r;

        r = cg_unified_flush();
        if (r < 0) {
                log_notice_errno(r, "Skipping ConditionControlGroupController tests: %m");
                return;
        }

        /* Invalid controllers are ignored */
        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, "thisisnotarealcontroller", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, "thisisnotarealcontroller", false, true);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        assert_se(cg_mask_supported(&system_mask) >= 0);

        /* Individual valid controllers one by one */
        for (controller = 0; controller < _CGROUP_CONTROLLER_MAX; controller++) {
                const char *local_controller_name = cgroup_controller_to_string(controller);
                log_info("chosen controller is '%s'", local_controller_name);
                if (system_mask & CGROUP_CONTROLLER_TO_MASK(controller)) {
                        log_info("this controller is available");
                        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, local_controller_name, false, false);
                        assert_se(condition);
                        assert_se(condition_test(condition) > 0);
                        condition_free(condition);

                        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, local_controller_name, false, true);
                        assert_se(condition);
                        assert_se(condition_test(condition) == 0);
                        condition_free(condition);
                } else {
                        log_info("this controller is unavailable");
                        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, local_controller_name, false, false);
                        assert_se(condition);
                        assert_se(condition_test(condition) == 0);
                        condition_free(condition);

                        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, local_controller_name, false, true);
                        assert_se(condition);
                        assert_se(condition_test(condition) > 0);
                        condition_free(condition);
                }
        }

        /* Multiple valid controllers at the same time */
        assert_se(cg_mask_to_string(system_mask, &controller_name) >= 0);

        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, strempty(controller_name), false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, strempty(controller_name), false, true);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
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
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_HOST, "garbage value jjjjjjjjjjjjjj", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_HOST, sid, false, true);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        hostname = gethostname_malloc();
        assert_se(hostname);

        /* if hostname looks like an id128 then skip testing it */
        if (id128_is_valid(hostname))
                log_notice("hostname is an id128, skipping test");
        else {
                condition = condition_new(CONDITION_HOST, hostname, false, false);
                assert_se(condition);
                assert_se(condition_test(condition) > 0);
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
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_COMMAND_LINE, "andthis=neither", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);
}

static void test_condition_test_kernel_version(void) {
        Condition *condition;
        struct utsname u;
        const char *v;

        condition = condition_new(CONDITION_KERNEL_VERSION, "*thisreallyshouldntbeinthekernelversion*", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "*", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        /* An artificially empty condition. It evaluates to true, but normally
         * such condition cannot be created, because the condition list is reset instead. */
        condition = condition_new(CONDITION_KERNEL_VERSION, "", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        assert_se(uname(&u) >= 0);

        condition = condition_new(CONDITION_KERNEL_VERSION, u.release, false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        strshorten(u.release, 4);
        strcpy(strchr(u.release, 0), "*");

        condition = condition_new(CONDITION_KERNEL_VERSION, u.release, false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        /* 0.1.2 would be a very very very old kernel */
        condition = condition_new(CONDITION_KERNEL_VERSION, "> 0.1.2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, ">0.1.2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "'>0.1.2' '<9.0.0'", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "> 0.1.2 < 9.0.0", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, ">", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, ">= 0.1.2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "< 0.1.2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "<= 0.1.2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "= 0.1.2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        /* 4711.8.15 is a very very very future kernel */
        condition = condition_new(CONDITION_KERNEL_VERSION, "< 4711.8.15", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "<= 4711.8.15", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "= 4711.8.15", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "> 4711.8.15", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, ">= 4711.8.15", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        assert_se(uname(&u) >= 0);

        v = strjoina(">=", u.release);
        condition = condition_new(CONDITION_KERNEL_VERSION, v, false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        v = strjoina("=  ", u.release);
        condition = condition_new(CONDITION_KERNEL_VERSION, v, false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        v = strjoina("<=", u.release);
        condition = condition_new(CONDITION_KERNEL_VERSION, v, false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        v = strjoina("> ", u.release);
        condition = condition_new(CONDITION_KERNEL_VERSION, v, false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        v = strjoina("<   ", u.release);
        condition = condition_new(CONDITION_KERNEL_VERSION, v, false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);
}

static void test_condition_test_null(void) {
        Condition *condition;

        condition = condition_new(CONDITION_NULL, NULL, false, false);
        assert_se(condition);
        assert_se(condition_test(condition) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_NULL, NULL, false, true);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);
}

static void test_condition_test_security(void) {
        Condition *condition;

        condition = condition_new(CONDITION_SECURITY, "garbage oifdsjfoidsjoj", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "selinux", false, true);
        assert_se(condition);
        assert_se(condition_test(condition) != mac_selinux_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "apparmor", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == mac_apparmor_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "tomoyo", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == mac_tomoyo_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "ima", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == use_ima());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "smack", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == mac_smack_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "audit", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == use_audit());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "uefi-secureboot", false, false);
        assert_se(condition);
        assert_se(condition_test(condition) == is_efi_secure_boot());
        condition_free(condition);
}

static void print_securities(void) {
        log_info("------ enabled security technologies ------");
        log_info("SELinux: %s", yes_no(mac_selinux_use()));
        log_info("AppArmor: %s", yes_no(mac_apparmor_use()));
        log_info("Tomoyo: %s", yes_no(mac_tomoyo_use()));
        log_info("IMA: %s", yes_no(use_ima()));
        log_info("SMACK: %s", yes_no(mac_smack_use()));
        log_info("Audit: %s", yes_no(use_audit()));
        log_info("UEFI secure boot: %s", yes_no(is_efi_secure_boot()));
        log_info("-------------------------------------------");
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
        if (uid_is_system(getuid()) || uid_is_system(geteuid()))
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
        int ngroups_max, ngroups, r, i;

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

        gids = newa(gid_t, ngroups_max);

        ngroups = getgroups(ngroups_max, gids);
        assert(ngroups >= 0);

        max_gid = getgid();
        for (i = 0; i < ngroups; i++) {
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

static void test_condition_test_cpus_one(const char *s, bool result) {
        Condition *condition;
        int r;

        log_debug("%s=%s", condition_type_to_string(CONDITION_CPUS), s);

        condition = condition_new(CONDITION_CPUS, s, false, false);
        assert_se(condition);

        r = condition_test(condition);
        assert_se(r >= 0);
        assert_se(r == result);
        condition_free(condition);
}

static void test_condition_test_cpus(void) {
        _cleanup_free_ char *t = NULL;
        int cpus;

        cpus = cpus_in_affinity_mask();
        assert_se(cpus >= 0);

        test_condition_test_cpus_one("> 0", true);
        test_condition_test_cpus_one(">= 0", true);
        test_condition_test_cpus_one("!= 0", true);
        test_condition_test_cpus_one("<= 0", false);
        test_condition_test_cpus_one("< 0", false);
        test_condition_test_cpus_one("= 0", false);

        test_condition_test_cpus_one("> 100000", false);
        test_condition_test_cpus_one("= 100000", false);
        test_condition_test_cpus_one(">= 100000", false);
        test_condition_test_cpus_one("< 100000", true);
        test_condition_test_cpus_one("!= 100000", true);
        test_condition_test_cpus_one("<= 100000", true);

        assert_se(asprintf(&t, "= %i", cpus) >= 0);
        test_condition_test_cpus_one(t, true);
        t = mfree(t);

        assert_se(asprintf(&t, "<= %i", cpus) >= 0);
        test_condition_test_cpus_one(t, true);
        t = mfree(t);

        assert_se(asprintf(&t, ">= %i", cpus) >= 0);
        test_condition_test_cpus_one(t, true);
        t = mfree(t);

        assert_se(asprintf(&t, "!= %i", cpus) >= 0);
        test_condition_test_cpus_one(t, false);
        t = mfree(t);

        assert_se(asprintf(&t, "< %i", cpus) >= 0);
        test_condition_test_cpus_one(t, false);
        t = mfree(t);

        assert_se(asprintf(&t, "> %i", cpus) >= 0);
        test_condition_test_cpus_one(t, false);
        t = mfree(t);
}

static void test_condition_test_memory_one(const char *s, bool result) {
        Condition *condition;
        int r;

        log_debug("%s=%s", condition_type_to_string(CONDITION_MEMORY), s);

        condition = condition_new(CONDITION_MEMORY, s, false, false);
        assert_se(condition);

        r = condition_test(condition);
        assert_se(r >= 0);
        assert_se(r == result);
        condition_free(condition);
}

static void test_condition_test_memory(void) {
        _cleanup_free_ char *t = NULL;
        uint64_t memory;

        memory = physical_memory();

        test_condition_test_memory_one("> 0", true);
        test_condition_test_memory_one(">= 0", true);
        test_condition_test_memory_one("!= 0", true);
        test_condition_test_memory_one("<= 0", false);
        test_condition_test_memory_one("< 0", false);
        test_condition_test_memory_one("= 0", false);

        test_condition_test_memory_one("> 18446744073709547520", false);
        test_condition_test_memory_one("= 18446744073709547520", false);
        test_condition_test_memory_one(">= 18446744073709547520", false);
        test_condition_test_memory_one("< 18446744073709547520", true);
        test_condition_test_memory_one("!= 18446744073709547520", true);
        test_condition_test_memory_one("<= 18446744073709547520", true);

        assert_se(asprintf(&t, "= %" PRIu64, memory) >= 0);
        test_condition_test_memory_one(t, true);
        t = mfree(t);

        assert_se(asprintf(&t, "<= %" PRIu64, memory) >= 0);
        test_condition_test_memory_one(t, true);
        t = mfree(t);

        assert_se(asprintf(&t, ">= %" PRIu64, memory) >= 0);
        test_condition_test_memory_one(t, true);
        t = mfree(t);

        assert_se(asprintf(&t, "!= %" PRIu64, memory) >= 0);
        test_condition_test_memory_one(t, false);
        t = mfree(t);

        assert_se(asprintf(&t, "< %" PRIu64, memory) >= 0);
        test_condition_test_memory_one(t, false);
        t = mfree(t);

        assert_se(asprintf(&t, "> %" PRIu64, memory) >= 0);
        test_condition_test_memory_one(t, false);
        t = mfree(t);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_condition_test_path();
        test_condition_test_ac_power();
        test_condition_test_host();
        test_condition_test_architecture();
        test_condition_test_kernel_command_line();
        test_condition_test_kernel_version();
        test_condition_test_null();
        test_condition_test_security();
        print_securities();
        test_condition_test_virtualization();
        test_condition_test_user();
        test_condition_test_group();
        test_condition_test_control_group_controller();
        test_condition_test_cpus();
        test_condition_test_memory();

        return 0;
}
