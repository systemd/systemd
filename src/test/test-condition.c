/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "apparmor-util.h"
#include "architecture.h"
#include "audit-util.h"
#include "battery-util.h"
#include "cgroup-util.h"
#include "condition.h"
#include "confidential-virt.h"
#include "cpu-set-util.h"
#include "efi-loader.h"
#include "env-util.h"
#include "errno-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "ima-util.h"
#include "limits-util.h"
#include "log.h"
#include "macro.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "path-util.h"
#include "process-util.h"
#include "psi-util.h"
#include "rm-rf.h"
#include "selinux-util.h"
#include "set.h"
#include "smack-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "tomoyo-util.h"
#include "uid-classification.h"
#include "user-util.h"
#include "virt.h"

TEST(condition_test_path) {
        Condition *condition;

        condition = condition_new(CONDITION_PATH_EXISTS, "/bin/sh", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS, "/bin/s?", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS_GLOB, "/bin/s?", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS_GLOB, "/bin/s?", false, true);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS, "/thiscertainlywontexist", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_EXISTS, "/thiscertainlywontexist", false, true);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_DIRECTORY, "/bin", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_DIRECTORY_NOT_EMPTY, "/bin", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_FILE_NOT_EMPTY, "/bin/sh", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_FILE_IS_EXECUTABLE, "/bin/sh", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_FILE_IS_EXECUTABLE, "/etc/passwd", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/proc", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/bin", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_READ_WRITE, "/tmp", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_ENCRYPTED, "/sys", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_PATH_IS_SYMBOLIC_LINK, "/dev/stdout", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);
}

TEST(condition_test_control_group_hierarchy) {
        Condition *condition;
        int r;

        r = cg_unified();
        if (IN_SET(r, -ENOMEDIUM, -ENOENT)) {
                log_tests_skipped("cgroupfs is not mounted");
                return;
        }
        assert_se(r >= 0);

        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, "v1", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == (r < CGROUP_UNIFIED_ALL));
        condition_free(condition);

        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, "v2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == (r >= CGROUP_UNIFIED_ALL));
        condition_free(condition);
}

TEST(condition_test_control_group_controller) {
        Condition *condition;
        CGroupMask system_mask;
        _cleanup_free_ char *controller_name = NULL;
        int r;

        r = cg_unified();
        if (IN_SET(r, -ENOMEDIUM, -ENOENT)) {
                log_tests_skipped("cgroupfs is not mounted");
                return;
        }
        assert_se(r >= 0);

        /* Invalid controllers are ignored */
        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, "thisisnotarealcontroller", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, "thisisnotarealcontroller", false, true);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        assert_se(cg_mask_supported(&system_mask) >= 0);

        /* Individual valid controllers one by one */
        for (CGroupController controller = 0; controller < _CGROUP_CONTROLLER_MAX; controller++) {
                const char *local_controller_name = cgroup_controller_to_string(controller);
                log_info("chosen controller is '%s'", local_controller_name);
                if (system_mask & CGROUP_CONTROLLER_TO_MASK(controller)) {
                        log_info("this controller is available");
                        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, local_controller_name, false, false);
                        assert_se(condition);
                        assert_se(condition_test(condition, environ) > 0);
                        condition_free(condition);

                        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, local_controller_name, false, true);
                        assert_se(condition);
                        assert_se(condition_test(condition, environ) == 0);
                        condition_free(condition);
                } else {
                        log_info("this controller is unavailable");
                        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, local_controller_name, false, false);
                        assert_se(condition);
                        assert_se(condition_test(condition, environ) == 0);
                        condition_free(condition);

                        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, local_controller_name, false, true);
                        assert_se(condition);
                        assert_se(condition_test(condition, environ) > 0);
                        condition_free(condition);
                }
        }

        /* Multiple valid controllers at the same time */
        assert_se(cg_mask_to_string(system_mask, &controller_name) >= 0);

        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, strempty(controller_name), false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, strempty(controller_name), false, true);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);
}

TEST(condition_test_ac_power) {
        Condition *condition;

        condition = condition_new(CONDITION_AC_POWER, "true", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == on_ac_power());
        condition_free(condition);

        condition = condition_new(CONDITION_AC_POWER, "false", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) != on_ac_power());
        condition_free(condition);

        condition = condition_new(CONDITION_AC_POWER, "false", false, true);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == on_ac_power());
        condition_free(condition);
}

TEST(condition_test_host) {
        _cleanup_free_ char *hostname = NULL;
        Condition *condition;
        sd_id128_t id;
        int r;

        r = sd_id128_get_machine(&id);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                return (void) log_tests_skipped("/etc/machine-id missing");
        assert_se(r >= 0);

        condition = condition_new(CONDITION_HOST, SD_ID128_TO_STRING(id), false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_HOST, "garbage value jjjjjjjjjjjjjj", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_HOST, SD_ID128_TO_STRING(id), false, true);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        hostname = gethostname_malloc();
        assert_se(hostname);

        /* if hostname looks like an id128 then skip testing it */
        if (id128_is_valid(hostname))
                log_notice("hostname is an id128, skipping test");
        else {
                condition = condition_new(CONDITION_HOST, hostname, false, false);
                assert_se(condition);
                assert_se(condition_test(condition, environ) > 0);
                condition_free(condition);
        }
}

TEST(condition_test_architecture) {
        Condition *condition;
        const char *sa;
        Architecture a;

        a = uname_architecture();
        assert_se(a >= 0);

        sa = architecture_to_string(a);
        assert_se(sa);

        condition = condition_new(CONDITION_ARCHITECTURE, sa, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_ARCHITECTURE, "garbage value", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_ARCHITECTURE, sa, false, true);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);
}

TEST(condition_test_firmware) {
        Condition *condition;

        /* Empty parameter */
        condition = condition_new(CONDITION_FIRMWARE, "", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        /* uefi parameter */
        condition = condition_new(CONDITION_FIRMWARE, "uefi", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == is_efi_boot());
        condition_free(condition);
}

TEST(condition_test_firmware_device_tree) {
        Condition *condition;
        bool is_device_tree_system;

        /* device-tree parameter */
        is_device_tree_system = (access("/sys/firmware/devicetree/", F_OK) == 0);

        condition = condition_new(CONDITION_FIRMWARE, "device-tree", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == is_device_tree_system);
        condition_free(condition);

        /* device-tree-compatible parameter */
        if (!is_device_tree_system) {
                condition = condition_new(CONDITION_FIRMWARE, "device-tree-compatible()", false, false);
                assert_se(condition);
                assert_se(condition_test(condition, environ) == 0);
                condition_free(condition);
        } else {
                _cleanup_free_ char *dtcompat = NULL;
                _cleanup_strv_free_ char **dtcompatlist = NULL;
                size_t dtcompat_size;
                int r;

                r = read_full_virtual_file("/proc/device-tree/compatible", &dtcompat, &dtcompat_size);
                if (r < 0) {
                        condition = condition_new(CONDITION_FIRMWARE, "device-tree-compatible()", false, false);
                        assert_se(condition);
                        if (r == -ENOENT)
                                assert_se(condition_test(condition, environ) == 0);
                        else
                                assert_se(condition_test(condition, environ) < 0);
                        condition_free(condition);
                        return;
                }

                dtcompatlist = strv_parse_nulstr(dtcompat, dtcompat_size);

                STRV_FOREACH(c, dtcompatlist) {
                        _cleanup_free_ char *expression = NULL;

                        assert_se(expression = strjoin("device-tree-compatible(", *c, ")"));
                        condition = condition_new(CONDITION_FIRMWARE, expression, false, false);
                        assert_se(condition);
                        assert_se(condition_test(condition, environ) > 0);
                        condition_free(condition);
                }
        }
}

TEST(condition_test_firmware_smbios) {
        Condition *condition;
        _cleanup_free_ char *bios_vendor = NULL, *bios_version = NULL;
        const char *expression;

        /* smbios-field parameter */
        /* Test some malformed smbios-field arguments */
        condition = condition_new(CONDITION_FIRMWARE, "smbios-field()", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_FIRMWARE, "smbios-field(malformed)", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_FIRMWARE, "smbios-field(malformed", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_FIRMWARE, "smbios-field(malformed=)", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_FIRMWARE, "smbios-field(malformed=)", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_FIRMWARE, "smbios-field(not_existing=nothing garbage)", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        /* Test not existing SMBIOS field */
        condition = condition_new(CONDITION_FIRMWARE, "smbios-field(not_existing=nothing)", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        /* Test with bios_vendor, if available */
        if (read_virtual_file("/sys/class/dmi/id/bios_vendor", SIZE_MAX, &bios_vendor, NULL) <= 0)
                return;

        /* remove trailing newline */
        strstrip(bios_vendor);

        /* Check if the bios_vendor contains any spaces we should quote */
        const char *quote = strchr(bios_vendor, ' ') ? "\"" : "";

        /* Test equality / inequality using fnmatch() */
        expression = strjoina("smbios-field(bios_vendor $= ", quote,  bios_vendor, quote, ")");
        condition = condition_new(CONDITION_FIRMWARE, expression, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        expression = strjoina("smbios-field(bios_vendor$=", quote, bios_vendor, quote, ")");
        condition = condition_new(CONDITION_FIRMWARE, expression, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        expression = strjoina("smbios-field(bios_vendor !$= ", quote, bios_vendor, quote, ")");
        condition = condition_new(CONDITION_FIRMWARE, expression, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        expression = strjoina("smbios-field(bios_vendor!$=", quote, bios_vendor, quote, ")");
        condition = condition_new(CONDITION_FIRMWARE, expression, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        expression = strjoina("smbios-field(bios_vendor $= ", quote,  bios_vendor, "*", quote, ")");
        condition = condition_new(CONDITION_FIRMWARE, expression, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        /* Test version comparison with bios_version, if available */
        if (read_virtual_file("/sys/class/dmi/id/bios_version", SIZE_MAX, &bios_version, NULL) <= 0)
                return;

        /* remove trailing newline */
        strstrip(bios_version);

        /* Check if the bios_version contains any spaces we should quote */
        quote = strchr(bios_version, ' ') ? "\"" : "";

        expression = strjoina("smbios-field(bios_version = ", quote, bios_version, quote, ")");
        condition = condition_new(CONDITION_FIRMWARE, expression, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        expression = strjoina("smbios-field(bios_version != ", quote, bios_version, quote, ")");
        condition = condition_new(CONDITION_FIRMWARE, expression, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        expression = strjoina("smbios-field(bios_version <= ", quote, bios_version, quote, ")");
        condition = condition_new(CONDITION_FIRMWARE, expression, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        expression = strjoina("smbios-field(bios_version >= ", quote, bios_version, quote, ")");
        condition = condition_new(CONDITION_FIRMWARE, expression, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        expression = strjoina("smbios-field(bios_version < ", quote, bios_version, ".1", quote, ")");
        condition = condition_new(CONDITION_FIRMWARE, expression, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        expression = strjoina("smbios-field(bios_version > ", quote, bios_version, ".1", quote, ")");
        condition = condition_new(CONDITION_FIRMWARE, expression, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);
}

TEST(condition_test_kernel_command_line) {
        Condition *condition;
        int r;

        condition = condition_new(CONDITION_KERNEL_COMMAND_LINE, "thisreallyshouldntbeonthekernelcommandline", false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        if (ERRNO_IS_PRIVILEGE(r))
                return;
        assert_se(r == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_COMMAND_LINE, "andthis=neither", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);
}

TEST(condition_test_kernel_version) {
        Condition *condition;
        struct utsname u;
        const char *v;

        condition = condition_new(CONDITION_KERNEL_VERSION, "*thisreallyshouldntbeinthekernelversion*", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "*", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        /* An artificially empty condition. It evaluates to true, but normally
         * such condition cannot be created, because the condition list is reset instead. */
        condition = condition_new(CONDITION_KERNEL_VERSION, "", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        assert_se(uname(&u) >= 0);

        condition = condition_new(CONDITION_KERNEL_VERSION, u.release, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        strshorten(u.release, 4);
        strcpy(strchr(u.release, 0), "*");

        condition = condition_new(CONDITION_KERNEL_VERSION, u.release, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        /* 0.1.2 would be a very very very old kernel */
        condition = condition_new(CONDITION_KERNEL_VERSION, "> 0.1.2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, ">0.1.2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "'>0.1.2' '<9.0.0'", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "> 0.1.2 < 9.0.0", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, ">", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, ">= 0.1.2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "< 0.1.2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "<= 0.1.2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "= 0.1.2", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        /* 4711.8.15 is a very very very future kernel */
        condition = condition_new(CONDITION_KERNEL_VERSION, "< 4711.8.15", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "<= 4711.8.15", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "= 4711.8.15", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, "> 4711.8.15", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_KERNEL_VERSION, " >= 4711.8.15", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        assert_se(uname(&u) >= 0);

        v = strjoina(">=", u.release);
        condition = condition_new(CONDITION_KERNEL_VERSION, v, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        v = strjoina("=  ", u.release);
        condition = condition_new(CONDITION_KERNEL_VERSION, v, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        v = strjoina("<=", u.release);
        condition = condition_new(CONDITION_KERNEL_VERSION, v, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        v = strjoina("> ", u.release);
        condition = condition_new(CONDITION_KERNEL_VERSION, v, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        v = strjoina("<   ", u.release);
        condition = condition_new(CONDITION_KERNEL_VERSION, v, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);
}

TEST(condition_test_credential) {
        _cleanup_(rm_rf_physical_and_freep) char *n1 = NULL, *n2 = NULL;
        _cleanup_free_ char *d1 = NULL, *d2 = NULL, *j = NULL;
        Condition *condition;

        assert_se(free_and_strdup(&d1, getenv("CREDENTIALS_DIRECTORY")) >= 0);
        assert_se(free_and_strdup(&d2, getenv("ENCRYPTED_CREDENTIALS_DIRECTORY")) >= 0);

        assert_se(unsetenv("CREDENTIALS_DIRECTORY") >= 0);
        assert_se(unsetenv("ENCRYPTED_CREDENTIALS_DIRECTORY") >= 0);

        condition = condition_new(CONDITION_CREDENTIAL, "definitelymissing", /* trigger= */ false, /* negate= */ false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        /* invalid */
        condition = condition_new(CONDITION_CREDENTIAL, "..", /* trigger= */ false, /* negate= */ false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        assert_se(mkdtemp_malloc(NULL, &n1) >= 0);
        assert_se(mkdtemp_malloc(NULL, &n2) >= 0);

        assert_se(setenv("CREDENTIALS_DIRECTORY", n1, /* overwrite= */ true) >= 0);
        assert_se(setenv("ENCRYPTED_CREDENTIALS_DIRECTORY", n2, /* overwrite= */ true) >= 0);

        condition = condition_new(CONDITION_CREDENTIAL, "stillmissing", /* trigger= */ false, /* negate= */ false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        assert_se(j = path_join(n1, "existing"));
        assert_se(touch(j) >= 0);
        assert_se(j);
        condition = condition_new(CONDITION_CREDENTIAL, "existing", /* trigger= */ false, /* negate= */ false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);
        free(j);

        assert_se(j = path_join(n2, "existing-encrypted"));
        assert_se(touch(j) >= 0);
        assert_se(j);
        condition = condition_new(CONDITION_CREDENTIAL, "existing-encrypted", /* trigger= */ false, /* negate= */ false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        assert_se(set_unset_env("CREDENTIALS_DIRECTORY", d1, /* overwrite= */ true) >= 0);
        assert_se(set_unset_env("ENCRYPTED_CREDENTIALS_DIRECTORY", d2, /* overwrite= */ true) >= 0);
}

#if defined(__i386__) || defined(__x86_64__)
TEST(condition_test_cpufeature) {
        Condition *condition;

        condition = condition_new(CONDITION_CPU_FEATURE, "fpu", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_FEATURE, "somecpufeaturethatreallydoesntmakesense", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_FEATURE, "a", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);
}
#endif

TEST(condition_test_security) {
        Condition *condition;

        condition = condition_new(CONDITION_SECURITY, "garbage oifdsjfoidsjoj", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "selinux", false, true);
        assert_se(condition);
        assert_se(condition_test(condition, environ) != mac_selinux_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "apparmor", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == mac_apparmor_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "tomoyo", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == mac_tomoyo_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "ima", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == use_ima());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "smack", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == mac_smack_use());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "audit", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == use_audit());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "uefi-secureboot", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == is_efi_secure_boot());
        condition_free(condition);

        condition = condition_new(CONDITION_SECURITY, "cvm", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) ==
                  (detect_confidential_virtualization() != CONFIDENTIAL_VIRTUALIZATION_NONE));
        condition_free(condition);
}

TEST(print_securities) {
        log_info("------ enabled security technologies ------");
        log_info("SELinux: %s", yes_no(mac_selinux_use()));
        log_info("AppArmor: %s", yes_no(mac_apparmor_use()));
        log_info("Tomoyo: %s", yes_no(mac_tomoyo_use()));
        log_info("IMA: %s", yes_no(use_ima()));
        log_info("SMACK: %s", yes_no(mac_smack_use()));
        log_info("Audit: %s", yes_no(use_audit()));
        log_info("UEFI secure boot: %s", yes_no(is_efi_secure_boot()));
        log_info("Confidential VM: %s", yes_no
                 (detect_confidential_virtualization() != CONFIDENTIAL_VIRTUALIZATION_NONE));
        log_info("-------------------------------------------");
}

TEST(condition_test_virtualization) {
        Condition *condition;
        int r;

        condition = condition_new(CONDITION_VIRTUALIZATION, "garbage oifdsjfoidsjoj", false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        if (ERRNO_IS_PRIVILEGE(r))
                return;
        log_info("ConditionVirtualization=garbage → %i", r);
        assert_se(r == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_VIRTUALIZATION, "container", false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionVirtualization=container → %i", r);
        assert_se(r == !!detect_container());
        condition_free(condition);

        condition = condition_new(CONDITION_VIRTUALIZATION, "vm", false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionVirtualization=vm → %i", r);
        assert_se(r == (detect_vm() && !detect_container()));
        condition_free(condition);

        condition = condition_new(CONDITION_VIRTUALIZATION, "private-users", false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionVirtualization=private-users → %i", r);
        assert_se(r == !!running_in_userns());
        condition_free(condition);

        NULSTR_FOREACH(virt,
                       "kvm\0"
                       "amazon\0"
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
                r = condition_test(condition, environ);
                log_info("ConditionVirtualization=%s → %i", virt, r);
                assert_se(r >= 0);
                condition_free(condition);
        }
}

TEST(condition_test_user) {
        Condition *condition;
        char* uid;
        char* username;
        int r;

        condition = condition_new(CONDITION_USER, "garbage oifdsjfoidsjoj", false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionUser=garbage → %i", r);
        assert_se(r == 0);
        condition_free(condition);

        assert_se(asprintf(&uid, "%"PRIu32, UINT32_C(0xFFFF)) > 0);
        condition = condition_new(CONDITION_USER, uid, false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionUser=%s → %i", uid, r);
        assert_se(r == 0);
        condition_free(condition);
        free(uid);

        assert_se(asprintf(&uid, "%u", (unsigned)getuid()) > 0);
        condition = condition_new(CONDITION_USER, uid, false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionUser=%s → %i", uid, r);
        assert_se(r > 0);
        condition_free(condition);
        free(uid);

        assert_se(asprintf(&uid, "%u", (unsigned)getuid()+1) > 0);
        condition = condition_new(CONDITION_USER, uid, false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionUser=%s → %i", uid, r);
        assert_se(r == 0);
        condition_free(condition);
        free(uid);

        username = getusername_malloc();
        assert_se(username);
        condition = condition_new(CONDITION_USER, username, false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionUser=%s → %i", username, r);
        assert_se(r > 0);
        condition_free(condition);
        free(username);

        username = (char*)(geteuid() == 0 ? NOBODY_USER_NAME : "root");
        condition = condition_new(CONDITION_USER, username, false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionUser=%s → %i", username, r);
        assert_se(r == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_USER, "@system", false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionUser=@system → %i", r);
        if (uid_is_system(getuid()) || uid_is_system(geteuid()))
                assert_se(r > 0);
        else
                assert_se(r == 0);
        condition_free(condition);
}

TEST(condition_test_group) {
        Condition *condition;
        char* gid;
        char* groupname;
        gid_t *gids, max_gid;
        int ngroups_max, ngroups, r, i;

        assert_se(0 < asprintf(&gid, "%u", UINT32_C(0xFFFF)));
        condition = condition_new(CONDITION_GROUP, gid, false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionGroup=%s → %i", gid, r);
        assert_se(r == 0);
        condition_free(condition);
        free(gid);

        assert_se(0 < asprintf(&gid, "%u", getgid()));
        condition = condition_new(CONDITION_GROUP, gid, false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionGroup=%s → %i", gid, r);
        assert_se(r > 0);
        condition_free(condition);
        free(gid);

        ngroups_max = sysconf(_SC_NGROUPS_MAX);
        assert_se(ngroups_max > 0);

        gids = newa(gid_t, ngroups_max);

        ngroups = getgroups(ngroups_max, gids);
        assert_se(ngroups >= 0);

        max_gid = getgid();
        for (i = 0; i < ngroups; i++) {
                _cleanup_free_ char *name = NULL;

                assert_se(0 < asprintf(&gid, "%u", gids[i]));
                condition = condition_new(CONDITION_GROUP, gid, false, false);
                assert_se(condition);
                r = condition_test(condition, environ);
                log_info("ConditionGroup=%s → %i", gid, r);
                assert_se(r > 0);
                condition_free(condition);
                free(gid);
                max_gid = gids[i] > max_gid ? gids[i] : max_gid;

                name = gid_to_name(gids[i]);
                assert_se(name);
                if (STR_IN_SET(name, "sbuild", "buildd"))
                        return; /* Debian package build in chroot, groupnames won't match, skip */
                condition = condition_new(CONDITION_GROUP, name, false, false);
                assert_se(condition);
                r = condition_test(condition, environ);
                log_info("ConditionGroup=%s → %i", name, r);
                assert_se(r > 0);
                condition_free(condition);
                max_gid = gids[i] > max_gid ? gids[i] : max_gid;
        }

        assert_se(0 < asprintf(&gid, "%u", max_gid+1));
        condition = condition_new(CONDITION_GROUP, gid, false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
        log_info("ConditionGroup=%s → %i", gid, r);
        assert_se(r == 0);
        condition_free(condition);
        free(gid);

        groupname = (char*)(getegid() == 0 ? NOBODY_GROUP_NAME : "root");
        condition = condition_new(CONDITION_GROUP, groupname, false, false);
        assert_se(condition);
        r = condition_test(condition, environ);
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

        r = condition_test(condition, environ);
        assert_se(r >= 0);
        assert_se(r == result);
        condition_free(condition);
}

TEST(condition_test_cpus) {
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

        r = condition_test(condition, environ);
        assert_se(r >= 0);
        assert_se(r == result);
        condition_free(condition);
}

TEST(condition_test_memory) {
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

        test_condition_test_memory_one("> 100T", false);
        test_condition_test_memory_one("= 100T", false);
        test_condition_test_memory_one(">= 100T", false);
        test_condition_test_memory_one("< 100T", true);
        test_condition_test_memory_one("!= 100T", true);
        test_condition_test_memory_one("<= 100T", true);

        test_condition_test_memory_one("> 100 T", false);
        test_condition_test_memory_one("= 100 T", false);
        test_condition_test_memory_one(">= 100 T", false);
        test_condition_test_memory_one("< 100 T", true);
        test_condition_test_memory_one("!= 100 T", true);
        test_condition_test_memory_one("<= 100 T", true);

        test_condition_test_memory_one("> 100 T 1 G", false);
        test_condition_test_memory_one("= 100 T 1 G", false);
        test_condition_test_memory_one(">= 100 T 1 G", false);
        test_condition_test_memory_one("< 100 T 1 G", true);
        test_condition_test_memory_one("!= 100 T 1 G", true);
        test_condition_test_memory_one("<= 100 T 1 G", true);

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

static void test_condition_test_environment_one(const char *s, bool result) {
        Condition *condition;
        int r;

        log_debug("%s=%s", condition_type_to_string(CONDITION_ENVIRONMENT), s);

        condition = condition_new(CONDITION_ENVIRONMENT, s, false, false);
        assert_se(condition);

        r = condition_test(condition, environ);
        assert_se(r >= 0);
        assert_se(r == result);
        condition_free(condition);
}

TEST(condition_test_environment) {
        assert_se(setenv("EXISTINGENVVAR", "foo", false) >= 0);

        test_condition_test_environment_one("MISSINGENVVAR", false);
        test_condition_test_environment_one("MISSINGENVVAR=foo", false);
        test_condition_test_environment_one("MISSINGENVVAR=", false);

        test_condition_test_environment_one("EXISTINGENVVAR", true);
        test_condition_test_environment_one("EXISTINGENVVAR=foo", true);
        test_condition_test_environment_one("EXISTINGENVVAR=bar", false);
        test_condition_test_environment_one("EXISTINGENVVAR=", false);
}

TEST(condition_test_os_release) {
        _cleanup_strv_free_ char **os_release_pairs = NULL;
        _cleanup_free_ char *version_id = NULL;
        const char *key_value_pair;
        Condition *condition;

        /* Should not happen, but it's a test so we don't know the environment. */
        if (load_os_release_pairs(NULL, &os_release_pairs) < 0)
                return;
        if (strv_length(os_release_pairs) < 2)
                return;

        condition = condition_new(CONDITION_OS_RELEASE, "_THISHOPEFULLYWONTEXIST=01234 56789", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        condition = condition_new(CONDITION_OS_RELEASE, "WRONG FORMAT", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_OS_RELEASE, "WRONG!<>=FORMAT", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_OS_RELEASE, "WRONG FORMAT=", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_OS_RELEASE, "WRONG =FORMAT", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_OS_RELEASE, "WRONG = FORMAT", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_OS_RELEASE, "WRONGFORMAT=   ", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_OS_RELEASE, "WRO NG=FORMAT", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == -EINVAL);
        condition_free(condition);

        condition = condition_new(CONDITION_OS_RELEASE, "", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        /* load_os_release_pairs() removes quotes, we have to add them back,
         * otherwise we get a string: "PRETTY_NAME=Debian GNU/Linux 10 (buster)"
         * which is wrong, as the value is not quoted anymore. */
        const char *quote = strchr(os_release_pairs[1], ' ') ? "\"" : "";
        key_value_pair = strjoina(os_release_pairs[0], "=", quote, os_release_pairs[1], quote);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        key_value_pair = strjoina(os_release_pairs[0], "!=", quote, os_release_pairs[1], quote);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        /* Test fnmatch() operators */
        key_value_pair = strjoina(os_release_pairs[0], "$=", quote, os_release_pairs[1], quote);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        key_value_pair = strjoina(os_release_pairs[0], "!$=", quote, os_release_pairs[1], quote);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        /* Some distros (eg: Arch) do not set VERSION_ID */
        if (parse_os_release(NULL, "VERSION_ID", &version_id) <= 0)
                return;

        key_value_pair = strjoina("VERSION_ID", "=", version_id);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "!=", version_id);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "<=", version_id);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", ">=", version_id);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "<", version_id, ".1");
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", ">", version_id, ".1");
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "=", version_id, " ", os_release_pairs[0], "=", quote, os_release_pairs[1], quote);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "!=", version_id, " ", os_release_pairs[0], "=", quote, os_release_pairs[1], quote);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "=", version_id, " ", os_release_pairs[0], "!=", quote, os_release_pairs[1], quote);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "!=", version_id, " ", os_release_pairs[0], "!=", quote, os_release_pairs[1], quote);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) == 0);
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "<", version_id, ".1", " ", os_release_pairs[0], "=", quote, os_release_pairs[1], quote);
        condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);
}

TEST(condition_test_psi) {
        Condition *condition;
        CGroupMask mask;
        int r;

        if (!is_pressure_supported())
                return (void) log_notice("Pressure Stall Information (PSI) is not supported, skipping %s", __func__);

        condition = condition_new(CONDITION_MEMORY_PRESSURE, "", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) < 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "sbarabau", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) < 0);
        condition_free(condition);

        condition = condition_new(CONDITION_MEMORY_PRESSURE, "10%sbarabau", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) < 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "10% sbarabau", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) < 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "-10", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) < 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "10%/10min", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) < 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "10min/10%", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) < 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "10% 5min", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) < 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "/5min", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) < 0);
        condition_free(condition);

        condition = condition_new(CONDITION_IO_PRESSURE, "10s /   ", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) < 0);
        condition_free(condition);

        condition = condition_new(CONDITION_MEMORY_PRESSURE, "100%", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        condition = condition_new(CONDITION_MEMORY_PRESSURE, "0%", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        condition = condition_new(CONDITION_MEMORY_PRESSURE, "0.0%", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "100%", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "0%", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "0.0%", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "0.01%", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "0.0%/10sec", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "100.0% / 1min", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        condition = condition_new(CONDITION_IO_PRESSURE, "50.0% / 1min", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        r = cg_all_unified();
        if (r < 0)
                return (void) log_notice("Failed to determine whether the unified cgroups hierarchy is used, skipping %s", __func__);
        if (r == 0)
                return (void) log_notice("Requires the unified cgroups hierarchy, skipping %s", __func__);

        if (cg_mask_supported(&mask) < 0)
                return (void) log_notice("Failed to get supported cgroup controllers, skipping %s", __func__);

        if (!FLAGS_SET(mask, CGROUP_MASK_MEMORY))
                return (void) log_notice("Requires the cgroup memory controller, skipping %s", __func__);

        if (!FLAGS_SET(mask, CGROUP_MASK_CPU))
                return (void) log_notice("Requires the cgroup CPU controller, skipping %s", __func__);

        condition = condition_new(CONDITION_MEMORY_PRESSURE, " : / ", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) < 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "hopefullythisisnotarealone.slice:100% / 10sec", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) > 0);
        condition_free(condition);

        condition = condition_new(CONDITION_CPU_PRESSURE, "-.slice:100.0% / 1min", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        condition = condition_new(CONDITION_MEMORY_PRESSURE, "-.slice:0.0%/5min", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        condition = condition_new(CONDITION_MEMORY_PRESSURE, "-.slice:100.0%", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);

        condition = condition_new(CONDITION_IO_PRESSURE, "-.slice:0.0%", false, false);
        assert_se(condition);
        assert_se(condition_test(condition, environ) >= 0);
        condition_free(condition);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
