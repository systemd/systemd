/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <gnu/libc-version.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "apparmor-util.h"
#include "architecture.h"
#include "battery-util.h"
#include "cgroup-util.h"
#include "condition.h"
#include "confidential-virt.h"
#include "cpu-set-util.h"
#include "efivars.h"
#include "env-util.h"
#include "errno-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hostname-setup.h"
#include "id128-util.h"
#include "ima-util.h"
#include "libaudit-util.h"
#include "limits-util.h"
#include "log.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "path-util.h"
#include "psi-util.h"
#include "rm-rf.h"
#include "selinux-util.h"
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

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_EXISTS, "/bin/sh", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_EXISTS, "/bin/s?", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_EXISTS_GLOB, "/bin/s?", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_EXISTS_GLOB, "/bin/s?", false, true)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_EXISTS, "/thiscertainlywontexist", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_EXISTS, "/thiscertainlywontexist", false, true)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_IS_DIRECTORY, "/bin", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_DIRECTORY_NOT_EMPTY, "/bin", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FILE_NOT_EMPTY, "/bin/sh", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FILE_IS_EXECUTABLE, "/bin/sh", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FILE_IS_EXECUTABLE, "/etc/passwd", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/proc", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_IS_MOUNT_POINT, "/bin", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_IS_READ_WRITE, "/tmp", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_IS_ENCRYPTED, "/sys", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        if (access("/run/dbus/system_bus_socket", F_OK) >= 0) {
                ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_IS_SOCKET, "/run/dbus/system_bus_socket", false, false)));
                ASSERT_OK_POSITIVE(condition_test(condition, environ));
                condition_free(condition);
        }

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_IS_SOCKET, "/sys", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_PATH_IS_SYMBOLIC_LINK, "/dev/stdout", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);
}

TEST(condition_test_control_group_hierarchy) {
        Condition *condition;

        ASSERT_NOT_NULL(condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, "v1", false, false));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL(condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, "v2", false, false));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);
}

TEST(condition_test_control_group_controller) {
        Condition *condition;
        CGroupMask system_mask;
        _cleanup_free_ char *controller_name = NULL;

        if (cg_is_available() <= 0)
                return (void) log_tests_skipped("cgroupfs v2 is not mounted");

        /* Invalid controllers are ignored */
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, "thisisnotarealcontroller", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, "thisisnotarealcontroller", false, true)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_OK(cg_mask_supported(&system_mask));

        /* Individual valid controllers one by one */
        for (CGroupController controller = 0; controller < _CGROUP_CONTROLLER_MAX; controller++) {
                const char *local_controller_name = cgroup_controller_to_string(controller);
                log_info("chosen controller is '%s'", local_controller_name);
                if (system_mask & CGROUP_CONTROLLER_TO_MASK(controller)) {
                        log_info("this controller is available");
                        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, local_controller_name, false, false)));
                        ASSERT_OK_POSITIVE(condition_test(condition, environ));
                        condition_free(condition);

                        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, local_controller_name, false, true)));
                        ASSERT_OK_ZERO(condition_test(condition, environ));
                        condition_free(condition);
                } else {
                        log_info("this controller is unavailable");
                        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, local_controller_name, false, false)));
                        ASSERT_OK_ZERO(condition_test(condition, environ));
                        condition_free(condition);

                        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, local_controller_name, false, true)));
                        ASSERT_OK_POSITIVE(condition_test(condition, environ));
                        condition_free(condition);
                }
        }

        /* Multiple valid controllers at the same time */
        ASSERT_OK(cg_mask_to_string(system_mask, &controller_name));

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, strempty(controller_name), false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CONTROL_GROUP_CONTROLLER, strempty(controller_name), false, true)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);
}

TEST(condition_test_ac_power) {
        Condition *condition;

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_AC_POWER, "true", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), on_ac_power());
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_AC_POWER, "false", false, false)));
        ASSERT_OK_NE(condition_test(condition, environ), on_ac_power());
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_AC_POWER, "false", false, true)));
        ASSERT_OK_EQ(condition_test(condition, environ), on_ac_power());
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
        ASSERT_OK(r);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_HOST, SD_ID128_TO_STRING(id), false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_HOST, "garbage value jjjjjjjjjjjjjj", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_HOST, SD_ID128_TO_STRING(id), false, true)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((hostname = gethostname_malloc()));

        /* if hostname looks like an id128 then skip testing it */
        if (id128_is_valid(hostname))
                return (void) log_notice("hostname is an id128, skipping test");

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_HOST, hostname, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);
}

TEST(condition_test_architecture) {
        Condition *condition;
        const char *sa;
        Architecture a;

        ASSERT_OK(a = uname_architecture());
        ASSERT_NOT_NULL((sa = architecture_to_string(a)));

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_ARCHITECTURE, sa, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_ARCHITECTURE, "garbage value", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_ARCHITECTURE, sa, false, true)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);
}

TEST(condition_test_firmware) {
        Condition *condition;

        /* Empty parameter */
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, "", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        /* uefi parameter */
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, "uefi", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), is_efi_boot());
        condition_free(condition);
}

TEST(condition_test_firmware_device_tree) {
        Condition *condition;
        bool is_device_tree_system;

        /* device-tree parameter */
        is_device_tree_system = access("/sys/firmware/devicetree/", F_OK) == 0;

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, "device-tree", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), is_device_tree_system);
        condition_free(condition);

        /* device-tree-compatible parameter */
        if (!is_device_tree_system) {
                ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, "device-tree-compatible()", false, false)));
                ASSERT_OK_ZERO(condition_test(condition, environ));
                condition_free(condition);
        } else {
                _cleanup_free_ char *dtcompat = NULL;
                _cleanup_strv_free_ char **dtcompatlist = NULL;
                size_t dtcompat_size;
                int r;

                r = read_full_virtual_file("/proc/device-tree/compatible", &dtcompat, &dtcompat_size);
                if (r < 0) {
                        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, "device-tree-compatible()", false, false)));
                        if (r == -ENOENT)
                                ASSERT_OK_ZERO(condition_test(condition, environ));
                        else
                                ASSERT_FAIL(condition_test(condition, environ));
                        condition_free(condition);
                        return;
                }

                dtcompatlist = strv_parse_nulstr(dtcompat, dtcompat_size);

                STRV_FOREACH(c, dtcompatlist) {
                        _cleanup_free_ char *expression = NULL;

                        ASSERT_NOT_NULL((expression = strjoin("device-tree-compatible(", *c, ")")));
                        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, expression, false, false)));
                        ASSERT_OK_POSITIVE(condition_test(condition, environ));
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
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, "smbios-field()", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, "smbios-field(malformed)", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, "smbios-field(malformed", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, "smbios-field(malformed=)", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, "smbios-field(malformed=)", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, "smbios-field(not_existing=nothing garbage)", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        /* Test not existing SMBIOS field */
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, "smbios-field(not_existing=nothing)", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
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
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, expression, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        expression = strjoina("smbios-field(bios_vendor$=", quote, bios_vendor, quote, ")");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, expression, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        expression = strjoina("smbios-field(bios_vendor !$= ", quote, bios_vendor, quote, ")");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, expression, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        expression = strjoina("smbios-field(bios_vendor!$=", quote, bios_vendor, quote, ")");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, expression, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        expression = strjoina("smbios-field(bios_vendor $= ", quote,  bios_vendor, "*", quote, ")");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, expression, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        /* Test version comparison with bios_version, if available */
        if (read_virtual_file("/sys/class/dmi/id/bios_version", SIZE_MAX, &bios_version, NULL) <= 0)
                return;

        /* remove trailing newline */
        strstrip(bios_version);

        /* Check if the bios_version contains any spaces we should quote */
        quote = strchr(bios_version, ' ') ? "\"" : "";

        expression = strjoina("smbios-field(bios_version = ", quote, bios_version, quote, ")");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, expression, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        expression = strjoina("smbios-field(bios_version != ", quote, bios_version, quote, ")");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, expression, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        expression = strjoina("smbios-field(bios_version <= ", quote, bios_version, quote, ")");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, expression, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        expression = strjoina("smbios-field(bios_version >= ", quote, bios_version, quote, ")");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, expression, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        expression = strjoina("smbios-field(bios_version < ", quote, bios_version, ".1", quote, ")");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, expression, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        expression = strjoina("smbios-field(bios_version > ", quote, bios_version, ".1", quote, ")");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_FIRMWARE, expression, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);
}

TEST(condition_test_kernel_command_line) {
        Condition *condition;
        int r;

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_KERNEL_COMMAND_LINE, "thisreallyshouldntbeonthekernelcommandline", false, false)));
        r = condition_test(condition, environ);
        if (ERRNO_IS_PRIVILEGE(r))
                return;
        ASSERT_OK_ZERO(r);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_KERNEL_COMMAND_LINE, "andthis=neither", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);
}

TEST(condition_test_kernel_version) {
        Condition *condition;
        struct utsname u;
        const char *v;

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "*thisreallyshouldntbeinthekernelversion*", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "*", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        /* An artificially empty condition. It evaluates to true, but normally
         * such condition cannot be created, because the condition list is reset instead. */
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_OK_ERRNO(uname(&u));

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, u.release, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        strshorten(u.release, 4);
        strcpy(strchr(u.release, 0), "*");

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, u.release, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        /* 0.1.2 would be a very very very old kernel */
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "> 0.1.2", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, ">0.1.2", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "'>0.1.2' '<9.0.0'", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "> 0.1.2 < 9.0.0", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, ">", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, ">= 0.1.2", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "< 0.1.2", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "<= 0.1.2", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "= 0.1.2", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        /* 4711.8.15 is a very very very future kernel */
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "< 4711.8.15", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "<= 4711.8.15", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "= 4711.8.15", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "> 4711.8.15", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, " >= 4711.8.15", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_OK_ERRNO(uname(&u));

        v = strjoina(">=", u.release);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, v, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        v = strjoina("=  ", u.release);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, v, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        v = strjoina("<=", u.release);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, v, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        v = strjoina("> ", u.release);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, v, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        v = strjoina("<   ", u.release);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, v, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);
}

TEST(condition_test_version) {
        Condition *condition;
        const char *v;
        char ver[8];

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd *thisreallyshouldntbeinthesystemdversion*", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd *", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        /* An artificially empty condition. It evaluates to true, but normally
         * such condition cannot be created, because the condition list is reset instead. */
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        /* 42 would be a very very very old systemd release */
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd > 42", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd>42", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd '>42' '<9000'", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd > 42 < 9000", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd>", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd >= 42", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd < 42", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd <= 42", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd = 42", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        /* 9000 is a very very very future systemd release */
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd < 9000", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd <= 9000", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd = 9000", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd > 9000", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "systemd >= 9000", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        xsprintf(ver, "%d", PROJECT_VERSION);

        v = strjoina("systemd>=", ver);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, v, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        v = strjoina("systemd =  ", ver);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, v, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        v = strjoina("systemd<=", ver);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, v, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        v = strjoina("systemd > ", ver);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, v, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        v = strjoina("systemd  <   ", ver);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, v, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        /* Test glibc version */
        bool has = !isempty(gnu_get_libc_version());

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "glibc > 1", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), has);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "glibc < 2", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), !has);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "glibc < 9999", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "glibc > 9999", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        v = strjoina("glibc = ", gnu_get_libc_version());
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, v, false, false)));
        if (has)
                ASSERT_OK_POSITIVE(condition_test(condition, environ));
        else
                ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        v = strjoina("glibc != ", gnu_get_libc_version());
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, v, false, false)));
        if (has)
                ASSERT_OK_ZERO(condition_test(condition, environ));
        else
                ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "glibc $= ?*", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), has);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VERSION, "glibc !$= ?*", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), !has);
        condition_free(condition);
}

TEST(condition_test_credential) {
        _cleanup_(rm_rf_physical_and_freep) char *n1 = NULL, *n2 = NULL;
        _cleanup_free_ char *d1 = NULL, *d2 = NULL, *j = NULL;
        Condition *condition;

        ASSERT_OK(free_and_strdup(&d1, getenv("CREDENTIALS_DIRECTORY")));
        ASSERT_OK(free_and_strdup(&d2, getenv("ENCRYPTED_CREDENTIALS_DIRECTORY")));

        ASSERT_OK_ERRNO(unsetenv("CREDENTIALS_DIRECTORY"));
        ASSERT_OK_ERRNO(unsetenv("ENCRYPTED_CREDENTIALS_DIRECTORY"));

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CREDENTIAL, "definitelymissing", /* trigger= */ false, /* negate= */ false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        /* invalid */
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CREDENTIAL, "..", /* trigger= */ false, /* negate= */ false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_OK(mkdtemp_malloc(NULL, &n1));
        ASSERT_OK(mkdtemp_malloc(NULL, &n2));

        ASSERT_OK_ERRNO(setenv("CREDENTIALS_DIRECTORY", n1, /* overwrite= */ true));
        ASSERT_OK_ERRNO(setenv("ENCRYPTED_CREDENTIALS_DIRECTORY", n2, /* overwrite= */ true));

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CREDENTIAL, "stillmissing", /* trigger= */ false, /* negate= */ false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((j = path_join(n1, "existing")));
        ASSERT_OK(touch(j));
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CREDENTIAL, "existing", /* trigger= */ false, /* negate= */ false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);
        free(j);

        ASSERT_NOT_NULL((j = path_join(n2, "existing-encrypted")));
        ASSERT_OK(touch(j));
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CREDENTIAL, "existing-encrypted", /* trigger= */ false, /* negate= */ false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_OK(set_unset_env("CREDENTIALS_DIRECTORY", d1, /* overwrite= */ true));
        ASSERT_OK(set_unset_env("ENCRYPTED_CREDENTIALS_DIRECTORY", d2, /* overwrite= */ true));
}

#if defined(__i386__) || defined(__x86_64__)
TEST(condition_test_cpufeature) {
        Condition *condition;

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_FEATURE, "fpu", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_FEATURE, "somecpufeaturethatreallydoesntmakesense", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_FEATURE, "a", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);
}
#endif

TEST(condition_test_security) {
        Condition *condition;

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_SECURITY, "garbage oifdsjfoidsjoj", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_SECURITY, "selinux", false, true)));
        ASSERT_OK_NE(condition_test(condition, environ), mac_selinux_use());
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_SECURITY, "apparmor", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), mac_apparmor_use());
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_SECURITY, "tomoyo", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), mac_tomoyo_use());
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_SECURITY, "ima", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), use_ima());
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_SECURITY, "smack", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), mac_smack_use());
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_SECURITY, "audit", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), use_audit());
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_SECURITY, "uefi-secureboot", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ), is_efi_secure_boot());
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_SECURITY, "cvm", false, false)));
        ASSERT_OK_EQ(condition_test(condition, environ),
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

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VIRTUALIZATION, "garbage oifdsjfoidsjoj", false, false)));
        r = condition_test(condition, environ);
        if (ERRNO_IS_PRIVILEGE(r))
                return;
        log_info("ConditionVirtualization=garbage → %i", r);
        ASSERT_OK_ZERO(r);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VIRTUALIZATION, "container", false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionVirtualization=container → %i", r);
        ASSERT_OK_EQ(r, !!detect_container());
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VIRTUALIZATION, "vm", false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionVirtualization=vm → %i", r);
        ASSERT_OK_EQ(r, (detect_vm() && !detect_container()));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_VIRTUALIZATION, "private-users", false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionVirtualization=private-users → %i", r);
        ASSERT_OK_EQ(r, !!running_in_userns());
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

                ASSERT_NOT_NULL((condition = condition_new(CONDITION_VIRTUALIZATION, virt, false, false)));
                r = condition_test(condition, environ);
                log_info("ConditionVirtualization=%s → %i", virt, r);
                ASSERT_OK(r);
                condition_free(condition);
        }
}

TEST(condition_test_user) {
        Condition *condition;
        char* uid;
        char* username;
        int r;

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_USER, "garbage oifdsjfoidsjoj", false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionUser=garbage → %i", r);
        ASSERT_OK_ZERO(r);
        condition_free(condition);

        ASSERT_OK_POSITIVE(asprintf(&uid, "%"PRIu32, UINT32_C(0xFFFF)));
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_USER, uid, false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionUser=%s → %i", uid, r);
        ASSERT_OK_ZERO(r);
        condition_free(condition);
        free(uid);

        ASSERT_OK_POSITIVE(asprintf(&uid, "%u", (unsigned)getuid()));
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_USER, uid, false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionUser=%s → %i", uid, r);
        ASSERT_OK_POSITIVE(r);
        condition_free(condition);
        free(uid);

        ASSERT_OK_POSITIVE(asprintf(&uid, "%u", (unsigned)getuid()+1));
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_USER, uid, false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionUser=%s → %i", uid, r);
        ASSERT_OK_ZERO(r);
        condition_free(condition);
        free(uid);

        ASSERT_NOT_NULL((username = getusername_malloc()));
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_USER, username, false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionUser=%s → %i", username, r);
        ASSERT_OK_POSITIVE(r);
        condition_free(condition);
        free(username);

        username = (char*)(geteuid() == 0 ? NOBODY_USER_NAME : "root");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_USER, username, false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionUser=%s → %i", username, r);
        ASSERT_OK_ZERO(r);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_USER, "@system", false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionUser=@system → %i", r);
        if (uid_is_system(getuid()) || uid_is_system(geteuid()))
                ASSERT_OK_POSITIVE(r);
        else
                ASSERT_OK_ZERO(r);
        condition_free(condition);
}

TEST(condition_test_group) {
        Condition *condition;
        char gid[DECIMAL_STR_MAX(uint32_t)];
        gid_t *gids, max_gid;
        int ngroups_max, ngroups, r, i;

        xsprintf(gid, "%u", UINT32_C(0xFFFF));
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_GROUP, gid, false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionGroup=%s → %i", gid, r);
        ASSERT_OK_ZERO(r);
        condition_free(condition);

        xsprintf(gid, "%u", getgid());
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_GROUP, gid, false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionGroup=%s → %i", gid, r);
        ASSERT_OK_POSITIVE(r);
        condition_free(condition);

        ngroups_max = ASSERT_OK_ERRNO(sysconf(_SC_NGROUPS_MAX));
        ASSERT_GT(ngroups_max, 0);

        gids = newa(gid_t, ngroups_max);

        ngroups = ASSERT_OK_ERRNO(getgroups(ngroups_max, gids));

        max_gid = getgid();
        for (i = 0; i < ngroups; i++) {
                _cleanup_free_ char *name = NULL;

                xsprintf(gid, "%u", gids[i]);
                ASSERT_NOT_NULL((condition = condition_new(CONDITION_GROUP, gid, false, false)));
                r = condition_test(condition, environ);
                log_info("ConditionGroup=%s → %i", gid, r);
                ASSERT_OK_POSITIVE(r);
                condition_free(condition);
                max_gid = gids[i] > max_gid ? gids[i] : max_gid;

                ASSERT_NOT_NULL((name = gid_to_name(gids[i])));
                if (STR_IN_SET(name, "sbuild", "buildd"))
                        return; /* Debian package build in chroot, groupnames won't match, skip */

                ASSERT_NOT_NULL((condition = condition_new(CONDITION_GROUP, name, false, false)));
                r = condition_test(condition, environ);
                log_info("ConditionGroup=%s → %i", name, r);
                ASSERT_OK_POSITIVE(r);
                condition_free(condition);
                max_gid = gids[i] > max_gid ? gids[i] : max_gid;
        }

        xsprintf(gid, "%u", max_gid + 1);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_GROUP, gid, false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionGroup=%s → %i", gid, r);
        ASSERT_OK_ZERO(r);
        condition_free(condition);

        /* In an unprivileged user namespace with the current user mapped to root, all the auxiliary groups
         * of the user will be mapped to the nobody group, which means the user in the user namespace is in
         * both the root and the nobody group, meaning the next test can't work, so let's skip it in that
         * case. */
        if (in_group(NOBODY_GROUP_NAME) && in_group("root"))
                return (void) log_tests_skipped("user is in both root and nobody group");

        const char *groupname = getegid() == 0 ? NOBODY_GROUP_NAME : "root";
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_GROUP, groupname, false, false)));
        r = condition_test(condition, environ);
        log_info("ConditionGroup=%s → %i", groupname, r);
        ASSERT_OK_ZERO(r);
        condition_free(condition);
}

static void test_condition_test_cpus_one(const char *s, bool result) {
        Condition *condition;

        log_debug("%s=%s", condition_type_to_string(CONDITION_CPUS), s);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPUS, s, false, false)));

        ASSERT_OK_EQ(condition_test(condition, environ), result);
        condition_free(condition);
}

TEST(condition_test_cpus) {
        _cleanup_free_ char *t = NULL;
        int cpus;

        cpus = ASSERT_OK(cpus_in_affinity_mask());

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

        ASSERT_OK(asprintf(&t, "= %i", cpus));
        test_condition_test_cpus_one(t, true);
        t = mfree(t);

        ASSERT_OK(asprintf(&t, "<= %i", cpus));
        test_condition_test_cpus_one(t, true);
        t = mfree(t);

        ASSERT_OK(asprintf(&t, ">= %i", cpus));
        test_condition_test_cpus_one(t, true);
        t = mfree(t);

        ASSERT_OK(asprintf(&t, "!= %i", cpus));
        test_condition_test_cpus_one(t, false);
        t = mfree(t);

        ASSERT_OK(asprintf(&t, "< %i", cpus));
        test_condition_test_cpus_one(t, false);
        t = mfree(t);

        ASSERT_OK(asprintf(&t, "> %i", cpus));
        test_condition_test_cpus_one(t, false);
        t = mfree(t);
}

static void test_condition_test_memory_one(const char *s, bool result) {
        Condition *condition;

        log_debug("%s=%s", condition_type_to_string(CONDITION_MEMORY), s);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_MEMORY, s, false, false)));

        ASSERT_OK_EQ(condition_test(condition, environ), result);
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

        ASSERT_OK(asprintf(&t, "= %" PRIu64, memory));
        test_condition_test_memory_one(t, true);
        t = mfree(t);

        ASSERT_OK(asprintf(&t, "<= %" PRIu64, memory));
        test_condition_test_memory_one(t, true);
        t = mfree(t);

        ASSERT_OK(asprintf(&t, ">= %" PRIu64, memory));
        test_condition_test_memory_one(t, true);
        t = mfree(t);

        ASSERT_OK(asprintf(&t, "!= %" PRIu64, memory));
        test_condition_test_memory_one(t, false);
        t = mfree(t);

        ASSERT_OK(asprintf(&t, "< %" PRIu64, memory));
        test_condition_test_memory_one(t, false);
        t = mfree(t);

        ASSERT_OK(asprintf(&t, "> %" PRIu64, memory));
        test_condition_test_memory_one(t, false);
        t = mfree(t);
}

static void test_condition_test_environment_one(const char *s, bool result) {
        Condition *condition;

        log_debug("%s=%s", condition_type_to_string(CONDITION_ENVIRONMENT), s);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_ENVIRONMENT, s, false, false)));

        ASSERT_OK_EQ(condition_test(condition, environ), result);
        condition_free(condition);
}

TEST(condition_test_environment) {
        ASSERT_OK_ERRNO(setenv("EXISTINGENVVAR", "foo", false));

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

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "_THISHOPEFULLYWONTEXIST=01234 56789", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "WRONG FORMAT", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "WRONG!<>=FORMAT", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "WRONG FORMAT=", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "WRONG =FORMAT", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "WRONG = FORMAT", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "WRONGFORMAT=   ", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "WRO NG=FORMAT", false, false)));
        ASSERT_ERROR(condition_test(condition, environ), EINVAL);
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        /* Test shell style globs */

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "ID_LIKE$=*THISHOPEFULLYWONTEXIST*", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "ID_THISHOPEFULLYWONTEXIST$=*rhel*", false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "ID_LIKE!$=*THISHOPEFULLYWONTEXIST*", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, "ID_THISHOPEFULLYWONTEXIST!$=*rhel*", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        /* load_os_release_pairs() removes quotes, we have to add them back,
         * otherwise we get a string: "PRETTY_NAME=Debian GNU/Linux 10 (buster)"
         * which is wrong, as the value is not quoted anymore. */
        const char *quote = strchr(os_release_pairs[1], ' ') ? "\"" : "";
        key_value_pair = strjoina(os_release_pairs[0], "=", quote, os_release_pairs[1], quote);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        key_value_pair = strjoina(os_release_pairs[0], "!=", quote, os_release_pairs[1], quote);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        /* Test fnmatch() operators */
        key_value_pair = strjoina(os_release_pairs[0], "$=", quote, os_release_pairs[1], quote);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        key_value_pair = strjoina(os_release_pairs[0], "!$=", quote, os_release_pairs[1], quote);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        /* Some distros (eg: Arch) do not set VERSION_ID */
        if (parse_os_release(NULL, "VERSION_ID", &version_id) <= 0)
                return;

        key_value_pair = strjoina("VERSION_ID", "=", version_id);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "!=", version_id);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "<=", version_id);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", ">=", version_id);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "<", version_id, ".1");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", ">", version_id, ".1");
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "=", version_id, " ", os_release_pairs[0], "=", quote, os_release_pairs[1], quote);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "!=", version_id, " ", os_release_pairs[0], "=", quote, os_release_pairs[1], quote);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "=", version_id, " ", os_release_pairs[0], "!=", quote, os_release_pairs[1], quote);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "!=", version_id, " ", os_release_pairs[0], "!=", quote, os_release_pairs[1], quote);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        key_value_pair = strjoina("VERSION_ID", "<", version_id, ".1", " ", os_release_pairs[0], "=", quote, os_release_pairs[1], quote);
        ASSERT_NOT_NULL((condition = condition_new(CONDITION_OS_RELEASE, key_value_pair, false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);
}

TEST(condition_test_psi) {
        Condition *condition;
        CGroupMask mask;

        if (!is_pressure_supported())
                return (void) log_notice("Pressure Stall Information (PSI) is not supported, skipping %s", __func__);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_MEMORY_PRESSURE, "", false, false)));
        ASSERT_FAIL(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "sbarabau", false, false)));
        ASSERT_FAIL(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_MEMORY_PRESSURE, "10%sbarabau", false, false)));
        ASSERT_FAIL(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "10% sbarabau", false, false)));
        ASSERT_FAIL(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "-10", false, false)));
        ASSERT_FAIL(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "10%/10min", false, false)));
        ASSERT_FAIL(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "10min/10%", false, false)));
        ASSERT_FAIL(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "10% 5min", false, false)));
        ASSERT_FAIL(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "/5min", false, false)));
        ASSERT_FAIL(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_IO_PRESSURE, "10s /   ", false, false)));
        ASSERT_FAIL(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_MEMORY_PRESSURE, "100%", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_MEMORY_PRESSURE, "0%", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_MEMORY_PRESSURE, "0.0%", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "100%", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "0%", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "0.0%", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "0.01%", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "0.0%/10sec", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "100.0% / 1min", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_IO_PRESSURE, "50.0% / 1min", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        if (cg_is_available() <= 0)
                return (void) log_tests_skipped("cgroupfs v2 is not mounted");

        if (cg_mask_supported(&mask) < 0)
                return (void) log_notice("Failed to get supported cgroup controllers, skipping %s", __func__);

        if (!FLAGS_SET(mask, CGROUP_MASK_MEMORY))
                return (void) log_notice("Requires the cgroup memory controller, skipping %s", __func__);

        if (!FLAGS_SET(mask, CGROUP_MASK_CPU))
                return (void) log_notice("Requires the cgroup CPU controller, skipping %s", __func__);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_MEMORY_PRESSURE, " : / ", false, false)));
        ASSERT_FAIL(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "hopefullythisisnotarealone.slice:100% / 10sec", false, false)));
        ASSERT_OK_POSITIVE(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_CPU_PRESSURE, "-.slice:100.0% / 1min", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_MEMORY_PRESSURE, "-.slice:0.0%/5min", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_MEMORY_PRESSURE, "-.slice:100.0%", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);

        ASSERT_NOT_NULL((condition = condition_new(CONDITION_IO_PRESSURE, "-.slice:0.0%", false, false)));
        ASSERT_OK(condition_test(condition, environ));
        condition_free(condition);
}

TEST(condition_test_kernel_module_loaded) {
        Condition *condition;
        int r;

        condition = ASSERT_NOT_NULL(condition_new(CONDITION_KERNEL_MODULE_LOADED, "", /* trigger= */ false, /* negate= */ false));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        condition = ASSERT_NOT_NULL(condition_new(CONDITION_KERNEL_MODULE_LOADED, "..", /* trigger= */ false, /* negate= */ false));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);

        if (access("/sys/module/", F_OK) < 0)
                return (void) log_tests_skipped("/sys/module not available, skipping.");

        FOREACH_STRING(m, "random", "vfat", "fat", "cec", "binfmt_misc", "binfmt-misc") {
                condition = ASSERT_NOT_NULL(condition_new(CONDITION_KERNEL_MODULE_LOADED, m, /* trigger= */ false, /* negate= */ false));
                r = condition_test(condition, environ);
                ASSERT_OK(r);
                condition_free(condition);

                log_notice("kmod %s is loaded: %s", m, yes_no(r));
        }

        condition = ASSERT_NOT_NULL(condition_new(CONDITION_KERNEL_MODULE_LOADED, "idefinitelydontexist", /* trigger= */ false, /* negate= */ false));
        ASSERT_OK_ZERO(condition_test(condition, environ));
        condition_free(condition);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
