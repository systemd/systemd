/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "apparmor-util.h"
#include "architecture.h"
#include "audit-util.h"
#include "cap-list.h"
#include "cgroup-util.h"
#include "condition.h"
#include "efivars.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "glob-util.h"
#include "hostname-util.h"
#include "ima-util.h"
#include "list.h"
#include "macro.h"
#include "mount-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "tomoyo-util.h"
#include "user-util.h"
#include "util.h"
#include "virt.h"

Condition* condition_new(ConditionType type, const char *parameter, bool trigger, bool negate) {
        Condition *c;
        int r;

        assert(type >= 0);
        assert(type < _CONDITION_TYPE_MAX);
        assert((!parameter) == (type == CONDITION_NULL));

        c = new0(Condition, 1);
        if (!c)
                return NULL;

        c->type = type;
        c->trigger = trigger;
        c->negate = negate;

        r = free_and_strdup(&c->parameter, parameter);
        if (r < 0) {
                return mfree(c);
        }

        return c;
}

void condition_free(Condition *c) {
        assert(c);

        free(c->parameter);
        free(c);
}

Condition* condition_free_list(Condition *first) {
        Condition *c, *n;

        LIST_FOREACH_SAFE(conditions, c, n, first)
                condition_free(c);

        return NULL;
}

static int condition_test_kernel_command_line(Condition *c) {
        _cleanup_free_ char *line = NULL;
        const char *p;
        bool equal;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_KERNEL_COMMAND_LINE);

        r = proc_cmdline(&line);
        if (r < 0)
                return r;

        equal = strchr(c->parameter, '=');

        for (p = line;;) {
                _cleanup_free_ char *word = NULL;
                bool found;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES|EXTRACT_RELAX);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (equal)
                        found = streq(word, c->parameter);
                else {
                        const char *f;

                        f = startswith(word, c->parameter);
                        found = f && IN_SET(*f, 0, '=');
                }

                if (found)
                        return true;
        }

        return false;
}

static int condition_test_kernel_version(Condition *c) {
        enum {
                /* Listed in order of checking. Note that some comparators are prefixes of others, hence the longest
                 * should be listed first. */
                LOWER_OR_EQUAL,
                GREATER_OR_EQUAL,
                LOWER,
                GREATER,
                EQUAL,
                _ORDER_MAX,
        };

        static const char *const prefix[_ORDER_MAX] = {
                [LOWER_OR_EQUAL] = "<=",
                [GREATER_OR_EQUAL] = ">=",
                [LOWER] = "<",
                [GREATER] = ">",
                [EQUAL] = "=",
        };
        const char *p = NULL;
        struct utsname u;
        size_t i;
        int k;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_KERNEL_VERSION);

        assert_se(uname(&u) >= 0);

        for (i = 0; i < _ORDER_MAX; i++) {
                p = startswith(c->parameter, prefix[i]);
                if (p)
                        break;
        }

        /* No prefix? Then treat as glob string */
        if (!p)
                return fnmatch(skip_leading_chars(c->parameter, NULL), u.release, 0) == 0;

        k = str_verscmp(u.release, skip_leading_chars(p, NULL));

        switch (i) {

        case LOWER:
                return k < 0;

        case LOWER_OR_EQUAL:
                return k <= 0;

        case EQUAL:
                return k == 0;

        case GREATER_OR_EQUAL:
                return k >= 0;

        case GREATER:
                return k > 0;

        default:
                assert_not_reached("Can't compare");
        }
}

static int condition_test_user(Condition *c) {
        uid_t id;
        int r;
        _cleanup_free_ char *username = NULL;
        const char *u;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_USER);

        r = parse_uid(c->parameter, &id);
        if (r >= 0)
                return id == getuid() || id == geteuid();

        if (streq("@system", c->parameter))
                return uid_is_system(getuid()) || uid_is_system(geteuid());

        username = getusername_malloc();
        if (!username)
                return -ENOMEM;

        if (streq(username, c->parameter))
                return 1;

        if (getpid_cached() == 1)
                return streq(c->parameter, "root");

        u = c->parameter;
        r = get_user_creds(&u, &id, NULL, NULL, NULL, USER_CREDS_ALLOW_MISSING);
        if (r < 0)
                return 0;

        return id == getuid() || id == geteuid();
}

static int condition_test_control_group_controller(Condition *c) {
        int r;
        CGroupMask system_mask, wanted_mask = 0;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_CONTROL_GROUP_CONTROLLER);

        r = cg_mask_supported(&system_mask);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine supported controllers: %m");

        r = cg_mask_from_string(c->parameter, &wanted_mask);
        if (r < 0 || wanted_mask <= 0) {
                /* This won't catch the case that we have an unknown controller
                 * mixed in with valid ones -- these are only assessed on the
                 * validity of the valid controllers found. */
                log_debug("Failed to parse cgroup string: %s", c->parameter);
                return 1;
        }

        return FLAGS_SET(system_mask, wanted_mask);
}

static int condition_test_group(Condition *c) {
        gid_t id;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_GROUP);

        r = parse_gid(c->parameter, &id);
        if (r >= 0)
                return in_gid(id);

        /* Avoid any NSS lookups if we are PID1 */
        if (getpid_cached() == 1)
                return streq(c->parameter, "root");

        return in_group(c->parameter) > 0;
}

static int condition_test_virtualization(Condition *c) {
        int b, v;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_VIRTUALIZATION);

        if (streq(c->parameter, "private-users"))
                return running_in_userns();

        v = detect_virtualization();
        if (v < 0)
                return v;

        /* First, compare with yes/no */
        b = parse_boolean(c->parameter);
        if (b >= 0)
                return b == !!v;

        /* Then, compare categorization */
        if (streq(c->parameter, "vm"))
                return VIRTUALIZATION_IS_VM(v);

        if (streq(c->parameter, "container"))
                return VIRTUALIZATION_IS_CONTAINER(v);

        /* Finally compare id */
        return v != VIRTUALIZATION_NONE && streq(c->parameter, virtualization_to_string(v));
}

static int condition_test_architecture(Condition *c) {
        int a, b;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_ARCHITECTURE);

        a = uname_architecture();
        if (a < 0)
                return a;

        if (streq(c->parameter, "native"))
                b = native_architecture();
        else {
                b = architecture_from_string(c->parameter);
                if (b < 0) /* unknown architecture? Then it's definitely not ours */
                        return false;
        }

        return a == b;
}

static int condition_test_host(Condition *c) {
        _cleanup_free_ char *h = NULL;
        sd_id128_t x, y;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_HOST);

        if (sd_id128_from_string(c->parameter, &x) >= 0) {

                r = sd_id128_get_machine(&y);
                if (r < 0)
                        return r;

                return sd_id128_equal(x, y);
        }

        h = gethostname_malloc();
        if (!h)
                return -ENOMEM;

        return fnmatch(c->parameter, h, FNM_CASEFOLD) == 0;
}

static int condition_test_ac_power(Condition *c) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_AC_POWER);

        r = parse_boolean(c->parameter);
        if (r < 0)
                return r;

        return (on_ac_power() != 0) == !!r;
}

static int condition_test_security(Condition *c) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_SECURITY);

        if (streq(c->parameter, "selinux"))
                return mac_selinux_use();
        if (streq(c->parameter, "smack"))
                return mac_smack_use();
        if (streq(c->parameter, "apparmor"))
                return mac_apparmor_use();
        if (streq(c->parameter, "audit"))
                return use_audit();
        if (streq(c->parameter, "ima"))
                return use_ima();
        if (streq(c->parameter, "tomoyo"))
                return mac_tomoyo_use();
        if (streq(c->parameter, "uefi-secureboot"))
                return is_efi_secure_boot();

        return false;
}

static int condition_test_capability(Condition *c) {
        unsigned long long capabilities = (unsigned long long) -1;
        _cleanup_fclose_ FILE *f = NULL;
        int value, r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_CAPABILITY);

        /* If it's an invalid capability, we don't have it */
        value = capability_from_name(c->parameter);
        if (value < 0)
                return -EINVAL;

        /* If it's a valid capability we default to assume
         * that we have it */

        f = fopen("/proc/self/status", "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *p;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                p = startswith(line, "CapBnd:");
                if (p) {
                        if (sscanf(line+7, "%llx", &capabilities) != 1)
                                return -EIO;

                        break;
                }
        }

        return !!(capabilities & (1ULL << value));
}

static int condition_test_needs_update(Condition *c) {
        const char *p;
        struct stat usr, other;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_NEEDS_UPDATE);

        /* If the file system is read-only we shouldn't suggest an update */
        if (path_is_read_only_fs(c->parameter) > 0)
                return false;

        /* Any other failure means we should allow the condition to be true,
         * so that we rather invoke too many update tools than too
         * few. */

        if (!path_is_absolute(c->parameter))
                return true;

        p = strjoina(c->parameter, "/.updated");
        if (lstat(p, &other) < 0)
                return true;

        if (lstat("/usr/", &usr) < 0)
                return true;

        /*
         * First, compare seconds as they are always accurate...
         */
        if (usr.st_mtim.tv_sec != other.st_mtim.tv_sec)
                return usr.st_mtim.tv_sec > other.st_mtim.tv_sec;

        /*
         * ...then compare nanoseconds.
         *
         * A false positive is only possible when /usr's nanoseconds > 0
         * (otherwise /usr cannot be strictly newer than the target file)
         * AND the target file's nanoseconds == 0
         * (otherwise the filesystem supports nsec timestamps, see stat(2)).
         */
        if (usr.st_mtim.tv_nsec > 0 && other.st_mtim.tv_nsec == 0) {
                _cleanup_free_ char *timestamp_str = NULL;
                uint64_t timestamp;
                int r;

                r = parse_env_file(NULL, p, NULL, "TIMESTAMP_NSEC", &timestamp_str, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse timestamp file '%s', using mtime: %m", p);
                        return true;
                } else if (r == 0) {
                        log_debug("No data in timestamp file '%s', using mtime", p);
                        return true;
                }

                r = safe_atou64(timestamp_str, &timestamp);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse timestamp value '%s' in file '%s', using mtime: %m", timestamp_str, p);
                        return true;
                }

                timespec_store(&other.st_mtim, timestamp);
        }

        return usr.st_mtim.tv_nsec > other.st_mtim.tv_nsec;
}

static int condition_test_first_boot(Condition *c) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_FIRST_BOOT);

        r = parse_boolean(c->parameter);
        if (r < 0)
                return r;

        return (access("/run/systemd/first-boot", F_OK) >= 0) == !!r;
}

static int condition_test_path_exists(Condition *c) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_EXISTS);

        return access(c->parameter, F_OK) >= 0;
}

static int condition_test_path_exists_glob(Condition *c) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_EXISTS_GLOB);

        return glob_exists(c->parameter) > 0;
}

static int condition_test_path_is_directory(Condition *c) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_DIRECTORY);

        return is_dir(c->parameter, true) > 0;
}

static int condition_test_path_is_symbolic_link(Condition *c) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_SYMBOLIC_LINK);

        return is_symlink(c->parameter) > 0;
}

static int condition_test_path_is_mount_point(Condition *c) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_MOUNT_POINT);

        return path_is_mount_point(c->parameter, NULL, AT_SYMLINK_FOLLOW) > 0;
}

static int condition_test_path_is_read_write(Condition *c) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_READ_WRITE);

        return path_is_read_only_fs(c->parameter) <= 0;
}

static int condition_test_directory_not_empty(Condition *c) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_DIRECTORY_NOT_EMPTY);

        r = dir_is_empty(c->parameter);
        return r <= 0 && r != -ENOENT;
}

static int condition_test_file_not_empty(Condition *c) {
        struct stat st;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_FILE_NOT_EMPTY);

        return (stat(c->parameter, &st) >= 0 &&
                S_ISREG(st.st_mode) &&
                st.st_size > 0);
}

static int condition_test_file_is_executable(Condition *c) {
        struct stat st;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_FILE_IS_EXECUTABLE);

        return (stat(c->parameter, &st) >= 0 &&
                S_ISREG(st.st_mode) &&
                (st.st_mode & 0111));
}

static int condition_test_null(Condition *c) {
        assert(c);
        assert(c->type == CONDITION_NULL);

        /* Note that during parsing we already evaluate the string and
         * store it in c->negate */
        return true;
}

int condition_test(Condition *c) {

        static int (*const condition_tests[_CONDITION_TYPE_MAX])(Condition *c) = {
                [CONDITION_PATH_EXISTS] = condition_test_path_exists,
                [CONDITION_PATH_EXISTS_GLOB] = condition_test_path_exists_glob,
                [CONDITION_PATH_IS_DIRECTORY] = condition_test_path_is_directory,
                [CONDITION_PATH_IS_SYMBOLIC_LINK] = condition_test_path_is_symbolic_link,
                [CONDITION_PATH_IS_MOUNT_POINT] = condition_test_path_is_mount_point,
                [CONDITION_PATH_IS_READ_WRITE] = condition_test_path_is_read_write,
                [CONDITION_DIRECTORY_NOT_EMPTY] = condition_test_directory_not_empty,
                [CONDITION_FILE_NOT_EMPTY] = condition_test_file_not_empty,
                [CONDITION_FILE_IS_EXECUTABLE] = condition_test_file_is_executable,
                [CONDITION_KERNEL_COMMAND_LINE] = condition_test_kernel_command_line,
                [CONDITION_KERNEL_VERSION] = condition_test_kernel_version,
                [CONDITION_VIRTUALIZATION] = condition_test_virtualization,
                [CONDITION_SECURITY] = condition_test_security,
                [CONDITION_CAPABILITY] = condition_test_capability,
                [CONDITION_HOST] = condition_test_host,
                [CONDITION_AC_POWER] = condition_test_ac_power,
                [CONDITION_ARCHITECTURE] = condition_test_architecture,
                [CONDITION_NEEDS_UPDATE] = condition_test_needs_update,
                [CONDITION_FIRST_BOOT] = condition_test_first_boot,
                [CONDITION_USER] = condition_test_user,
                [CONDITION_GROUP] = condition_test_group,
                [CONDITION_CONTROL_GROUP_CONTROLLER] = condition_test_control_group_controller,
                [CONDITION_NULL] = condition_test_null,
        };

        int r, b;

        assert(c);
        assert(c->type >= 0);
        assert(c->type < _CONDITION_TYPE_MAX);

        r = condition_tests[c->type](c);
        if (r < 0) {
                c->result = CONDITION_ERROR;
                return r;
        }

        b = (r > 0) == !c->negate;
        c->result = b ? CONDITION_SUCCEEDED : CONDITION_FAILED;
        return b;
}

void condition_dump(Condition *c, FILE *f, const char *prefix, const char *(*to_string)(ConditionType t)) {
        assert(c);
        assert(f);

        prefix = strempty(prefix);

        fprintf(f,
                "%s\t%s: %s%s%s %s\n",
                prefix,
                to_string(c->type),
                c->trigger ? "|" : "",
                c->negate ? "!" : "",
                c->parameter,
                condition_result_to_string(c->result));
}

void condition_dump_list(Condition *first, FILE *f, const char *prefix, const char *(*to_string)(ConditionType t)) {
        Condition *c;

        LIST_FOREACH(conditions, c, first)
                condition_dump(c, f, prefix, to_string);
}

static const char* const condition_type_table[_CONDITION_TYPE_MAX] = {
        [CONDITION_ARCHITECTURE] = "ConditionArchitecture",
        [CONDITION_VIRTUALIZATION] = "ConditionVirtualization",
        [CONDITION_HOST] = "ConditionHost",
        [CONDITION_KERNEL_COMMAND_LINE] = "ConditionKernelCommandLine",
        [CONDITION_KERNEL_VERSION] = "ConditionKernelVersion",
        [CONDITION_SECURITY] = "ConditionSecurity",
        [CONDITION_CAPABILITY] = "ConditionCapability",
        [CONDITION_AC_POWER] = "ConditionACPower",
        [CONDITION_NEEDS_UPDATE] = "ConditionNeedsUpdate",
        [CONDITION_FIRST_BOOT] = "ConditionFirstBoot",
        [CONDITION_PATH_EXISTS] = "ConditionPathExists",
        [CONDITION_PATH_EXISTS_GLOB] = "ConditionPathExistsGlob",
        [CONDITION_PATH_IS_DIRECTORY] = "ConditionPathIsDirectory",
        [CONDITION_PATH_IS_SYMBOLIC_LINK] = "ConditionPathIsSymbolicLink",
        [CONDITION_PATH_IS_MOUNT_POINT] = "ConditionPathIsMountPoint",
        [CONDITION_PATH_IS_READ_WRITE] = "ConditionPathIsReadWrite",
        [CONDITION_DIRECTORY_NOT_EMPTY] = "ConditionDirectoryNotEmpty",
        [CONDITION_FILE_NOT_EMPTY] = "ConditionFileNotEmpty",
        [CONDITION_FILE_IS_EXECUTABLE] = "ConditionFileIsExecutable",
        [CONDITION_USER] = "ConditionUser",
        [CONDITION_GROUP] = "ConditionGroup",
        [CONDITION_CONTROL_GROUP_CONTROLLER] = "ConditionControlGroupController",
        [CONDITION_NULL] = "ConditionNull"
};

DEFINE_STRING_TABLE_LOOKUP(condition_type, ConditionType);

static const char* const assert_type_table[_CONDITION_TYPE_MAX] = {
        [CONDITION_ARCHITECTURE] = "AssertArchitecture",
        [CONDITION_VIRTUALIZATION] = "AssertVirtualization",
        [CONDITION_HOST] = "AssertHost",
        [CONDITION_KERNEL_COMMAND_LINE] = "AssertKernelCommandLine",
        [CONDITION_KERNEL_VERSION] = "AssertKernelVersion",
        [CONDITION_SECURITY] = "AssertSecurity",
        [CONDITION_CAPABILITY] = "AssertCapability",
        [CONDITION_AC_POWER] = "AssertACPower",
        [CONDITION_NEEDS_UPDATE] = "AssertNeedsUpdate",
        [CONDITION_FIRST_BOOT] = "AssertFirstBoot",
        [CONDITION_PATH_EXISTS] = "AssertPathExists",
        [CONDITION_PATH_EXISTS_GLOB] = "AssertPathExistsGlob",
        [CONDITION_PATH_IS_DIRECTORY] = "AssertPathIsDirectory",
        [CONDITION_PATH_IS_SYMBOLIC_LINK] = "AssertPathIsSymbolicLink",
        [CONDITION_PATH_IS_MOUNT_POINT] = "AssertPathIsMountPoint",
        [CONDITION_PATH_IS_READ_WRITE] = "AssertPathIsReadWrite",
        [CONDITION_DIRECTORY_NOT_EMPTY] = "AssertDirectoryNotEmpty",
        [CONDITION_FILE_NOT_EMPTY] = "AssertFileNotEmpty",
        [CONDITION_FILE_IS_EXECUTABLE] = "AssertFileIsExecutable",
        [CONDITION_USER] = "AssertUser",
        [CONDITION_GROUP] = "AssertGroup",
        [CONDITION_CONTROL_GROUP_CONTROLLER] = "AssertControlGroupController",
        [CONDITION_NULL] = "AssertNull"
};

DEFINE_STRING_TABLE_LOOKUP(assert_type, ConditionType);

static const char* const condition_result_table[_CONDITION_RESULT_MAX] = {
        [CONDITION_UNTESTED] = "untested",
        [CONDITION_SUCCEEDED] = "succeeded",
        [CONDITION_FAILED] = "failed",
        [CONDITION_ERROR] = "error",
};

DEFINE_STRING_TABLE_LOOKUP(condition_result, ConditionResult);
