/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <errno.h>
#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "apparmor-util.h"
#include "architecture.h"
#include "audit-util.h"
#include "cap-list.h"
#include "condition.h"
#include "extract-word.h"
#include "fd-util.h"
#include "glob-util.h"
#include "hostname-util.h"
#include "ima-util.h"
#include "mount-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
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
                free(c);
                return NULL;
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

        equal = !!strchr(c->parameter, '=');
        p = line;

        for (;;) {
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
                        found = f && (*f == '=' || *f == 0);
                }

                if (found)
                        return true;
        }

        return false;
}

static int condition_test_virtualization(Condition *c) {
        int b, v;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_VIRTUALIZATION);

        v = detect_virtualization();
        if (v < 0)
                return v;

        /* First, compare with yes/no */
        b = parse_boolean(c->parameter);

        if (v > 0 && b > 0)
                return true;

        if (v == 0 && b == 0)
                return true;

        /* Then, compare categorization */
        if (VIRTUALIZATION_IS_VM(v) && streq(c->parameter, "vm"))
                return true;

        if (VIRTUALIZATION_IS_CONTAINER(v) && streq(c->parameter, "container"))
                return true;

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
        else
                b = architecture_from_string(c->parameter);
        if (b < 0)
                return b;

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

        return false;
}

static int condition_test_capability(Condition *c) {
        _cleanup_fclose_ FILE *f = NULL;
        int value;
        char line[LINE_MAX];
        unsigned long long capabilities = -1;

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

        while (fgets(line, sizeof(line), f)) {
                truncate_nl(line);

                if (startswith(line, "CapBnd:")) {
                        (void) sscanf(line+7, "%llx", &capabilities);
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
         * so that we rather invoke too many update tools then too
         * few. */

        if (!path_is_absolute(c->parameter))
                return true;

        p = strjoina(c->parameter, "/.updated");
        if (lstat(p, &other) < 0)
                return true;

        if (lstat("/usr/", &usr) < 0)
                return true;

        return usr.st_mtim.tv_sec > other.st_mtim.tv_sec ||
                (usr.st_mtim.tv_sec == other.st_mtim.tv_sec && usr.st_mtim.tv_nsec > other.st_mtim.tv_nsec);
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

        return path_is_mount_point(c->parameter, AT_SYMLINK_FOLLOW) > 0;
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
                [CONDITION_VIRTUALIZATION] = condition_test_virtualization,
                [CONDITION_SECURITY] = condition_test_security,
                [CONDITION_CAPABILITY] = condition_test_capability,
                [CONDITION_HOST] = condition_test_host,
                [CONDITION_AC_POWER] = condition_test_ac_power,
                [CONDITION_ARCHITECTURE] = condition_test_architecture,
                [CONDITION_NEEDS_UPDATE] = condition_test_needs_update,
                [CONDITION_FIRST_BOOT] = condition_test_first_boot,
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

        if (!prefix)
                prefix = "";

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
        [CONDITION_NULL] = "ConditionNull"
};

DEFINE_STRING_TABLE_LOOKUP(condition_type, ConditionType);

static const char* const assert_type_table[_CONDITION_TYPE_MAX] = {
        [CONDITION_ARCHITECTURE] = "AssertArchitecture",
        [CONDITION_VIRTUALIZATION] = "AssertVirtualization",
        [CONDITION_HOST] = "AssertHost",
        [CONDITION_KERNEL_COMMAND_LINE] = "AssertKernelCommandLine",
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
