/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "all-units.h"
#include "alloc-util.h"
#include "capability-util.h"
#include "conf-parser.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "hostname-util.h"
#include "install-printf.h"
#include "install.h"
#include "load-fragment.h"
#include "macro.h"
#include "memory-util.h"
#include "rm-rf.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"

/* Nontrivial value serves as a placeholder to check that parsing function (didn't) change it */
#define CGROUP_LIMIT_DUMMY      3

static int test_unit_file_get_set(void) {
        int r;
        Hashmap *h;
        UnitFileList *p;

        h = hashmap_new(&string_hash_ops);
        assert_se(h);

        r = unit_file_get_list(UNIT_FILE_SYSTEM, NULL, h, NULL, NULL);
        if (IN_SET(r, -EPERM, -EACCES))
                return log_tests_skipped_errno(r, "unit_file_get_list");

        log_full_errno(r == 0 ? LOG_INFO : LOG_ERR, r,
                       "unit_file_get_list: %m");
        if (r < 0)
                return EXIT_FAILURE;

        HASHMAP_FOREACH(p, h)
                printf("%s = %s\n", p->path, unit_file_state_to_string(p->state));

        unit_file_list_free(h);

        return 0;
}

static void check_execcommand(ExecCommand *c,
                              const char* path,
                              const char* argv0,
                              const char* argv1,
                              const char* argv2,
                              bool ignore) {
        size_t n;

        assert_se(c);
        log_info("expect: \"%s\" [\"%s\" \"%s\" \"%s\"]",
                 path, argv0 ?: path, argv1, argv2);
        n = strv_length(c->argv);
        log_info("actual: \"%s\" [\"%s\" \"%s\" \"%s\"]",
                 c->path, c->argv[0], n > 0 ? c->argv[1] : NULL, n > 1 ? c->argv[2] : NULL);
        assert_se(streq(c->path, path));
        assert_se(streq(c->argv[0], argv0 ?: path));
        if (n > 0)
                assert_se(streq_ptr(c->argv[1], argv1));
        if (n > 1)
                assert_se(streq_ptr(c->argv[2], argv2));
        assert_se(!!(c->flags & EXEC_COMMAND_IGNORE_FAILURE) == ignore);
}

static void test_config_parse_exec(void) {
        /* int config_parse_exec(
                 const char *unit,
                 const char *filename,
                 unsigned line,
                 const char *section,
                 unsigned section_line,
                 const char *lvalue,
                 int ltype,
                 const char *rvalue,
                 void *data,
                 void *userdata) */
        int r;

        ExecCommand *c = NULL, *c1;
        const char *ccc;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(unit_freep) Unit *u = NULL;

        r = manager_new(UNIT_FILE_USER, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test: manager_new: %m");
                return;
        }

        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);

        assert_se(u = unit_new(m, sizeof(Service)));

        log_info("/* basic test */");
        r = config_parse_exec(NULL, "fake", 1, "section", 1,
                              "LValue", 0, "/RValue r1",
                              &c, u);
        assert_se(r >= 0);
        check_execcommand(c, "/RValue", "/RValue", "r1", NULL, false);

        r = config_parse_exec(NULL, "fake", 2, "section", 1,
                              "LValue", 0, "/RValue///slashes r1///",
                              &c, u);

        log_info("/* test slashes */");
        assert_se(r >= 0);
        c1 = c->command_next;
        check_execcommand(c1, "/RValue/slashes", "/RValue///slashes", "r1///", NULL, false);

        log_info("/* trailing slash */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "/RValue/ argv0 r1",
                              &c, u);
        assert_se(r == -ENOEXEC);
        assert_se(c1->command_next == NULL);

        log_info("/* honour_argv0 */");
        r = config_parse_exec(NULL, "fake", 3, "section", 1,
                              "LValue", 0, "@/RValue///slashes2 ///argv0 r1",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue/slashes2", "///argv0", "r1", NULL, false);

        log_info("/* honour_argv0, no args */");
        r = config_parse_exec(NULL, "fake", 3, "section", 1,
                              "LValue", 0, "@/RValue",
                              &c, u);
        assert_se(r == -ENOEXEC);
        assert_se(c1->command_next == NULL);

        log_info("/* no command, whitespace only, reset */");
        r = config_parse_exec(NULL, "fake", 3, "section", 1,
                              "LValue", 0, "",
                              &c, u);
        assert_se(r == 0);
        assert_se(c == NULL);

        log_info("/* ignore && honour_argv0 */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "-@/RValue///slashes3 argv0a r1",
                              &c, u);
        assert_se(r >= 0);
        c1 = c;
        check_execcommand(c1, "/RValue/slashes3", "argv0a", "r1", NULL, true);

        log_info("/* ignore && honour_argv0 */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "@-/RValue///slashes4 argv0b r1",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue/slashes4", "argv0b", "r1", NULL, true);

        log_info("/* ignore && ignore */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "--/RValue argv0 r1",
                              &c, u);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* ignore && ignore (2) */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "-@-/RValue argv0 r1",
                              &c, u);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* semicolon */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "-@/RValue argv0 r1 ; "
                              "/goo/goo boo",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue", "argv0", "r1", NULL, true);

        c1 = c1->command_next;
        check_execcommand(c1, "/goo/goo", NULL, "boo", NULL, false);

        log_info("/* two semicolons in a row */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "-@/RValue argv0 r1 ; ; "
                              "/goo/goo boo",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue", "argv0", "r1", NULL, true);
        c1 = c1->command_next;
        check_execcommand(c1, "/goo/goo", "/goo/goo", "boo", NULL, false);

        log_info("/* trailing semicolon */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "-@/RValue argv0 r1 ; ",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue", "argv0", "r1", NULL, true);

        assert_se(c1->command_next == NULL);

        log_info("/* trailing semicolon, no whitespace */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "-@/RValue argv0 r1 ;",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue", "argv0", "r1", NULL, true);

        assert_se(c1->command_next == NULL);

        log_info("/* trailing semicolon in single quotes */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "-@/RValue argv0 r1 ';'",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue", "argv0", "r1", ";", true);

        log_info("/* escaped semicolon */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/bin/find \\;",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/bin/find", NULL, ";", NULL, false);

        log_info("/* escaped semicolon with following arg */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/sbin/find \\; /x",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/sbin/find", NULL, ";", "/x", false);

        log_info("/* escaped semicolon as part of an expression */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/sbin/find \\;x",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/sbin/find", NULL, "\\;x", NULL, false);

        log_info("/* encoded semicolon */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/bin/find \\073",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/bin/find", NULL, ";", NULL, false);

        log_info("/* quoted semicolon */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/bin/find \";\"",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/bin/find", NULL, ";", NULL, false);

        log_info("/* quoted semicolon with following arg */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/sbin/find \";\" /x",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/sbin/find", NULL, ";", "/x", false);

        log_info("/* spaces in the filename */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "\"/PATH WITH SPACES/daemon\" -1 -2",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/PATH WITH SPACES/daemon", NULL, "-1", "-2", false);

        log_info("/* spaces in the filename, no args */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "\"/PATH WITH SPACES/daemon -1 -2\"",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/PATH WITH SPACES/daemon -1 -2", NULL, NULL, NULL, false);

        log_info("/* spaces in the filename, everything quoted */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "\"/PATH WITH SPACES/daemon\" \"-1\" '-2'",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/PATH WITH SPACES/daemon", NULL, "-1", "-2", false);

        log_info("/* escaped spaces in the filename */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "\"/PATH\\sWITH\\sSPACES/daemon\" '-1 -2'",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/PATH WITH SPACES/daemon", NULL, "-1 -2", NULL, false);

        log_info("/* escaped spaces in the filename (2) */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "\"/PATH\\x20WITH\\x20SPACES/daemon\" \"-1 -2\"",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/PATH WITH SPACES/daemon", NULL, "-1 -2", NULL, false);

        for (ccc = "abfnrtv\\\'\"x"; *ccc; ccc++) {
                /* \\x is an incomplete hexadecimal sequence, invalid because of the slash */
                char path[] = "/path\\X";
                path[sizeof(path) - 2] = *ccc;

                log_info("/* invalid character: \\%c */", *ccc);
                r = config_parse_exec(NULL, "fake", 4, "section", 1,
                                      "LValue", 0, path,
                                      &c, u);
                assert_se(r == -ENOEXEC);
                assert_se(c1->command_next == NULL);
        }

        log_info("/* valid character: \\s */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "/path\\s",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/path ", NULL, NULL, NULL, false);

        log_info("/* quoted backslashes */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/bin/grep '\\w+\\K'",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/bin/grep", NULL, "\\w+\\K", NULL, false);

        log_info("/* trailing backslash: \\ */");
        /* backslash is invalid */
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "/path\\",
                              &c, u);
        assert_se(r == -ENOEXEC);
        assert_se(c1->command_next == NULL);

        log_info("/* missing ending ' */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "/path 'foo",
                              &c, u);
        assert_se(r == -ENOEXEC);
        assert_se(c1->command_next == NULL);

        log_info("/* missing ending ' with trailing backslash */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "/path 'foo\\",
                              &c, u);
        assert_se(r == -ENOEXEC);
        assert_se(c1->command_next == NULL);

        log_info("/* invalid space between modifiers */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "- /path",
                              &c, u);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* only modifiers, no path */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "-",
                              &c, u);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* long arg */"); /* See issue #22957. */

        char x[LONG_LINE_MAX-100], *y;
        y = mempcpy(x, "/bin/echo ", STRLEN("/bin/echo "));
        memset(y, 'x', sizeof(x) - STRLEN("/bin/echo ") - 1);
        x[sizeof(x) - 1] = '\0';

        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0, x,
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/bin/echo", NULL, y, NULL, false);

        log_info("/* empty argument, reset */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "",
                              &c, u);
        assert_se(r == 0);
        assert_se(c == NULL);

        exec_command_free_list(c);
}

static void test_config_parse_log_extra_fields(void) {
        /* int config_parse_log_extra_fields(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) */

        int r;

        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(unit_freep) Unit *u = NULL;
        ExecContext c = {};

        r = manager_new(UNIT_FILE_USER, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test: manager_new: %m");
                return;
        }

        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);

        assert_se(u = unit_new(m, sizeof(Service)));

        log_info("/* %s – basic test */", __func__);
        r = config_parse_log_extra_fields(NULL, "fake", 1, "section", 1,
                                          "LValue", 0, "FOO=BAR \"QOOF=quux '  ' \"",
                                          &c, u);
        assert_se(r >= 0);
        assert_se(c.n_log_extra_fields == 2);
        assert_se(strneq(c.log_extra_fields[0].iov_base, "FOO=BAR", c.log_extra_fields[0].iov_len));
        assert_se(strneq(c.log_extra_fields[1].iov_base, "QOOF=quux '  ' ", c.log_extra_fields[1].iov_len));

        log_info("/* %s – add some */", __func__);
        r = config_parse_log_extra_fields(NULL, "fake", 1, "section", 1,
                                          "LValue", 0, "FOO2=BAR2 QOOF2=quux '  '",
                                          &c, u);
        assert_se(r >= 0);
        assert_se(c.n_log_extra_fields == 4);
        assert_se(strneq(c.log_extra_fields[0].iov_base, "FOO=BAR", c.log_extra_fields[0].iov_len));
        assert_se(strneq(c.log_extra_fields[1].iov_base, "QOOF=quux '  ' ", c.log_extra_fields[1].iov_len));
        assert_se(strneq(c.log_extra_fields[2].iov_base, "FOO2=BAR2", c.log_extra_fields[2].iov_len));
        assert_se(strneq(c.log_extra_fields[3].iov_base, "QOOF2=quux", c.log_extra_fields[3].iov_len));

        exec_context_dump(&c, stdout, "    --> ");

        log_info("/* %s – reset */", __func__);
        r = config_parse_log_extra_fields(NULL, "fake", 1, "section", 1,
                                          "LValue", 0, "",
                                          &c, u);
        assert_se(r >= 0);
        assert_se(c.n_log_extra_fields == 0);

        exec_context_free_log_extra_fields(&c);

        log_info("/* %s – bye */", __func__);
}

static void test_install_printf(void) {
        char    name[] = "name.service",
                path[] = "/run/systemd/system/name.service";
        UnitFileInstallInfo i = { .name = name, .path = path, };
        UnitFileInstallInfo i2 = { .name= name, .path = path, };
        char    name3[] = "name@inst.service",
                path3[] = "/run/systemd/system/name.service";
        UnitFileInstallInfo i3 = { .name = name3, .path = path3, };
        UnitFileInstallInfo i4 = { .name = name3, .path = path3, };

        _cleanup_free_ char *mid = NULL, *bid = NULL, *host = NULL, *gid = NULL, *group = NULL, *uid = NULL, *user = NULL;

        assert_se(specifier_machine_id('m', NULL, NULL, NULL, &mid) >= 0 && mid);
        assert_se(specifier_boot_id('b', NULL, NULL, NULL, &bid) >= 0 && bid);
        assert_se(host = gethostname_malloc());
        assert_se(group = gid_to_name(getgid()));
        assert_se(asprintf(&gid, UID_FMT, getgid()) >= 0);
        assert_se(user = uid_to_name(getuid()));
        assert_se(asprintf(&uid, UID_FMT, getuid()) >= 0);

#define expect(src, pattern, result)                                    \
        do {                                                            \
                _cleanup_free_ char *t = NULL;                          \
                _cleanup_free_ char                                     \
                        *d1 = strdup(i.name),                           \
                        *d2 = strdup(i.path);                           \
                assert_se(install_name_printf(&src, pattern, NULL, &t) >= 0 || !result); \
                memzero(i.name, strlen(i.name));                        \
                memzero(i.path, strlen(i.path));                        \
                assert_se(d1 && d2);                                    \
                if (result) {                                           \
                        printf("%s\n", t);                              \
                        assert_se(streq(t, result));                    \
                } else assert_se(t == NULL);                            \
                strcpy(i.name, d1);                                     \
                strcpy(i.path, d2);                                     \
        } while (false)

        expect(i, "%n", "name.service");
        expect(i, "%N", "name");
        expect(i, "%p", "name");
        expect(i, "%i", "");
        expect(i, "%j", "name");
        expect(i, "%g", group);
        expect(i, "%G", gid);
        expect(i, "%u", user);
        expect(i, "%U", uid);

        expect(i, "%m", mid);
        expect(i, "%b", bid);
        expect(i, "%H", host);

        expect(i2, "%g", group);
        expect(i2, "%G", gid);
        expect(i2, "%u", user);
        expect(i2, "%U", uid);

        expect(i3, "%n", "name@inst.service");
        expect(i3, "%N", "name@inst");
        expect(i3, "%p", "name");
        expect(i3, "%g", group);
        expect(i3, "%G", gid);
        expect(i3, "%u", user);
        expect(i3, "%U", uid);

        expect(i3, "%m", mid);
        expect(i3, "%b", bid);
        expect(i3, "%H", host);

        expect(i4, "%g", group);
        expect(i4, "%G", gid);
        expect(i4, "%u", user);
        expect(i4, "%U", uid);
}

static uint64_t make_cap(int cap) {
        return ((uint64_t) 1ULL << (uint64_t) cap);
}

static void test_config_parse_capability_set(void) {
        /* int config_parse_capability_set(
                 const char *unit,
                 const char *filename,
                 unsigned line,
                 const char *section,
                 unsigned section_line,
                 const char *lvalue,
                 int ltype,
                 const char *rvalue,
                 void *data,
                 void *userdata) */
        int r;
        uint64_t capability_bounding_set = 0;

        r = config_parse_capability_set(NULL, "fake", 1, "section", 1,
                              "CapabilityBoundingSet", 0, "CAP_NET_RAW",
                              &capability_bounding_set, NULL);
        assert_se(r >= 0);
        assert_se(capability_bounding_set == make_cap(CAP_NET_RAW));

        r = config_parse_capability_set(NULL, "fake", 1, "section", 1,
                              "CapabilityBoundingSet", 0, "CAP_NET_ADMIN",
                              &capability_bounding_set, NULL);
        assert_se(r >= 0);
        assert_se(capability_bounding_set == (make_cap(CAP_NET_RAW) | make_cap(CAP_NET_ADMIN)));

        r = config_parse_capability_set(NULL, "fake", 1, "section", 1,
                              "CapabilityBoundingSet", 0, "~CAP_NET_ADMIN",
                              &capability_bounding_set, NULL);
        assert_se(r >= 0);
        assert_se(capability_bounding_set == make_cap(CAP_NET_RAW));

        r = config_parse_capability_set(NULL, "fake", 1, "section", 1,
                              "CapabilityBoundingSet", 0, "",
                              &capability_bounding_set, NULL);
        assert_se(r >= 0);
        assert_se(capability_bounding_set == UINT64_C(0));

        r = config_parse_capability_set(NULL, "fake", 1, "section", 1,
                              "CapabilityBoundingSet", 0, "~",
                              &capability_bounding_set, NULL);
        assert_se(r >= 0);
        assert_se(cap_test_all(capability_bounding_set));

        capability_bounding_set = 0;
        r = config_parse_capability_set(NULL, "fake", 1, "section", 1,
                              "CapabilityBoundingSet", 0, "  'CAP_NET_RAW' WAT_CAP??? CAP_NET_ADMIN CAP'_trailing_garbage",
                              &capability_bounding_set, NULL);
        assert_se(r >= 0);
        assert_se(capability_bounding_set == (make_cap(CAP_NET_RAW) | make_cap(CAP_NET_ADMIN)));
}

static void test_config_parse_rlimit(void) {
        struct rlimit * rl[_RLIMIT_MAX] = {};

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitNOFILE", RLIMIT_NOFILE, "55", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_NOFILE]);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == 55);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == rl[RLIMIT_NOFILE]->rlim_max);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitNOFILE", RLIMIT_NOFILE, "55:66", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_NOFILE]);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == 55);
        assert_se(rl[RLIMIT_NOFILE]->rlim_max == 66);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitNOFILE", RLIMIT_NOFILE, "infinity", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_NOFILE]);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == RLIM_INFINITY);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == rl[RLIMIT_NOFILE]->rlim_max);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitNOFILE", RLIMIT_NOFILE, "infinity:infinity", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_NOFILE]);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == RLIM_INFINITY);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == rl[RLIMIT_NOFILE]->rlim_max);

        rl[RLIMIT_NOFILE]->rlim_cur = 10;
        rl[RLIMIT_NOFILE]->rlim_max = 20;

        /* Invalid values don't change rl */
        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitNOFILE", RLIMIT_NOFILE, "10:20:30", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_NOFILE]);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == 10);
        assert_se(rl[RLIMIT_NOFILE]->rlim_max == 20);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitNOFILE", RLIMIT_NOFILE, "wat:wat", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_NOFILE]);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == 10);
        assert_se(rl[RLIMIT_NOFILE]->rlim_max == 20);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitNOFILE", RLIMIT_NOFILE, "66:wat", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_NOFILE]);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == 10);
        assert_se(rl[RLIMIT_NOFILE]->rlim_max == 20);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitNOFILE", RLIMIT_NOFILE, "200:100", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_NOFILE]);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == 10);
        assert_se(rl[RLIMIT_NOFILE]->rlim_max == 20);

        rl[RLIMIT_NOFILE] = mfree(rl[RLIMIT_NOFILE]);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitCPU", RLIMIT_CPU, "56", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_CPU]);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == 56);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == rl[RLIMIT_CPU]->rlim_max);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitCPU", RLIMIT_CPU, "57s", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_CPU]);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == 57);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == rl[RLIMIT_CPU]->rlim_max);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitCPU", RLIMIT_CPU, "40s:1m", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_CPU]);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == 40);
        assert_se(rl[RLIMIT_CPU]->rlim_max == 60);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitCPU", RLIMIT_CPU, "infinity", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_CPU]);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == RLIM_INFINITY);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == rl[RLIMIT_CPU]->rlim_max);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitCPU", RLIMIT_CPU, "1234ms", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_CPU]);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == 2);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == rl[RLIMIT_CPU]->rlim_max);

        rl[RLIMIT_CPU] = mfree(rl[RLIMIT_CPU]);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitRTTIME", RLIMIT_RTTIME, "58", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_RTTIME]);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == 58);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == rl[RLIMIT_RTTIME]->rlim_max);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitRTTIME", RLIMIT_RTTIME, "58:60", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_RTTIME]);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == 58);
        assert_se(rl[RLIMIT_RTTIME]->rlim_max == 60);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitRTTIME", RLIMIT_RTTIME, "59s", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_RTTIME]);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == 59 * USEC_PER_SEC);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == rl[RLIMIT_RTTIME]->rlim_max);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitRTTIME", RLIMIT_RTTIME, "59s:123s", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_RTTIME]);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == 59 * USEC_PER_SEC);
        assert_se(rl[RLIMIT_RTTIME]->rlim_max == 123 * USEC_PER_SEC);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitRTTIME", RLIMIT_RTTIME, "infinity", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_RTTIME]);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == RLIM_INFINITY);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == rl[RLIMIT_RTTIME]->rlim_max);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitRTTIME", RLIMIT_RTTIME, "infinity:infinity", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_RTTIME]);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == RLIM_INFINITY);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == rl[RLIMIT_RTTIME]->rlim_max);

        assert_se(config_parse_rlimit(NULL, "fake", 1, "section", 1, "LimitRTTIME", RLIMIT_RTTIME, "2345ms", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_RTTIME]);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == 2345 * USEC_PER_MSEC);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == rl[RLIMIT_RTTIME]->rlim_max);

        rl[RLIMIT_RTTIME] = mfree(rl[RLIMIT_RTTIME]);
}

static void test_config_parse_pass_environ(void) {
        /* int config_parse_pass_environ(
                 const char *unit,
                 const char *filename,
                 unsigned line,
                 const char *section,
                 unsigned section_line,
                 const char *lvalue,
                 int ltype,
                 const char *rvalue,
                 void *data,
                 void *userdata) */
        int r;
        _cleanup_strv_free_ char **passenv = NULL;

        r = config_parse_pass_environ(NULL, "fake", 1, "section", 1,
                                      "PassEnvironment", 0, "A B",
                                      &passenv, NULL);
        assert_se(r >= 0);
        assert_se(strv_length(passenv) == 2);
        assert_se(streq(passenv[0], "A"));
        assert_se(streq(passenv[1], "B"));

        r = config_parse_pass_environ(NULL, "fake", 1, "section", 1,
                                      "PassEnvironment", 0, "",
                                      &passenv, NULL);
        assert_se(r >= 0);
        assert_se(strv_isempty(passenv));

        r = config_parse_pass_environ(NULL, "fake", 1, "section", 1,
                                      "PassEnvironment", 0, "'invalid name' 'normal_name' A=1 'special_name$$' \\",
                                      &passenv, NULL);
        assert_se(r >= 0);
        assert_se(strv_length(passenv) == 1);
        assert_se(streq(passenv[0], "normal_name"));
}

static void test_unit_dump_config_items(void) {
        unit_dump_config_items(stdout);
}

static void test_config_parse_memory_limit(void) {
        /* int config_parse_memory_limit(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) */
        CGroupContext c;
        struct limit_test {
                const char *limit;
                const char *value;
                uint64_t *result;
                uint64_t expected;
        } limit_tests[]= {
                { "MemoryMin",  "",             &c.memory_min,  CGROUP_LIMIT_MIN },
                { "MemoryMin",  "0",            &c.memory_min,  CGROUP_LIMIT_MIN },
                { "MemoryMin",  "10",           &c.memory_min,  10 },
                { "MemoryMin",  "infinity",     &c.memory_min,  CGROUP_LIMIT_MAX },
                { "MemoryLow",  "",             &c.memory_low,  CGROUP_LIMIT_MIN },
                { "MemoryLow",  "0",            &c.memory_low,  CGROUP_LIMIT_MIN },
                { "MemoryLow",  "10",           &c.memory_low,  10 },
                { "MemoryLow",  "infinity",     &c.memory_low,  CGROUP_LIMIT_MAX },
                { "MemoryHigh", "",             &c.memory_high, CGROUP_LIMIT_MAX },
                { "MemoryHigh", "0",            &c.memory_high, CGROUP_LIMIT_DUMMY },
                { "MemoryHigh", "10",           &c.memory_high, 10 },
                { "MemoryHigh", "infinity",     &c.memory_high, CGROUP_LIMIT_MAX },
                { "MemoryMax",  "",             &c.memory_max,  CGROUP_LIMIT_MAX },
                { "MemoryMax",  "0",            &c.memory_max,  CGROUP_LIMIT_DUMMY },
                { "MemoryMax",  "10",           &c.memory_max,  10 },
                { "MemoryMax",  "infinity",     &c.memory_max,  CGROUP_LIMIT_MAX },
        };
        size_t i;
        int r;

        for (i = 0; i < ELEMENTSOF(limit_tests); i++) {
                c.memory_min = CGROUP_LIMIT_DUMMY;
                c.memory_low = CGROUP_LIMIT_DUMMY;
                c.memory_high = CGROUP_LIMIT_DUMMY;
                c.memory_max = CGROUP_LIMIT_DUMMY;
                r = config_parse_memory_limit(NULL, "fake", 1, "section", 1,
                                              limit_tests[i].limit, 1,
                                              limit_tests[i].value, &c, NULL);
                log_info("%s=%s\t%"PRIu64"==%"PRIu64"\n",
                         limit_tests[i].limit, limit_tests[i].value,
                         *limit_tests[i].result, limit_tests[i].expected);
                assert_se(r >= 0);
                assert_se(*limit_tests[i].result == limit_tests[i].expected);
        }

}

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        int r;

        test_setup_logging(LOG_INFO);

        r = enter_cgroup_subroot(NULL);
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        assert_se(runtime_dir = setup_fake_runtime_dir());

        r = test_unit_file_get_set();
        test_config_parse_exec();
        test_config_parse_log_extra_fields();
        test_config_parse_capability_set();
        test_config_parse_rlimit();
        test_config_parse_pass_environ();
        TEST_REQ_RUNNING_SYSTEMD(test_install_printf());
        test_unit_dump_config_items();
        test_config_parse_memory_limit();

        return r;
}
