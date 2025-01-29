/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-id128.h"

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
#include "open-file.h"
#include "pcre2-util.h"
#include "rm-rf.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"

/* Nontrivial value serves as a placeholder to check that parsing function (didn't) change it */
#define CGROUP_LIMIT_DUMMY      3

static char *runtime_dir = NULL;

STATIC_DESTRUCTOR_REGISTER(runtime_dir, rm_rf_physical_and_freep);

/* For testing type compatibility. */
_unused_ ConfigPerfItemLookup unused_lookup = load_fragment_gperf_lookup;

TEST_RET(unit_file_get_list) {
        int r;
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        UnitFileList *p;

        r = unit_file_get_list(RUNTIME_SCOPE_SYSTEM, NULL, NULL, NULL, &h);
        if (IN_SET(r, -EPERM, -EACCES))
                return log_tests_skipped_errno(r, "unit_file_get_list");

        log_full_errno(r == 0 ? LOG_INFO : LOG_ERR, r,
                       "unit_file_get_list: %m");
        if (r < 0)
                return EXIT_FAILURE;

        HASHMAP_FOREACH(p, h)
                printf("%s = %s\n", p->path, unit_file_state_to_string(p->state));

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
                 path, argv0 ?: path, strnull(argv1), strnull(argv2));
        n = strv_length(c->argv);
        log_info("actual: \"%s\" [\"%s\" \"%s\" \"%s\"]",
                 c->path, c->argv[0], n > 0 ? c->argv[1] : "(null)", n > 1 ? c->argv[2] : "(null)");
        ASSERT_STREQ(c->path, path);
        ASSERT_STREQ(c->argv[0], argv0 ?: path);
        if (n > 0)
                ASSERT_STREQ(c->argv[1], argv1);
        if (n > 1)
                ASSERT_STREQ(c->argv[2], argv2);
        assert_se(!!(c->flags & EXEC_COMMAND_IGNORE_FAILURE) == ignore);
}

TEST(config_parse_exec) {
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

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test: manager_new: %m");
                return;
        }

        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL, NULL) >= 0);

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
        ASSERT_NULL(c1->command_next);

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
        ASSERT_NULL(c1->command_next);

        log_info("/* no command, whitespace only, reset */");
        r = config_parse_exec(NULL, "fake", 3, "section", 1,
                              "LValue", 0, "",
                              &c, u);
        assert_se(r == 0);
        ASSERT_NULL(c);

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
        ASSERT_NULL(c1->command_next);

        log_info("/* ignore && ignore (2) */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "-@-/RValue argv0 r1",
                              &c, u);
        assert_se(r == 0);
        ASSERT_NULL(c1->command_next);

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

        ASSERT_NULL(c1->command_next);

        log_info("/* trailing semicolon, no whitespace */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "-@/RValue argv0 r1 ;",
                              &c, u);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue", "argv0", "r1", NULL, true);

        ASSERT_NULL(c1->command_next);

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
                ASSERT_NULL(c1->command_next);
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
        ASSERT_NULL(c1->command_next);

        log_info("/* missing ending ' */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "/path 'foo",
                              &c, u);
        assert_se(r == -ENOEXEC);
        ASSERT_NULL(c1->command_next);

        log_info("/* missing ending ' with trailing backslash */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "/path 'foo\\",
                              &c, u);
        assert_se(r == -ENOEXEC);
        ASSERT_NULL(c1->command_next);

        log_info("/* invalid space between modifiers */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "- /path",
                              &c, u);
        assert_se(r == 0);
        ASSERT_NULL(c1->command_next);

        log_info("/* only modifiers, no path */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "-",
                              &c, u);
        assert_se(r == 0);
        ASSERT_NULL(c1->command_next);

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
        ASSERT_NULL(c);

        exec_command_free_list(c);
}

TEST(config_parse_log_extra_fields) {
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

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test: manager_new: %m");
                return;
        }

        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL, NULL) >= 0);

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

TEST(install_printf, .sd_booted = true) {
        char    name[] = "name.service",
                path[] = "/run/systemd/system/name.service";
        InstallInfo i = { .name = name, .path = path, };
        InstallInfo i2 = { .name= name, .path = path, };
        char    name3[] = "name@inst.service",
                path3[] = "/run/systemd/system/name.service";
        InstallInfo i3 = { .name = name3, .path = path3, };
        InstallInfo i4 = { .name = name3, .path = path3, };

        _cleanup_free_ char *mid = NULL, *bid = NULL, *host = NULL, *gid = NULL, *group = NULL, *uid = NULL, *user = NULL;

        if (sd_id128_get_machine(NULL) >= 0)
                assert_se(specifier_machine_id('m', NULL, NULL, NULL, &mid) >= 0 && mid);
        if (sd_booted() > 0)
                assert_se(specifier_boot_id('b', NULL, NULL, NULL, &bid) >= 0 && bid);
        assert_se(host = gethostname_malloc());
        assert_se(group = gid_to_name(getgid()));
        assert_se(asprintf(&gid, UID_FMT, getgid()) >= 0);
        assert_se(user = uid_to_name(getuid()));
        assert_se(asprintf(&uid, UID_FMT, getuid()) >= 0);

#define expect(scope, src, pattern, result)                             \
        do {                                                            \
                _cleanup_free_ char *t = NULL,                          \
                        *d1 = ASSERT_PTR(strdup(i.name)),               \
                        *d2 = ASSERT_PTR(strdup(i.path));               \
                int r = install_name_printf(scope, &src, pattern, &t);  \
                assert_se(result ? r >= 0 : r < 0);                     \
                memzero(i.name, strlen(i.name));                        \
                memzero(i.path, strlen(i.path));                        \
                if (result) {                                           \
                        printf("%s\n", t);                              \
                        ASSERT_STREQ(t, result);                    \
                } else                                                  \
                        assert_se(!t);                                  \
                strcpy(i.name, d1);                                     \
                strcpy(i.path, d2);                                     \
        } while (false)

        expect(RUNTIME_SCOPE_SYSTEM, i, "%n", "name.service");
        expect(RUNTIME_SCOPE_SYSTEM, i, "%N", "name");
        expect(RUNTIME_SCOPE_SYSTEM, i, "%p", "name");
        expect(RUNTIME_SCOPE_SYSTEM, i, "%i", "");
        expect(RUNTIME_SCOPE_SYSTEM, i, "%j", "name");
        expect(RUNTIME_SCOPE_SYSTEM, i, "%g", "root");
        expect(RUNTIME_SCOPE_SYSTEM, i, "%G", "0");
        expect(RUNTIME_SCOPE_SYSTEM, i, "%u", "root");
        expect(RUNTIME_SCOPE_SYSTEM, i, "%U", "0");

        expect(RUNTIME_SCOPE_SYSTEM, i, "%m", mid);
        expect(RUNTIME_SCOPE_SYSTEM, i, "%b", bid);
        expect(RUNTIME_SCOPE_SYSTEM, i, "%H", host);

        expect(RUNTIME_SCOPE_SYSTEM, i2, "%g", "root");
        expect(RUNTIME_SCOPE_SYSTEM, i2, "%G", "0");
        expect(RUNTIME_SCOPE_SYSTEM, i2, "%u", "root");
        expect(RUNTIME_SCOPE_SYSTEM, i2, "%U", "0");

        expect(RUNTIME_SCOPE_USER, i2, "%g", group);
        expect(RUNTIME_SCOPE_USER, i2, "%G", gid);
        expect(RUNTIME_SCOPE_USER, i2, "%u", user);
        expect(RUNTIME_SCOPE_USER, i2, "%U", uid);

        /* gcc-12.0.1-0.9.fc36.x86_64 insist that streq(…, NULL) is called,
         * even though the call is inside of a conditional where the pointer is checked. :( */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull"
        expect(RUNTIME_SCOPE_GLOBAL, i2, "%g", NULL);
        expect(RUNTIME_SCOPE_GLOBAL, i2, "%G", NULL);
        expect(RUNTIME_SCOPE_GLOBAL, i2, "%u", NULL);
        expect(RUNTIME_SCOPE_GLOBAL, i2, "%U", NULL);
#pragma GCC diagnostic pop

        expect(RUNTIME_SCOPE_SYSTEM, i3, "%n", "name@inst.service");
        expect(RUNTIME_SCOPE_SYSTEM, i3, "%N", "name@inst");
        expect(RUNTIME_SCOPE_SYSTEM, i3, "%p", "name");
        expect(RUNTIME_SCOPE_USER, i3, "%g", group);
        expect(RUNTIME_SCOPE_USER, i3, "%G", gid);
        expect(RUNTIME_SCOPE_USER, i3, "%u", user);
        expect(RUNTIME_SCOPE_USER, i3, "%U", uid);

        expect(RUNTIME_SCOPE_SYSTEM, i3, "%m", mid);
        expect(RUNTIME_SCOPE_SYSTEM, i3, "%b", bid);
        expect(RUNTIME_SCOPE_SYSTEM, i3, "%H", host);

        expect(RUNTIME_SCOPE_USER, i4, "%g", group);
        expect(RUNTIME_SCOPE_USER, i4, "%G", gid);
        expect(RUNTIME_SCOPE_USER, i4, "%u", user);
        expect(RUNTIME_SCOPE_USER, i4, "%U", uid);
}

static uint64_t make_cap(int cap) {
        return ((uint64_t) 1ULL << (uint64_t) cap);
}

TEST(config_parse_capability_set) {
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

TEST(config_parse_rlimit) {
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

TEST(config_parse_pass_environ) {
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
        ASSERT_STREQ(passenv[0], "A");
        ASSERT_STREQ(passenv[1], "B");

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
        ASSERT_STREQ(passenv[0], "normal_name");
}

TEST(config_parse_unit_env_file) {
        /* int config_parse_unit_env_file(
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

        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *u;
        _cleanup_strv_free_ char **files = NULL;
        int r;

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test: manager_new: %m");
                return;
        }

        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL, NULL) >= 0);

        assert_se(u = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u, "foobar.service") == 0);

        r = config_parse_unit_env_file(u->id, "fake", 1, "section", 1,
                                      "EnvironmentFile", 0, "not-absolute",
                                       &files, u);
        assert_se(r == 0);
        assert_se(strv_isempty(files));

        r = config_parse_unit_env_file(u->id, "fake", 1, "section", 1,
                                      "EnvironmentFile", 0, "/absolute1",
                                       &files, u);
        assert_se(r == 0);
        assert_se(strv_length(files) == 1);

        r = config_parse_unit_env_file(u->id, "fake", 1, "section", 1,
                                      "EnvironmentFile", 0, "/absolute2",
                                       &files, u);
        assert_se(r == 0);
        assert_se(strv_length(files) == 2);
        ASSERT_STREQ(files[0], "/absolute1");
        ASSERT_STREQ(files[1], "/absolute2");

        r = config_parse_unit_env_file(u->id, "fake", 1, "section", 1,
                                       "EnvironmentFile", 0, "",
                                       &files, u);
        assert_se(r == 0);
        assert_se(strv_isempty(files));

        r = config_parse_unit_env_file(u->id, "fake", 1, "section", 1,
                                       "EnvironmentFile", 0, "/path/%n.conf",
                                       &files, u);
        assert_se(r == 0);
        assert_se(strv_length(files) == 1);
        ASSERT_STREQ(files[0], "/path/foobar.service.conf");
}

TEST(unit_dump_config_items) {
        unit_dump_config_items(stdout);
}

TEST(config_parse_memory_limit) {
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
        int r;

        FOREACH_ELEMENT(test, limit_tests) {
                c.memory_min = CGROUP_LIMIT_DUMMY;
                c.memory_low = CGROUP_LIMIT_DUMMY;
                c.memory_high = CGROUP_LIMIT_DUMMY;
                c.memory_max = CGROUP_LIMIT_DUMMY;
                r = config_parse_memory_limit(NULL, "fake", 1, "section", 1,
                                              test->limit, 1,
                                              test->value, &c, NULL);
                log_info("%s=%s\t%"PRIu64"==%"PRIu64,
                         test->limit, test->value,
                         *test->result, test->expected);
                assert_se(r >= 0);
                assert_se(*test->result == test->expected);
        }
}

TEST(contains_instance_specifier_superset) {
        assert_se(contains_instance_specifier_superset("foobar@a%i"));
        assert_se(contains_instance_specifier_superset("foobar@%ia"));
        assert_se(contains_instance_specifier_superset("foobar@%n"));
        assert_se(contains_instance_specifier_superset("foobar@%n.service"));
        assert_se(contains_instance_specifier_superset("foobar@%N"));
        assert_se(contains_instance_specifier_superset("foobar@%N.service"));
        assert_se(contains_instance_specifier_superset("foobar@baz.%N.service"));
        assert_se(contains_instance_specifier_superset("@%N.service"));
        assert_se(contains_instance_specifier_superset("@%N"));
        assert_se(contains_instance_specifier_superset("@%a%N"));

        assert_se(!contains_instance_specifier_superset("foobar@%i.service"));
        assert_se(!contains_instance_specifier_superset("foobar%ia.service"));
        assert_se(!contains_instance_specifier_superset("foobar@%%n.service"));
        assert_se(!contains_instance_specifier_superset("foobar@baz.service"));
        assert_se(!contains_instance_specifier_superset("%N.service"));
        assert_se(!contains_instance_specifier_superset("%N"));
        assert_se(!contains_instance_specifier_superset("@%aN"));
        assert_se(!contains_instance_specifier_superset("@%a%b"));
}

TEST(unit_is_recursive_template_dependency) {
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *u;
        int r;

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test: manager_new: %m");
                return;
        }

        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL, NULL) >= 0);

        assert_se(u = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u, "foobar@1.service") == 0);
        u->fragment_path = strdup("/foobar@.service");

        assert_se(hashmap_put_strdup(&m->unit_id_map, "foobar@foobar@123.service", "/foobar@.service"));
        assert_se(hashmap_put_strdup(&m->unit_id_map, "foobar@foobar@456.service", "/custom.service"));

        /* Test that %n, %N and any extension of %i specifiers in the instance are detected as recursive. */
        assert_se(unit_is_likely_recursive_template_dependency(u, "foobar@foobar@123.service", "foobar@%N.service") == 1);
        assert_se(unit_is_likely_recursive_template_dependency(u, "foobar@foobar@123.service", "foobar@%n.service") == 1);
        assert_se(unit_is_likely_recursive_template_dependency(u, "foobar@foobar@123.service", "foobar@a%i.service") == 1);
        assert_se(unit_is_likely_recursive_template_dependency(u, "foobar@foobar@123.service", "foobar@%ia.service") == 1);
        assert_se(unit_is_likely_recursive_template_dependency(u, "foobar@foobar@123.service", "foobar@%x%n.service") == 1);
        /* Test that %i on its own is not detected as recursive. */
        assert_se(unit_is_likely_recursive_template_dependency(u, "foobar@foobar@123.service", "foobar@%i.service") == 0);
        /* Test that a specifier other than %i, %n and %N is not detected as recursive. */
        assert_se(unit_is_likely_recursive_template_dependency(u, "foobar@foobar@123.service", "foobar@%xn.service") == 0);
        /* Test that an expanded specifier is not detected as recursive. */
        assert_se(unit_is_likely_recursive_template_dependency(u, "foobar@foobar@123.service", "foobar@foobar@123.service") == 0);
        /* Test that a dependency with a custom fragment path is not detected as recursive. */
        assert_se(unit_is_likely_recursive_template_dependency(u, "foobar@foobar@456.service", "foobar@%n.service") == 0);
        /* Test that a dependency without a fragment path is not detected as recursive. */
        assert_se(unit_is_likely_recursive_template_dependency(u, "foobar@foobar@789.service", "foobar@%n.service") == 0);
        /* Test that a dependency with a different prefix is not detected as recursive. */
        assert_se(unit_is_likely_recursive_template_dependency(u, "quux@foobar@123.service", "quux@%n.service") == 0);
        /* Test that a dependency of a different type is not detected as recursive. */
        assert_se(unit_is_likely_recursive_template_dependency(u, "foobar@foobar@123.mount", "foobar@%n.mount") == 0);
}

#define TEST_PATTERN(_regex, _allowed_patterns_count, _denied_patterns_count)   \
        {                                                                       \
                .regex = _regex,                                                \
                .allowed_patterns_count = _allowed_patterns_count,              \
                .denied_patterns_count = _denied_patterns_count                 \
        }

TEST(config_parse_log_filter_patterns) {
        ExecContext c = {};

        static const struct {
                const char *regex;
                size_t allowed_patterns_count;
                size_t denied_patterns_count;
        } regex_tests[] = {
                TEST_PATTERN("", 0, 0),
                TEST_PATTERN(".*", 1, 0),
                TEST_PATTERN("~.*", 1, 1),
                TEST_PATTERN("", 0, 0),
                TEST_PATTERN("~.*", 0, 1),
                TEST_PATTERN("[.*", 0, 1),              /* Invalid pattern. */
                TEST_PATTERN(".*gg.*", 1, 1),
                TEST_PATTERN("~.*", 1, 1),              /* Already in the patterns list. */
                TEST_PATTERN("[.*", 1, 1),              /* Invalid pattern. */
                TEST_PATTERN("\\x7ehello", 2, 1),
                TEST_PATTERN("", 0, 0),
                TEST_PATTERN("~foobar", 0, 1),
        };

        if (ERRNO_IS_NOT_SUPPORTED(dlopen_pcre2()))
                return (void) log_tests_skipped("PCRE2 support is not available");

        FOREACH_ELEMENT(test, regex_tests) {
                assert_se(config_parse_log_filter_patterns(NULL, "fake", 1, "section", 1, "LogFilterPatterns", 1,
                                                           test->regex, &c, NULL) >= 0);

                assert_se(set_size(c.log_filter_allowed_patterns) == test->allowed_patterns_count);
                assert_se(set_size(c.log_filter_denied_patterns) == test->denied_patterns_count);

                /* Ensure `~` is properly removed */
                const char *p;
                SET_FOREACH(p, c.log_filter_allowed_patterns)
                        assert_se(p && p[0] != '~');
                SET_FOREACH(p, c.log_filter_denied_patterns)
                        assert_se(p && p[0] != '~');
        }

        exec_context_done(&c);
}

TEST(config_parse_open_file) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(unit_freep) Unit *u = NULL;
        _cleanup_(open_file_freep) OpenFile *of = NULL;
        int r;

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test: manager_new: %m");
                return;
        }

        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL, NULL) >= 0);

        assert_se(u = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u, "foobar.service") == 0);

        r = config_parse_open_file(NULL, "fake", 1, "section", 1,
                                   "OpenFile", 0, "/proc/1/ns/mnt:host-mount-namespace:read-only",
                                   &of, u);
        assert_se(r >= 0);
        assert_se(of);
        ASSERT_STREQ(of->path, "/proc/1/ns/mnt");
        ASSERT_STREQ(of->fdname, "host-mount-namespace");
        assert_se(of->flags == OPENFILE_READ_ONLY);

        of = open_file_free(of);
        r = config_parse_open_file(NULL, "fake", 1, "section", 1,
                                   "OpenFile", 0, "/proc/1/ns/mnt::read-only",
                                   &of, u);
        assert_se(r >= 0);
        assert_se(of);
        ASSERT_STREQ(of->path, "/proc/1/ns/mnt");
        ASSERT_STREQ(of->fdname, "mnt");
        assert_se(of->flags == OPENFILE_READ_ONLY);

        r = config_parse_open_file(NULL, "fake", 1, "section", 1,
                                   "OpenFile", 0, "",
                                   &of, u);
        assert_se(r >= 0);
        assert_se(!of);
}

static int intro(void) {
        if (enter_cgroup_subroot(NULL) == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        assert_se(runtime_dir = setup_fake_runtime_dir());
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
