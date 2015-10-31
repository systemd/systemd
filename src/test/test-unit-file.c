/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/capability.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "hostname-util.h"
#include "install-printf.h"
#include "install.h"
#include "load-fragment.h"
#include "macro.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "test-helper.h"
#include "user-util.h"
#include "util.h"

static int test_unit_file_get_set(void) {
        int r;
        Hashmap *h;
        Iterator i;
        UnitFileList *p;

        h = hashmap_new(&string_hash_ops);
        assert_se(h);

        r = unit_file_get_list(UNIT_FILE_SYSTEM, NULL, h);

        if (r == -EPERM || r == -EACCES) {
                printf("Skipping test: unit_file_get_list: %s", strerror(-r));
                return EXIT_TEST_SKIP;
        }

        log_full(r == 0 ? LOG_INFO : LOG_ERR,
                 "unit_file_get_list: %s", strerror(-r));
        if (r < 0)
                return EXIT_FAILURE;

        HASHMAP_FOREACH(p, h, i)
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
        assert_se(c->ignore == ignore);
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

        log_info("/* basic test */");
        r = config_parse_exec(NULL, "fake", 1, "section", 1,
                              "LValue", 0, "/RValue r1",
                              &c, NULL);
        assert_se(r >= 0);
        check_execcommand(c, "/RValue", "/RValue", "r1", NULL, false);

        r = config_parse_exec(NULL, "fake", 2, "section", 1,
                              "LValue", 0, "/RValue///slashes r1///",
                              &c, NULL);

        log_info("/* test slashes */");
        assert_se(r >= 0);
        c1 = c->command_next;
        check_execcommand(c1, "/RValue/slashes", "/RValue///slashes", "r1///", NULL, false);

        log_info("/* trailing slash */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "/RValue/ argv0 r1",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* honour_argv0 */");
        r = config_parse_exec(NULL, "fake", 3, "section", 1,
                              "LValue", 0, "@/RValue///slashes2 ///argv0 r1",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue/slashes2", "///argv0", "r1", NULL, false);

        log_info("/* honour_argv0, no args */");
        r = config_parse_exec(NULL, "fake", 3, "section", 1,
                              "LValue", 0, "@/RValue",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* no command, whitespace only, reset */");
        r = config_parse_exec(NULL, "fake", 3, "section", 1,
                              "LValue", 0, "    ",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c == NULL);

        log_info("/* ignore && honour_argv0 */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "-@/RValue///slashes3 argv0a r1",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c;
        check_execcommand(c1, "/RValue/slashes3", "argv0a", "r1", NULL, true);

        log_info("/* ignore && honour_argv0 */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "@-/RValue///slashes4 argv0b r1",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue/slashes4", "argv0b", "r1", NULL, true);

        log_info("/* ignore && ignore */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "--/RValue argv0 r1",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* ignore && ignore (2) */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "-@-/RValue argv0 r1",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* semicolon */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "-@/RValue argv0 r1 ; "
                              "/goo/goo boo",
                              &c, NULL);
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
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue", "argv0", "r1", NULL, true);

        /* second command fails because the executable name is ";" */
        assert_se(c1->command_next == NULL);

        log_info("/* trailing semicolon */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "-@/RValue argv0 r1 ; ",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue", "argv0", "r1", NULL, true);

        assert_se(c1->command_next == NULL);

        log_info("/* trailing semicolon, no whitespace */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "-@/RValue argv0 r1 ;",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue", "argv0", "r1", NULL, true);

        assert_se(c1->command_next == NULL);

        log_info("/* trailing semicolon in single quotes */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "-@/RValue argv0 r1 ';'",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue", "argv0", "r1", ";", true);

        log_info("/* escaped semicolon */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/bin/find \\;",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/bin/find", NULL, ";", NULL, false);

        log_info("/* escaped semicolon with following arg */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/sbin/find \\; /x",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/sbin/find", NULL, ";", "/x", false);

        log_info("/* escaped semicolon as part of an expression */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/sbin/find \\;x",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/sbin/find", NULL, "\\;x", NULL, false);

        log_info("/* encoded semicolon */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/bin/find \\073",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/bin/find", NULL, ";", NULL, false);

        log_info("/* quoted semicolon */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/bin/find \";\"",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/bin/find", NULL, ";", NULL, false);

        log_info("/* quoted semicolon with following arg */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/sbin/find \";\" /x",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/sbin/find", NULL, ";", "/x", false);

        log_info("/* spaces in the filename */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "\"/PATH WITH SPACES/daemon\" -1 -2",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/PATH WITH SPACES/daemon", NULL, "-1", "-2", false);

        log_info("/* spaces in the filename, no args */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "\"/PATH WITH SPACES/daemon -1 -2\"",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/PATH WITH SPACES/daemon -1 -2", NULL, NULL, NULL, false);

        log_info("/* spaces in the filename, everything quoted */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "\"/PATH WITH SPACES/daemon\" \"-1\" '-2'",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/PATH WITH SPACES/daemon", NULL, "-1", "-2", false);

        log_info("/* escaped spaces in the filename */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "\"/PATH\\sWITH\\sSPACES/daemon\" '-1 -2'",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/PATH WITH SPACES/daemon", NULL, "-1 -2", NULL, false);

        log_info("/* escaped spaces in the filename (2) */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "\"/PATH\\x20WITH\\x20SPACES/daemon\" \"-1 -2\"",
                              &c, NULL);
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
                                      &c, NULL);
                assert_se(r == 0);
                assert_se(c1->command_next == NULL);
        }

        log_info("/* valid character: \\s */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "/path\\s",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/path ", NULL, NULL, NULL, false);

        log_info("/* quoted backslashes */");
        r = config_parse_exec(NULL, "fake", 5, "section", 1,
                              "LValue", 0,
                              "/bin/grep '\\w+\\K'",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/bin/grep", NULL, "\\w+\\K", NULL, false);


        log_info("/* trailing backslash: \\ */");
        /* backslash is invalid */
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "/path\\",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* missing ending ' */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "/path 'foo",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* missing ending ' with trailing backslash */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "/path 'foo\\",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* invalid space between modifiers */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "- /path",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* only modifiers, no path */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "-",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        log_info("/* empty argument, reset */");
        r = config_parse_exec(NULL, "fake", 4, "section", 1,
                              "LValue", 0, "",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c == NULL);

        exec_command_free_list(c);
}

#define env_file_1                              \
        "a=a\n"                                 \
        "b=b\\\n"                               \
        "c\n"                                   \
        "d=d\\\n"                               \
        "e\\\n"                                 \
        "f\n"                                   \
        "g=g\\ \n"                              \
        "h=h\n"                                 \
        "i=i\\"

#define env_file_2                              \
        "a=a\\\n"

#define env_file_3 \
        "#SPAMD_ARGS=\"-d --socketpath=/var/lib/bulwark/spamd \\\n" \
        "#--nouser-config                                     \\\n" \
        "normal=line"

#define env_file_4 \
       "# Generated\n" \
       "\n" \
       "HWMON_MODULES=\"coretemp f71882fg\"\n" \
       "\n" \
       "# For compatibility reasons\n" \
       "\n" \
       "MODULE_0=coretemp\n" \
       "MODULE_1=f71882fg"

#define env_file_5                              \
        "a=\n"                                 \
        "b="

static void test_load_env_file_1(void) {
        _cleanup_strv_free_ char **data = NULL;
        int r;

        char name[] = "/tmp/test-load-env-file.XXXXXX";
        _cleanup_close_ int fd;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(write(fd, env_file_1, sizeof(env_file_1)) == sizeof(env_file_1));

        r = load_env_file(NULL, name, NULL, &data);
        assert_se(r == 0);
        assert_se(streq(data[0], "a=a"));
        assert_se(streq(data[1], "b=bc"));
        assert_se(streq(data[2], "d=def"));
        assert_se(streq(data[3], "g=g "));
        assert_se(streq(data[4], "h=h"));
        assert_se(streq(data[5], "i=i"));
        assert_se(data[6] == NULL);
        unlink(name);
}

static void test_load_env_file_2(void) {
        _cleanup_strv_free_ char **data = NULL;
        int r;

        char name[] = "/tmp/test-load-env-file.XXXXXX";
        _cleanup_close_ int fd;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(write(fd, env_file_2, sizeof(env_file_2)) == sizeof(env_file_2));

        r = load_env_file(NULL, name, NULL, &data);
        assert_se(r == 0);
        assert_se(streq(data[0], "a=a"));
        assert_se(data[1] == NULL);
        unlink(name);
}

static void test_load_env_file_3(void) {
        _cleanup_strv_free_ char **data = NULL;
        int r;

        char name[] = "/tmp/test-load-env-file.XXXXXX";
        _cleanup_close_ int fd;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(write(fd, env_file_3, sizeof(env_file_3)) == sizeof(env_file_3));

        r = load_env_file(NULL, name, NULL, &data);
        assert_se(r == 0);
        assert_se(data == NULL);
        unlink(name);
}

static void test_load_env_file_4(void) {
        _cleanup_strv_free_ char **data = NULL;
        char name[] = "/tmp/test-load-env-file.XXXXXX";
        _cleanup_close_ int fd;
        int r;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(write(fd, env_file_4, sizeof(env_file_4)) == sizeof(env_file_4));

        r = load_env_file(NULL, name, NULL, &data);
        assert_se(r == 0);
        assert_se(streq(data[0], "HWMON_MODULES=coretemp f71882fg"));
        assert_se(streq(data[1], "MODULE_0=coretemp"));
        assert_se(streq(data[2], "MODULE_1=f71882fg"));
        assert_se(data[3] == NULL);
        unlink(name);
}

static void test_load_env_file_5(void) {
        _cleanup_strv_free_ char **data = NULL;
        int r;

        char name[] = "/tmp/test-load-env-file.XXXXXX";
        _cleanup_close_ int fd;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(write(fd, env_file_5, sizeof(env_file_5)) == sizeof(env_file_5));

        r = load_env_file(NULL, name, NULL, &data);
        assert_se(r == 0);
        assert_se(streq(data[0], "a="));
        assert_se(streq(data[1], "b="));
        assert_se(data[2] == NULL);
        unlink(name);
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

        _cleanup_free_ char *mid = NULL, *bid = NULL, *host = NULL, *uid = NULL, *user = NULL;

        assert_se(specifier_machine_id('m', NULL, NULL, &mid) >= 0 && mid);
        assert_se(specifier_boot_id('b', NULL, NULL, &bid) >= 0 && bid);
        assert_se((host = gethostname_malloc()));
        assert_se((user = getusername_malloc()));
        assert_se(asprintf(&uid, UID_FMT, getuid()) >= 0);

#define expect(src, pattern, result)                                    \
        do {                                                            \
                _cleanup_free_ char *t = NULL;                          \
                _cleanup_free_ char                                     \
                        *d1 = strdup(i.name),                           \
                        *d2 = strdup(i.path);                           \
                assert_se(install_full_printf(&src, pattern, &t) >= 0 || !result); \
                memzero(i.name, strlen(i.name));                        \
                memzero(i.path, strlen(i.path));                        \
                assert_se(d1 && d2);                                    \
                if (result) {                                           \
                        printf("%s\n", t);                              \
                        assert_se(streq(t, result));                    \
                } else assert_se(t == NULL);                            \
                strcpy(i.name, d1);                                     \
                strcpy(i.path, d2);                                     \
        } while(false)

        expect(i, "%n", "name.service");
        expect(i, "%N", "name");
        expect(i, "%p", "name");
        expect(i, "%i", "");
        expect(i, "%u", user);
        expect(i, "%U", uid);

        expect(i, "%m", mid);
        expect(i, "%b", bid);
        expect(i, "%H", host);

        expect(i2, "%u", user);
        expect(i2, "%U", uid);

        expect(i3, "%n", "name@inst.service");
        expect(i3, "%N", "name@inst");
        expect(i3, "%p", "name");
        expect(i3, "%u", user);
        expect(i3, "%U", uid);

        expect(i3, "%m", mid);
        expect(i3, "%b", bid);
        expect(i3, "%H", host);

        expect(i4, "%u", user);
        expect(i4, "%U", uid);
}

static uint64_t make_cap(int cap) {
        return ((uint64_t) 1ULL << (uint64_t) cap);
}

static void test_config_parse_bounding_set(void) {
        /* int config_parse_bounding_set(
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
        uint64_t capability_bounding_set_drop = 0;

        r = config_parse_bounding_set(NULL, "fake", 1, "section", 1,
                              "CapabilityBoundingSet", 0, "CAP_NET_RAW",
                              &capability_bounding_set_drop, NULL);
        assert_se(r >= 0);
        assert_se(capability_bounding_set_drop == ~make_cap(CAP_NET_RAW));

        r = config_parse_bounding_set(NULL, "fake", 1, "section", 1,
                              "CapabilityBoundingSet", 0, "CAP_NET_ADMIN",
                              &capability_bounding_set_drop, NULL);
        assert_se(r >= 0);
        assert_se(capability_bounding_set_drop == ~(make_cap(CAP_NET_RAW) | make_cap(CAP_NET_ADMIN)));

        r = config_parse_bounding_set(NULL, "fake", 1, "section", 1,
                              "CapabilityBoundingSet", 0, "",
                              &capability_bounding_set_drop, NULL);
        assert_se(r >= 0);
        assert_se(capability_bounding_set_drop == ~((uint64_t) 0ULL));

        r = config_parse_bounding_set(NULL, "fake", 1, "section", 1,
                              "CapabilityBoundingSet", 0, "~",
                              &capability_bounding_set_drop, NULL);
        assert_se(r >= 0);
        assert_se(capability_bounding_set_drop == (uint64_t) 0ULL);

        capability_bounding_set_drop = 0;
        r = config_parse_bounding_set(NULL, "fake", 1, "section", 1,
                              "CapabilityBoundingSet", 0, "  'CAP_NET_RAW' WAT_CAP??? CAP_NET_ADMIN CAP'_trailing_garbage",
                              &capability_bounding_set_drop, NULL);
        assert_se(r >= 0);
        assert_se(capability_bounding_set_drop == ~(make_cap(CAP_NET_RAW) | make_cap(CAP_NET_ADMIN)));
}

static void test_config_parse_rlimit(void) {
        struct rlimit * rl[_RLIMIT_MAX] = {};

        assert_se(config_parse_limit(NULL, "fake", 1, "section", 1, "LimitNOFILE", RLIMIT_NOFILE, "55", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_NOFILE]);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == 55);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == rl[RLIMIT_NOFILE]->rlim_max);

        assert_se(config_parse_limit(NULL, "fake", 1, "section", 1, "LimitNOFILE", RLIMIT_NOFILE, "infinity", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_NOFILE]);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == RLIM_INFINITY);
        assert_se(rl[RLIMIT_NOFILE]->rlim_cur == rl[RLIMIT_NOFILE]->rlim_max);

        rl[RLIMIT_NOFILE] = mfree(rl[RLIMIT_NOFILE]);

        assert_se(config_parse_sec_limit(NULL, "fake", 1, "section", 1, "LimitCPU", RLIMIT_CPU, "56", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_CPU]);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == 56);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == rl[RLIMIT_CPU]->rlim_max);

        assert_se(config_parse_sec_limit(NULL, "fake", 1, "section", 1, "LimitCPU", RLIMIT_CPU, "57s", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_CPU]);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == 57);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == rl[RLIMIT_CPU]->rlim_max);

        assert_se(config_parse_sec_limit(NULL, "fake", 1, "section", 1, "LimitCPU", RLIMIT_CPU, "infinity", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_CPU]);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == RLIM_INFINITY);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == rl[RLIMIT_CPU]->rlim_max);

        assert_se(config_parse_sec_limit(NULL, "fake", 1, "section", 1, "LimitCPU", RLIMIT_CPU, "1234ms", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_CPU]);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == 2);
        assert_se(rl[RLIMIT_CPU]->rlim_cur == rl[RLIMIT_CPU]->rlim_max);

        rl[RLIMIT_CPU] = mfree(rl[RLIMIT_CPU]);

        assert_se(config_parse_usec_limit(NULL, "fake", 1, "section", 1, "LimitRTTIME", RLIMIT_RTTIME, "58", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_RTTIME]);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == 58);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == rl[RLIMIT_RTTIME]->rlim_max);

        assert_se(config_parse_usec_limit(NULL, "fake", 1, "section", 1, "LimitRTTIME", RLIMIT_RTTIME, "59s", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_RTTIME]);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == 59 * USEC_PER_SEC);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == rl[RLIMIT_RTTIME]->rlim_max);

        assert_se(config_parse_usec_limit(NULL, "fake", 1, "section", 1, "LimitRTTIME", RLIMIT_RTTIME, "infinity", rl, NULL) >= 0);
        assert_se(rl[RLIMIT_RTTIME]);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == RLIM_INFINITY);
        assert_se(rl[RLIMIT_RTTIME]->rlim_cur == rl[RLIMIT_RTTIME]->rlim_max);

        assert_se(config_parse_usec_limit(NULL, "fake", 1, "section", 1, "LimitRTTIME", RLIMIT_RTTIME, "2345ms", rl, NULL) >= 0);
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
                              "PassEnvironment", 0, "'invalid name' 'normal_name' A=1 \\",
                              &passenv, NULL);
        assert_se(r >= 0);
        assert_se(strv_length(passenv) == 1);
        assert_se(streq(passenv[0], "normal_name"));

}

int main(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        r = test_unit_file_get_set();
        test_config_parse_exec();
        test_config_parse_bounding_set();
        test_config_parse_rlimit();
        test_config_parse_pass_environ();
        test_load_env_file_1();
        test_load_env_file_2();
        test_load_env_file_3();
        test_load_env_file_4();
        test_load_env_file_5();
        TEST_REQ_RUNNING_SYSTEMD(test_install_printf());

        return r;
}
