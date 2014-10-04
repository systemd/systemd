/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Thomas H.P. Andersen

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

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <errno.h>
#include <signal.h>
#include <math.h>
#include <sys/wait.h>

#include "util.h"
#include "mkdir.h"
#include "strv.h"
#include "def.h"
#include "fileio.h"
#include "conf-parser.h"

static void test_streq_ptr(void) {
        assert_se(streq_ptr(NULL, NULL));
        assert_se(!streq_ptr("abc", "cdef"));
}

static void test_align_power2(void) {
        unsigned long i, p2;

        assert_se(ALIGN_POWER2(0) == 0);
        assert_se(ALIGN_POWER2(1) == 1);
        assert_se(ALIGN_POWER2(2) == 2);
        assert_se(ALIGN_POWER2(3) == 4);
        assert_se(ALIGN_POWER2(12) == 16);

        assert_se(ALIGN_POWER2(ULONG_MAX) == 0);
        assert_se(ALIGN_POWER2(ULONG_MAX - 1) == 0);
        assert_se(ALIGN_POWER2(ULONG_MAX - 1024) == 0);
        assert_se(ALIGN_POWER2(ULONG_MAX / 2) == ULONG_MAX / 2 + 1);
        assert_se(ALIGN_POWER2(ULONG_MAX + 1) == 0);

        for (i = 1; i < 131071; ++i) {
                for (p2 = 1; p2 < i; p2 <<= 1)
                        /* empty */ ;

                assert_se(ALIGN_POWER2(i) == p2);
        }

        for (i = ULONG_MAX - 1024; i < ULONG_MAX; ++i) {
                for (p2 = 1; p2 && p2 < i; p2 <<= 1)
                        /* empty */ ;

                assert_se(ALIGN_POWER2(i) == p2);
        }
}

static void test_max(void) {
        static const struct {
                int a;
                int b[CONST_MAX(10, 100)];
        } val1 = {
                .a = CONST_MAX(10, 100),
        };
        int d = 0;

        assert_cc(sizeof(val1.b) == sizeof(int) * 100);

        /* CONST_MAX returns (void) instead of a value if the passed arguments
         * are not of the same type or not constant expressions. */
        assert_cc(__builtin_types_compatible_p(typeof(CONST_MAX(1, 10)), int));
        assert_cc(__builtin_types_compatible_p(typeof(CONST_MAX(1, 1U)), void));

        assert_se(val1.a == 100);
        assert_se(MAX(++d, 0) == 1);
        assert_se(d == 1);

        assert_cc(MAXSIZE(char[3], uint16_t) == 3);
        assert_cc(MAXSIZE(char[3], uint32_t) == 4);
        assert_cc(MAXSIZE(char, long) == sizeof(long));

        assert_se(MAX(-5, 5) == 5);
        assert_se(MAX(5, 5) == 5);
        assert_se(MAX(MAX(1, MAX(2, MAX(3, 4))), 5) == 5);
        assert_se(MAX(MAX(1, MAX(2, MAX(3, 2))), 1) == 3);
        assert_se(MAX(MIN(1, MIN(2, MIN(3, 4))), 5) == 5);
        assert_se(MAX(MAX(1, MIN(2, MIN(3, 2))), 1) == 2);
        assert_se(LESS_BY(8, 4) == 4);
        assert_se(LESS_BY(8, 8) == 0);
        assert_se(LESS_BY(4, 8) == 0);
        assert_se(LESS_BY(16, LESS_BY(8, 4)) == 12);
        assert_se(LESS_BY(4, LESS_BY(8, 4)) == 0);
        assert_se(CLAMP(-5, 0, 1) == 0);
        assert_se(CLAMP(5, 0, 1) == 1);
        assert_se(CLAMP(5, -10, 1) == 1);
        assert_se(CLAMP(5, -10, 10) == 5);
        assert_se(CLAMP(CLAMP(0, -10, 10), CLAMP(-5, 10, 20), CLAMP(100, -5, 20)) == 10);
}

static void test_container_of(void) {
        struct mytype {
                uint8_t pad1[3];
                uint64_t v1;
                uint8_t pad2[2];
                uint32_t v2;
        } _packed_ myval = { };

        assert_cc(sizeof(myval) == 17);
        assert_se(container_of(&myval.v1, struct mytype, v1) == &myval);
        assert_se(container_of(&myval.v2, struct mytype, v2) == &myval);
        assert_se(container_of(&container_of(&myval.v2,
                                             struct mytype,
                                             v2)->v1,
                               struct mytype,
                               v1) == &myval);
}

static void test_alloca(void) {
        static const uint8_t zero[997] = { };
        char *t;

        t = alloca_align(17, 512);
        assert_se(!((uintptr_t)t & 0xff));
        memzero(t, 17);

        t = alloca0_align(997, 1024);
        assert_se(!((uintptr_t)t & 0x1ff));
        assert_se(!memcmp(t, zero, 997));
}

static void test_first_word(void) {
        assert_se(first_word("Hello", ""));
        assert_se(first_word("Hello", "Hello"));
        assert_se(first_word("Hello world", "Hello"));
        assert_se(first_word("Hello\tworld", "Hello"));
        assert_se(first_word("Hello\nworld", "Hello"));
        assert_se(first_word("Hello\rworld", "Hello"));
        assert_se(first_word("Hello ", "Hello"));

        assert_se(!first_word("Hello", "Hellooo"));
        assert_se(!first_word("Hello", "xxxxx"));
        assert_se(!first_word("Hellooo", "Hello"));
}

static void test_close_many(void) {
        int fds[3];
        char name0[] = "/tmp/test-close-many.XXXXXX";
        char name1[] = "/tmp/test-close-many.XXXXXX";
        char name2[] = "/tmp/test-close-many.XXXXXX";

        fds[0] = mkostemp_safe(name0, O_RDWR|O_CLOEXEC);
        fds[1] = mkostemp_safe(name1, O_RDWR|O_CLOEXEC);
        fds[2] = mkostemp_safe(name2, O_RDWR|O_CLOEXEC);

        close_many(fds, 2);

        assert_se(fcntl(fds[0], F_GETFD) == -1);
        assert_se(fcntl(fds[1], F_GETFD) == -1);
        assert_se(fcntl(fds[2], F_GETFD) >= 0);

        safe_close(fds[2]);

        unlink(name0);
        unlink(name1);
        unlink(name2);
}

static void test_parse_boolean(void) {
        assert_se(parse_boolean("1") == 1);
        assert_se(parse_boolean("y") == 1);
        assert_se(parse_boolean("Y") == 1);
        assert_se(parse_boolean("yes") == 1);
        assert_se(parse_boolean("YES") == 1);
        assert_se(parse_boolean("true") == 1);
        assert_se(parse_boolean("TRUE") == 1);
        assert_se(parse_boolean("on") == 1);
        assert_se(parse_boolean("ON") == 1);

        assert_se(parse_boolean("0") == 0);
        assert_se(parse_boolean("n") == 0);
        assert_se(parse_boolean("N") == 0);
        assert_se(parse_boolean("no") == 0);
        assert_se(parse_boolean("NO") == 0);
        assert_se(parse_boolean("false") == 0);
        assert_se(parse_boolean("FALSE") == 0);
        assert_se(parse_boolean("off") == 0);
        assert_se(parse_boolean("OFF") == 0);

        assert_se(parse_boolean("garbage") < 0);
        assert_se(parse_boolean("") < 0);
        assert_se(parse_boolean("full") < 0);
}

static void test_parse_pid(void) {
        int r;
        pid_t pid;

        r = parse_pid("100", &pid);
        assert_se(r == 0);
        assert_se(pid == 100);

        r = parse_pid("0x7FFFFFFF", &pid);
        assert_se(r == 0);
        assert_se(pid == 2147483647);

        pid = 65; /* pid is left unchanged on ERANGE. Set to known arbitrary value. */
        r = parse_pid("0", &pid);
        assert_se(r == -ERANGE);
        assert_se(pid == 65);

        pid = 65; /* pid is left unchanged on ERANGE. Set to known arbitrary value. */
        r = parse_pid("-100", &pid);
        assert_se(r == -ERANGE);
        assert_se(pid == 65);

        pid = 65; /* pid is left unchanged on ERANGE. Set to known arbitrary value. */
        r = parse_pid("0xFFFFFFFFFFFFFFFFF", &pid);
        assert_se(r == -ERANGE);
        assert_se(pid == 65);
}

static void test_parse_uid(void) {
        int r;
        uid_t uid;

        r = parse_uid("100", &uid);
        assert_se(r == 0);
        assert_se(uid == 100);
}

static void test_safe_atolli(void) {
        int r;
        long long l;

        r = safe_atolli("12345", &l);
        assert_se(r == 0);
        assert_se(l == 12345);

        r = safe_atolli("junk", &l);
        assert_se(r == -EINVAL);
}

static void test_safe_atod(void) {
        int r;
        double d;
        char *e;

        r = safe_atod("junk", &d);
        assert_se(r == -EINVAL);

        r = safe_atod("0.2244", &d);
        assert_se(r == 0);
        assert_se(fabs(d - 0.2244) < 0.000001);

        r = safe_atod("0,5", &d);
        assert_se(r == -EINVAL);

        errno = 0;
        strtod("0,5", &e);
        assert_se(*e == ',');

        /* Check if this really is locale independent */
        if (setlocale(LC_NUMERIC, "de_DE.utf8")) {

                r = safe_atod("0.2244", &d);
                assert_se(r == 0);
                assert_se(fabs(d - 0.2244) < 0.000001);

                r = safe_atod("0,5", &d);
                assert_se(r == -EINVAL);

                errno = 0;
                assert_se(fabs(strtod("0,5", &e) - 0.5) < 0.00001);
        }

        /* And check again, reset */
        assert_se(setlocale(LC_NUMERIC, "C"));

        r = safe_atod("0.2244", &d);
        assert_se(r == 0);
        assert_se(fabs(d - 0.2244) < 0.000001);

        r = safe_atod("0,5", &d);
        assert_se(r == -EINVAL);

        errno = 0;
        strtod("0,5", &e);
        assert_se(*e == ',');
}

static void test_strappend(void) {
        _cleanup_free_ char *t1, *t2, *t3, *t4;

        t1 = strappend(NULL, NULL);
        assert_se(streq(t1, ""));

        t2 = strappend(NULL, "suf");
        assert_se(streq(t2, "suf"));

        t3 = strappend("pre", NULL);
        assert_se(streq(t3, "pre"));

        t4 = strappend("pre", "suf");
        assert_se(streq(t4, "presuf"));
}

static void test_strstrip(void) {
        char *r;
        char input[] = "   hello, waldo.   ";

        r = strstrip(input);
        assert_se(streq(r, "hello, waldo."));
}

static void test_delete_chars(void) {
        char *r;
        char input[] = "   hello, waldo.   abc";

        r = delete_chars(input, WHITESPACE);
        assert_se(streq(r, "hello,waldo.abc"));
}

static void test_in_charset(void) {
        assert_se(in_charset("dddaaabbbcccc", "abcd"));
        assert_se(!in_charset("dddaaabbbcccc", "abc f"));
}

static void test_hexchar(void) {
        assert_se(hexchar(0xa) == 'a');
        assert_se(hexchar(0x0) == '0');
}

static void test_unhexchar(void) {
        assert_se(unhexchar('a') == 0xA);
        assert_se(unhexchar('A') == 0xA);
        assert_se(unhexchar('0') == 0x0);
}

static void test_octchar(void) {
        assert_se(octchar(00) == '0');
        assert_se(octchar(07) == '7');
}

static void test_unoctchar(void) {
        assert_se(unoctchar('0') == 00);
        assert_se(unoctchar('7') == 07);
}

static void test_decchar(void) {
        assert_se(decchar(0) == '0');
        assert_se(decchar(9) == '9');
}

static void test_undecchar(void) {
        assert_se(undecchar('0') == 0);
        assert_se(undecchar('9') == 9);
}

static void test_cescape(void) {
        _cleanup_free_ char *escaped;

        assert_se(escaped = cescape("abc\\\"\b\f\n\r\t\v\a\003\177\234\313"));
        assert_se(streq(escaped, "abc\\\\\\\"\\b\\f\\n\\r\\t\\v\\a\\003\\177\\234\\313"));
}

static void test_cunescape(void) {
        _cleanup_free_ char *unescaped;

        assert_se(unescaped = cunescape("abc\\\\\\\"\\b\\f\\a\\n\\r\\t\\v\\003\\177\\234\\313\\000\\x00"));
        assert_se(streq(unescaped, "abc\\\"\b\f\a\n\r\t\v\003\177\234\313\\000\\x00"));
}

static void test_foreach_word(void) {
        const char *word, *state;
        size_t l;
        int i = 0;
        const char test[] = "test abc d\te   f   ";
        const char * const expected[] = {
                "test",
                "abc",
                "d",
                "e",
                "f",
                "",
                NULL
        };

        FOREACH_WORD(word, l, test, state)
                assert_se(strneq(expected[i++], word, l));
}

static void test_foreach_word_quoted(void) {
        const char *word, *state;
        size_t l;
        int i = 0;
        const char test[] = "test a b c 'd' e '' '' hhh '' '' \"a b c\"";
        const char * const expected[] = {
                "test",
                "a",
                "b",
                "c",
                "d",
                "e",
                "",
                "",
                "hhh",
                "",
                "",
                "a b c",
                NULL
        };

        printf("<%s>\n", test);
        FOREACH_WORD_QUOTED(word, l, test, state) {
                _cleanup_free_ char *t = NULL;

                assert_se(t = strndup(word, l));
                assert_se(strneq(expected[i++], word, l));
                printf("<%s>\n", t);
        }
        assert_se(isempty(state));
}

static void test_default_term_for_tty(void) {
        puts(default_term_for_tty("/dev/tty23"));
        puts(default_term_for_tty("/dev/ttyS23"));
        puts(default_term_for_tty("/dev/tty0"));
        puts(default_term_for_tty("/dev/pty0"));
        puts(default_term_for_tty("/dev/pts/0"));
        puts(default_term_for_tty("/dev/console"));
        puts(default_term_for_tty("tty23"));
        puts(default_term_for_tty("ttyS23"));
        puts(default_term_for_tty("tty0"));
        puts(default_term_for_tty("pty0"));
        puts(default_term_for_tty("pts/0"));
        puts(default_term_for_tty("console"));
}

static void test_memdup_multiply(void) {
        int org[] = {1, 2, 3};
        int *dup;

        dup = (int*)memdup_multiply(org, sizeof(int), 3);

        assert_se(dup);
        assert_se(dup[0] == 1);
        assert_se(dup[1] == 2);
        assert_se(dup[2] == 3);
        free(dup);
}

static void test_hostname_is_valid(void) {
        assert_se(hostname_is_valid("foobar"));
        assert_se(hostname_is_valid("foobar.com"));
        assert_se(!hostname_is_valid("fööbar"));
        assert_se(!hostname_is_valid(""));
        assert_se(!hostname_is_valid("."));
        assert_se(!hostname_is_valid(".."));
        assert_se(!hostname_is_valid("foobar."));
        assert_se(!hostname_is_valid(".foobar"));
        assert_se(!hostname_is_valid("foo..bar"));
        assert_se(!hostname_is_valid("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
}

static void test_u64log2(void) {
        assert_se(u64log2(0) == 0);
        assert_se(u64log2(8) == 3);
        assert_se(u64log2(9) == 3);
        assert_se(u64log2(15) == 3);
        assert_se(u64log2(16) == 4);
        assert_se(u64log2(1024*1024) == 20);
        assert_se(u64log2(1024*1024+5) == 20);
}

static void test_get_process_comm(void) {
        struct stat st;
        _cleanup_free_ char *a = NULL, *c = NULL, *d = NULL, *f = NULL, *i = NULL;
        unsigned long long b;
        pid_t e;
        uid_t u;
        gid_t g;
        dev_t h;
        int r;

        if (stat("/proc/1/comm", &st) == 0) {
                assert_se(get_process_comm(1, &a) >= 0);
                log_info("pid1 comm: '%s'", a);
        } else {
                log_warning("/proc/1/comm does not exist.");
        }

        assert_se(get_starttime_of_pid(1, &b) >= 0);
        log_info("pid1 starttime: '%llu'", b);

        assert_se(get_process_cmdline(1, 0, true, &c) >= 0);
        log_info("pid1 cmdline: '%s'", c);

        assert_se(get_process_cmdline(1, 8, false, &d) >= 0);
        log_info("pid1 cmdline truncated: '%s'", d);

        assert_se(get_parent_of_pid(1, &e) >= 0);
        log_info("pid1 ppid: "PID_FMT, e);
        assert_se(e == 0);

        assert_se(is_kernel_thread(1) == 0);

        r = get_process_exe(1, &f);
        assert_se(r >= 0 || r == -EACCES);
        log_info("pid1 exe: '%s'", strna(f));

        assert_se(get_process_uid(1, &u) == 0);
        log_info("pid1 uid: "UID_FMT, u);
        assert_se(u == 0);

        assert_se(get_process_gid(1, &g) == 0);
        log_info("pid1 gid: "GID_FMT, g);
        assert_se(g == 0);

        assert_se(get_ctty_devnr(1, &h) == -ENOENT);

        getenv_for_pid(1, "PATH", &i);
        log_info("pid1 $PATH: '%s'", strna(i));
}

static void test_protect_errno(void) {
        errno = 12;
        {
                PROTECT_ERRNO;
                errno = 11;
        }
        assert_se(errno == 12);
}

static void test_parse_size(void) {
        off_t bytes;

        assert_se(parse_size("111", 1024, &bytes) == 0);
        assert_se(bytes == 111);

        assert_se(parse_size("111.4", 1024, &bytes) == 0);
        assert_se(bytes == 111);

        assert_se(parse_size(" 112 B", 1024, &bytes) == 0);
        assert_se(bytes == 112);

        assert_se(parse_size(" 112.6 B", 1024, &bytes) == 0);
        assert_se(bytes == 112);

        assert_se(parse_size("3.5 K", 1024, &bytes) == 0);
        assert_se(bytes == 3*1024 + 512);

        assert_se(parse_size("3. K", 1024, &bytes) == 0);
        assert_se(bytes == 3*1024);

        assert_se(parse_size("3.0 K", 1024, &bytes) == 0);
        assert_se(bytes == 3*1024);

        assert_se(parse_size("3. 0 K", 1024, &bytes) == -EINVAL);

        assert_se(parse_size(" 4 M 11.5K", 1024, &bytes) == 0);
        assert_se(bytes == 4*1024*1024 + 11 * 1024 + 512);

        assert_se(parse_size("3B3.5G", 1024, &bytes) == -EINVAL);

        assert_se(parse_size("3.5G3B", 1024, &bytes) == 0);
        assert_se(bytes == 3ULL*1024*1024*1024 + 512*1024*1024 + 3);

        assert_se(parse_size("3.5G 4B", 1024, &bytes) == 0);
        assert_se(bytes == 3ULL*1024*1024*1024 + 512*1024*1024 + 4);

        assert_se(parse_size("3B3G4T", 1024, &bytes) == -EINVAL);

        assert_se(parse_size("4T3G3B", 1024, &bytes) == 0);
        assert_se(bytes == (4ULL*1024 + 3)*1024*1024*1024 + 3);

        assert_se(parse_size(" 4 T 3 G 3 B", 1024, &bytes) == 0);
        assert_se(bytes == (4ULL*1024 + 3)*1024*1024*1024 + 3);

        assert_se(parse_size("12P", 1024, &bytes) == 0);
        assert_se(bytes == 12ULL * 1024*1024*1024*1024*1024);

        assert_se(parse_size("12P12P", 1024, &bytes) == -EINVAL);

        assert_se(parse_size("3E 2P", 1024, &bytes) == 0);
        assert_se(bytes == (3 * 1024 + 2ULL) * 1024*1024*1024*1024*1024);

        assert_se(parse_size("12X", 1024, &bytes) == -EINVAL);

        assert_se(parse_size("12.5X", 1024, &bytes) == -EINVAL);

        assert_se(parse_size("12.5e3", 1024, &bytes) == -EINVAL);

        assert_se(parse_size("1024E", 1024, &bytes) == -ERANGE);
        assert_se(parse_size("-1", 1024, &bytes) == -ERANGE);
        assert_se(parse_size("-1024E", 1024, &bytes) == -ERANGE);

        assert_se(parse_size("-1024P", 1024, &bytes) == -ERANGE);

        assert_se(parse_size("-10B 20K", 1024, &bytes) == -ERANGE);
}

static void test_config_parse_iec_off(void) {
        off_t offset = 0;
        assert_se(config_parse_iec_off(NULL, "/this/file", 11, "Section", 22, "Size", 0, "4M", &offset, NULL) == 0);
        assert_se(offset == 4 * 1024 * 1024);

        assert_se(config_parse_iec_off(NULL, "/this/file", 11, "Section", 22, "Size", 0, "4.5M", &offset, NULL) == 0);
}

static void test_strextend(void) {
        _cleanup_free_ char *str = strdup("0123");
        strextend(&str, "456", "78", "9", NULL);
        assert_se(streq(str, "0123456789"));
}

static void test_strrep(void) {
        _cleanup_free_ char *one, *three, *zero;
        one = strrep("waldo", 1);
        three = strrep("waldo", 3);
        zero = strrep("waldo", 0);

        assert_se(streq(one, "waldo"));
        assert_se(streq(three, "waldowaldowaldo"));
        assert_se(streq(zero, ""));
}

static void test_split_pair(void) {
        _cleanup_free_ char *a = NULL, *b = NULL;

        assert_se(split_pair("", "", &a, &b) == -EINVAL);
        assert_se(split_pair("foo=bar", "", &a, &b) == -EINVAL);
        assert_se(split_pair("", "=", &a, &b) == -EINVAL);
        assert_se(split_pair("foo=bar", "=", &a, &b) >= 0);
        assert_se(streq(a, "foo"));
        assert_se(streq(b, "bar"));
        free(a);
        free(b);
        assert_se(split_pair("==", "==", &a, &b) >= 0);
        assert_se(streq(a, ""));
        assert_se(streq(b, ""));
        free(a);
        free(b);

        assert_se(split_pair("===", "==", &a, &b) >= 0);
        assert_se(streq(a, ""));
        assert_se(streq(b, "="));
}

static void test_fstab_node_to_udev_node(void) {
        char *n;

        n = fstab_node_to_udev_node("LABEL=applé/jack");
        puts(n);
        assert_se(streq(n, "/dev/disk/by-label/applé\\x2fjack"));
        free(n);

        n = fstab_node_to_udev_node("PARTLABEL=pinkié pie");
        puts(n);
        assert_se(streq(n, "/dev/disk/by-partlabel/pinkié\\x20pie"));
        free(n);

        n = fstab_node_to_udev_node("UUID=037b9d94-148e-4ee4-8d38-67bfe15bb535");
        puts(n);
        assert_se(streq(n, "/dev/disk/by-uuid/037b9d94-148e-4ee4-8d38-67bfe15bb535"));
        free(n);

        n = fstab_node_to_udev_node("PARTUUID=037b9d94-148e-4ee4-8d38-67bfe15bb535");
        puts(n);
        assert_se(streq(n, "/dev/disk/by-partuuid/037b9d94-148e-4ee4-8d38-67bfe15bb535"));
        free(n);

        n = fstab_node_to_udev_node("PONIES=awesome");
        puts(n);
        assert_se(streq(n, "PONIES=awesome"));
        free(n);

        n = fstab_node_to_udev_node("/dev/xda1");
        puts(n);
        assert_se(streq(n, "/dev/xda1"));
        free(n);
}

static void test_get_files_in_directory(void) {
        _cleanup_strv_free_ char **l = NULL, **t = NULL;

        assert_se(get_files_in_directory("/tmp", &l) >= 0);
        assert_se(get_files_in_directory(".", &t) >= 0);
        assert_se(get_files_in_directory(".", NULL) >= 0);
}

static void test_in_set(void) {
        assert_se(IN_SET(1, 1));
        assert_se(IN_SET(1, 1, 2, 3, 4));
        assert_se(IN_SET(2, 1, 2, 3, 4));
        assert_se(IN_SET(3, 1, 2, 3, 4));
        assert_se(IN_SET(4, 1, 2, 3, 4));
        assert_se(!IN_SET(0, 1));
        assert_se(!IN_SET(0, 1, 2, 3, 4));
}

static void test_writing_tmpfile(void) {
        char name[] = "/tmp/test-systemd_writing_tmpfile.XXXXXX";
        _cleanup_free_ char *contents = NULL;
        size_t size;
        int fd, r;
        struct iovec iov[3];

        IOVEC_SET_STRING(iov[0], "abc\n");
        IOVEC_SET_STRING(iov[1], ALPHANUMERICAL "\n");
        IOVEC_SET_STRING(iov[2], "");

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        printf("tmpfile: %s", name);

        r = writev(fd, iov, 3);
        assert_se(r >= 0);

        r = read_full_file(name, &contents, &size);
        assert_se(r == 0);
        printf("contents: %s", contents);
        assert_se(streq(contents, "abc\n" ALPHANUMERICAL "\n"));

        unlink(name);
}

static void test_hexdump(void) {
        uint8_t data[146];
        unsigned i;

        hexdump(stdout, NULL, 0);
        hexdump(stdout, "", 0);
        hexdump(stdout, "", 1);
        hexdump(stdout, "x", 1);
        hexdump(stdout, "x", 2);
        hexdump(stdout, "foobar", 7);
        hexdump(stdout, "f\nobar", 7);
        hexdump(stdout, "xxxxxxxxxxxxxxxxxxxxyz", 23);

        for (i = 0; i < ELEMENTSOF(data); i++)
                data[i] = i*2;

        hexdump(stdout, data, sizeof(data));
}

static void test_log2i(void) {
        assert_se(log2i(1) == 0);
        assert_se(log2i(2) == 1);
        assert_se(log2i(3) == 1);
        assert_se(log2i(4) == 2);
        assert_se(log2i(32) == 5);
        assert_se(log2i(33) == 5);
        assert_se(log2i(63) == 5);
        assert_se(log2i(INT_MAX) == sizeof(int)*8-2);
}

static void test_foreach_string(void) {
        const char * const t[] = {
                "foo",
                "bar",
                "waldo",
                NULL
        };
        const char *x;
        unsigned i = 0;

        FOREACH_STRING(x, "foo", "bar", "waldo")
                assert_se(streq_ptr(t[i++], x));

        assert_se(i == 3);

        FOREACH_STRING(x, "zzz")
                assert_se(streq(x, "zzz"));
}

static void test_filename_is_safe(void) {
        char foo[FILENAME_MAX+2];
        int i;

        assert_se(!filename_is_safe(""));
        assert_se(!filename_is_safe("/bar/foo"));
        assert_se(!filename_is_safe("/"));
        assert_se(!filename_is_safe("."));
        assert_se(!filename_is_safe(".."));

        for (i=0; i<FILENAME_MAX+1; i++)
                foo[i] = 'a';
        foo[FILENAME_MAX+1] = '\0';

        assert_se(!filename_is_safe(foo));

        assert_se(filename_is_safe("foo_bar-333"));
        assert_se(filename_is_safe("o.o"));
}

static void test_string_has_cc(void) {
        assert_se(string_has_cc("abc\1", NULL));
        assert_se(string_has_cc("abc\x7f", NULL));
        assert_se(string_has_cc("abc\x7f", NULL));
        assert_se(string_has_cc("abc\t\x7f", "\t"));
        assert_se(string_has_cc("abc\t\x7f", "\t"));
        assert_se(string_has_cc("\x7f", "\t"));
        assert_se(string_has_cc("\x7f", "\t\a"));

        assert_se(!string_has_cc("abc\t\t", "\t"));
        assert_se(!string_has_cc("abc\t\t\a", "\t\a"));
        assert_se(!string_has_cc("a\ab\tc", "\t\a"));
}

static void test_ascii_strlower(void) {
        char a[] = "AabBcC Jk Ii Od LKJJJ kkd LK";
        assert_se(streq(ascii_strlower(a), "aabbcc jk ii od lkjjj kkd lk"));
}

static void test_files_same(void) {
        _cleanup_close_ int fd = -1;
        char name[] = "/tmp/test-files_same.XXXXXX";
        char name_alias[] = "/tmp/test-files_same.alias";

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(symlink(name, name_alias) >= 0);

        assert_se(files_same(name, name));
        assert_se(files_same(name, name_alias));

        unlink(name);
        unlink(name_alias);
}

static void test_is_valid_documentation_url(void) {
        assert_se(is_valid_documentation_url("http://www.freedesktop.org/wiki/Software/systemd"));
        assert_se(is_valid_documentation_url("https://www.kernel.org/doc/Documentation/binfmt_misc.txt"));
        assert_se(is_valid_documentation_url("file:foo"));
        assert_se(is_valid_documentation_url("man:systemd.special(7)"));
        assert_se(is_valid_documentation_url("info:bar"));

        assert_se(!is_valid_documentation_url("foo:"));
        assert_se(!is_valid_documentation_url("info:"));
        assert_se(!is_valid_documentation_url(""));
}

static void test_file_in_same_dir(void) {
        char *t;

        t = file_in_same_dir("/", "a");
        assert_se(streq(t, "/a"));
        free(t);

        t = file_in_same_dir("/", "/a");
        assert_se(streq(t, "/a"));
        free(t);

        t = file_in_same_dir("", "a");
        assert_se(streq(t, "a"));
        free(t);

        t = file_in_same_dir("a/", "a");
        assert_se(streq(t, "a/a"));
        free(t);

        t = file_in_same_dir("bar/foo", "bar");
        assert_se(streq(t, "bar/bar"));
        free(t);
}

static void test_endswith(void) {
        assert_se(endswith("foobar", "bar"));
        assert_se(endswith("foobar", ""));
        assert_se(endswith("foobar", "foobar"));
        assert_se(endswith("", ""));

        assert_se(!endswith("foobar", "foo"));
        assert_se(!endswith("foobar", "foobarfoofoo"));
}

static void test_close_nointr(void) {
        char name[] = "/tmp/test-test-close_nointr.XXXXXX";
        int fd;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(close_nointr(fd) >= 0);
        assert_se(close_nointr(fd) < 0);

        unlink(name);
}


static void test_unlink_noerrno(void) {
        char name[] = "/tmp/test-close_nointr.XXXXXX";
        int fd;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(close_nointr(fd) >= 0);

        {
                PROTECT_ERRNO;
                errno = -42;
                assert_se(unlink_noerrno(name) >= 0);
                assert_se(errno == -42);
                assert_se(unlink_noerrno(name) < 0);
                assert_se(errno == -42);
        }
}

static void test_readlink_and_make_absolute(void) {
        char tempdir[] = "/tmp/test-readlink_and_make_absolute";
        char name[] = "/tmp/test-readlink_and_make_absolute/original";
        char name2[] = "test-readlink_and_make_absolute/original";
        char name_alias[] = "/tmp/test-readlink_and_make_absolute-alias";
        char *r = NULL;

        assert_se(mkdir_safe(tempdir, 0755, getuid(), getgid()) >= 0);
        assert_se(touch(name) >= 0);

        assert_se(symlink(name, name_alias) >= 0);
        assert_se(readlink_and_make_absolute(name_alias, &r) >= 0);
        assert_se(streq(r, name));
        free(r);
        assert_se(unlink(name_alias) >= 0);

        assert_se(chdir(tempdir) >= 0);
        assert_se(symlink(name2, name_alias) >= 0);
        assert_se(readlink_and_make_absolute(name_alias, &r) >= 0);
        assert_se(streq(r, name));
        free(r);
        assert_se(unlink(name_alias) >= 0);

        assert_se(rm_rf_dangerous(tempdir, false, true, false) >= 0);
}

static void test_read_one_char(void) {
        _cleanup_fclose_ FILE *file = NULL;
        char r;
        bool need_nl;
        char name[] = "/tmp/test-read_one_char.XXXXXX";
        int fd;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        file = fdopen(fd, "r+");
        assert_se(file);
        assert_se(fputs("c\n", file) >= 0);
        rewind(file);

        assert_se(read_one_char(file, &r, 1000000, &need_nl) >= 0);
        assert_se(!need_nl);
        assert_se(r == 'c');
        assert_se(read_one_char(file, &r, 1000000, &need_nl) < 0);

        rewind(file);
        assert_se(fputs("foobar\n", file) >= 0);
        rewind(file);
        assert_se(read_one_char(file, &r, 1000000, &need_nl) < 0);

        rewind(file);
        assert_se(fputs("\n", file) >= 0);
        rewind(file);
        assert_se(read_one_char(file, &r, 1000000, &need_nl) < 0);

        unlink(name);
}

static void test_ignore_signals(void) {
        assert_se(ignore_signals(SIGINT, -1) >= 0);
        assert_se(kill(getpid(), SIGINT) >= 0);
        assert_se(ignore_signals(SIGUSR1, SIGUSR2, SIGTERM, SIGPIPE, -1) >= 0);
        assert_se(kill(getpid(), SIGUSR1) >= 0);
        assert_se(kill(getpid(), SIGUSR2) >= 0);
        assert_se(kill(getpid(), SIGTERM) >= 0);
        assert_se(kill(getpid(), SIGPIPE) >= 0);
        assert_se(default_signals(SIGINT, SIGUSR1, SIGUSR2, SIGTERM, SIGPIPE, -1) >= 0);
}

static void test_strshorten(void) {
        char s[] = "foobar";

        assert_se(strlen(strshorten(s, 6)) == 6);
        assert_se(strlen(strshorten(s, 12)) == 6);
        assert_se(strlen(strshorten(s, 2)) == 2);
        assert_se(strlen(strshorten(s, 0)) == 0);
}

static void test_strappenda(void) {
        char *actual;

        actual = strappenda("", "foo", "bar");
        assert_se(streq(actual, "foobar"));

        actual = strappenda("foo", "bar", "baz");
        assert_se(streq(actual, "foobarbaz"));

        actual = strappenda("foo", "", "bar", "baz");
        assert_se(streq(actual, "foobarbaz"));
}

static void test_is_symlink(void) {
        char name[] = "/tmp/test-is_symlink.XXXXXX";
        char name_link[] = "/tmp/test-is_symlink.link";
        _cleanup_close_ int fd = -1;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(symlink(name, name_link) >= 0);

        assert_se(is_symlink(name) == 0);
        assert_se(is_symlink(name_link) == 1);
        assert_se(is_symlink("/a/file/which/does/not/exist/i/guess") < 0);


        unlink(name);
        unlink(name_link);
}

static void test_pid_is_unwaited(void) {
        pid_t pid;

        pid = fork();
        assert_se(pid >= 0);
        if (pid == 0) {
                _exit(EXIT_SUCCESS);
        } else {
                int status;

                waitpid(pid, &status, 0);
                assert_se(!pid_is_unwaited(pid));
        }
        assert_se(pid_is_unwaited(getpid()));
        assert_se(!pid_is_unwaited(-1));
}

static void test_pid_is_alive(void) {
        pid_t pid;

        pid = fork();
        assert_se(pid >= 0);
        if (pid == 0) {
                _exit(EXIT_SUCCESS);
        } else {
                int status;

                waitpid(pid, &status, 0);
                assert_se(!pid_is_alive(pid));
        }
        assert_se(pid_is_alive(getpid()));
        assert_se(!pid_is_alive(-1));
}

static void test_search_and_fopen(void) {
        const char *dirs[] = {"/tmp/foo/bar", "/tmp", NULL};
        char name[] = "/tmp/test-search_and_fopen.XXXXXX";
        int fd = -1;
        int r;
        FILE *f;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        close(fd);

        r = search_and_fopen(basename(name), "r", NULL, dirs, &f);
        assert_se(r >= 0);
        fclose(f);

        r = search_and_fopen(name, "r", NULL, dirs, &f);
        assert_se(r >= 0);
        fclose(f);

        r = search_and_fopen(basename(name), "r", "/", dirs, &f);
        assert_se(r >= 0);
        fclose(f);

        r = search_and_fopen("/a/file/which/does/not/exist/i/guess", "r", NULL, dirs, &f);
        assert_se(r < 0);
        r = search_and_fopen("afilewhichdoesnotexistiguess", "r", NULL, dirs, &f);
        assert_se(r < 0);

        r = unlink(name);
        assert_se(r == 0);

        r = search_and_fopen(basename(name), "r", NULL, dirs, &f);
        assert_se(r < 0);
}


static void test_search_and_fopen_nulstr(void) {
        const char dirs[] = "/tmp/foo/bar\0/tmp\0";
        char name[] = "/tmp/test-search_and_fopen.XXXXXX";
        int fd = -1;
        int r;
        FILE *f;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        close(fd);

        r = search_and_fopen_nulstr(basename(name), "r", NULL, dirs, &f);
        assert_se(r >= 0);
        fclose(f);

        r = search_and_fopen_nulstr(name, "r", NULL, dirs, &f);
        assert_se(r >= 0);
        fclose(f);

        r = search_and_fopen_nulstr("/a/file/which/does/not/exist/i/guess", "r", NULL, dirs, &f);
        assert_se(r < 0);
        r = search_and_fopen_nulstr("afilewhichdoesnotexistiguess", "r", NULL, dirs, &f);
        assert_se(r < 0);

        r = unlink(name);
        assert_se(r == 0);

        r = search_and_fopen_nulstr(basename(name), "r", NULL, dirs, &f);
        assert_se(r < 0);
}

static void test_glob_exists(void) {
        char name[] = "/tmp/test-glob_exists.XXXXXX";
        int fd = -1;
        int r;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        close(fd);

        r = glob_exists("/tmp/test-glob_exists*");
        assert_se(r == 1);

        r = unlink(name);
        assert_se(r == 0);
        r = glob_exists("/tmp/test-glob_exists*");
        assert_se(r == 0);
}

static void test_execute_directory(void) {
        char name[] = "/tmp/test-execute_directory/script1";
        char name2[] = "/tmp/test-execute_directory/script2";
        char name3[] = "/tmp/test-execute_directory/useless";
        char tempdir[] = "/tmp/test-execute_directory/";

        assert_se(mkdir_safe(tempdir, 0755, getuid(), getgid()) >= 0);
        assert_se(write_string_file(name, "#!/bin/sh\necho 'Executing '$0\ntouch /tmp/test-execute_directory/it_works") == 0);
        assert_se(write_string_file(name2, "#!/bin/sh\necho 'Executing '$0\ntouch /tmp/test-execute_directory/it_works2") == 0);
        assert_se(chmod(name, 0755) == 0);
        assert_se(chmod(name2, 0755) == 0);
        assert_se(touch(name3) >= 0);

        execute_directory(tempdir, NULL, DEFAULT_TIMEOUT_USEC, NULL);
        assert_se(access("/tmp/test-execute_directory/it_works", F_OK) >= 0);
        assert_se(access("/tmp/test-execute_directory/it_works2", F_OK) >= 0);

        rm_rf_dangerous(tempdir, false, true, false);
}

static void test_unquote_first_word(void) {
        const char *p, *original;
        char *t;

        p = original = "foobar waldo";
        assert_se(unquote_first_word(&p, &t) > 0);
        assert_se(streq(t, "foobar"));
        free(t);
        assert_se(p == original + 7);

        assert_se(unquote_first_word(&p, &t) > 0);
        assert_se(streq(t, "waldo"));
        free(t);
        assert_se(p == original + 12);

        assert_se(unquote_first_word(&p, &t) == 0);
        assert_se(!t);
        assert_se(p == original + 12);

        p = original = "\"foobar\" \'waldo\'";
        assert_se(unquote_first_word(&p, &t) > 0);
        assert_se(streq(t, "foobar"));
        free(t);
        assert_se(p == original + 9);

        assert_se(unquote_first_word(&p, &t) > 0);
        assert_se(streq(t, "waldo"));
        free(t);
        assert_se(p == original + 16);

        assert_se(unquote_first_word(&p, &t) == 0);
        assert_se(!t);
        assert_se(p == original + 16);

        p = original = "\"";
        assert_se(unquote_first_word(&p, &t) == -EINVAL);
        assert_se(p == original + 1);

        p = original = "\'";
        assert_se(unquote_first_word(&p, &t) == -EINVAL);
        assert_se(p == original + 1);

        p = original = "yay\'foo\'bar";
        assert_se(unquote_first_word(&p, &t) > 0);
        assert_se(streq(t, "yayfoobar"));
        free(t);
        assert_se(p == original + 11);

        p = original = "   foobar   ";
        assert_se(unquote_first_word(&p, &t) > 0);
        assert_se(streq(t, "foobar"));
        free(t);
        assert_se(p == original + 12);
}

static void test_unquote_many_words(void) {
        const char *p, *original;
        char *a, *b, *c;

        p = original = "foobar waldi piep";
        assert_se(unquote_many_words(&p, &a, &b, &c, NULL) == 3);
        assert_se(p == original + 17);
        assert_se(streq_ptr(a, "foobar"));
        assert_se(streq_ptr(b, "waldi"));
        assert_se(streq_ptr(c, "piep"));
        free(a);
        free(b);
        free(c);

        p = original = "'foobar' wa\"ld\"i   ";
        assert_se(unquote_many_words(&p, &a, &b, &c, NULL) == 2);
        assert_se(p == original + 19);
        assert_se(streq_ptr(a, "foobar"));
        assert_se(streq_ptr(b, "waldi"));
        assert_se(streq_ptr(c, NULL));
        free(a);
        free(b);

        p = original = "";
        assert_se(unquote_many_words(&p, &a, &b, &c, NULL) == 0);
        assert_se(p == original);
        assert_se(streq_ptr(a, NULL));
        assert_se(streq_ptr(b, NULL));
        assert_se(streq_ptr(c, NULL));

        p = original = "  ";
        assert_se(unquote_many_words(&p, &a, &b, &c, NULL) == 0);
        assert_se(p == original+2);
        assert_se(streq_ptr(a, NULL));
        assert_se(streq_ptr(b, NULL));
        assert_se(streq_ptr(c, NULL));

        p = original = "foobar";
        assert_se(unquote_many_words(&p, NULL) == 0);
        assert_se(p == original);

        p = original = "foobar waldi";
        assert_se(unquote_many_words(&p, &a, NULL) == 1);
        assert_se(p == original+7);
        assert_se(streq_ptr(a, "foobar"));
        free(a);

        p = original = "     foobar    ";
        assert_se(unquote_many_words(&p, &a, NULL) == 1);
        assert_se(p == original+15);
        assert_se(streq_ptr(a, "foobar"));
        free(a);
}

int main(int argc, char *argv[]) {
        log_parse_environment();
        log_open();

        test_streq_ptr();
        test_align_power2();
        test_max();
        test_container_of();
        test_alloca();
        test_first_word();
        test_close_many();
        test_parse_boolean();
        test_parse_pid();
        test_parse_uid();
        test_safe_atolli();
        test_safe_atod();
        test_strappend();
        test_strstrip();
        test_delete_chars();
        test_in_charset();
        test_hexchar();
        test_unhexchar();
        test_octchar();
        test_unoctchar();
        test_decchar();
        test_undecchar();
        test_cescape();
        test_cunescape();
        test_foreach_word();
        test_foreach_word_quoted();
        test_default_term_for_tty();
        test_memdup_multiply();
        test_hostname_is_valid();
        test_u64log2();
        test_get_process_comm();
        test_protect_errno();
        test_parse_size();
        test_config_parse_iec_off();
        test_strextend();
        test_strrep();
        test_split_pair();
        test_fstab_node_to_udev_node();
        test_get_files_in_directory();
        test_in_set();
        test_writing_tmpfile();
        test_hexdump();
        test_log2i();
        test_foreach_string();
        test_filename_is_safe();
        test_string_has_cc();
        test_ascii_strlower();
        test_files_same();
        test_is_valid_documentation_url();
        test_file_in_same_dir();
        test_endswith();
        test_close_nointr();
        test_unlink_noerrno();
        test_readlink_and_make_absolute();
        test_read_one_char();
        test_ignore_signals();
        test_strshorten();
        test_strappenda();
        test_is_symlink();
        test_pid_is_unwaited();
        test_pid_is_alive();
        test_search_and_fopen();
        test_search_and_fopen_nulstr();
        test_glob_exists();
        test_execute_directory();
        test_unquote_first_word();
        test_unquote_many_words();

        return 0;
}
