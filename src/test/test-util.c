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

#include "util.h"

static void test_streq_ptr(void) {
        assert_se(streq_ptr(NULL, NULL));
        assert_se(!streq_ptr("abc", "cdef"));
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

        fds[0] = mkstemp(name0);
        fds[1] = mkstemp(name1);
        fds[2] = mkstemp(name2);

        close_many(fds, 2);

        assert_se(fcntl(fds[0], F_GETFD) == -1);
        assert_se(fcntl(fds[1], F_GETFD) == -1);
        assert_se(fcntl(fds[2], F_GETFD) >= 0);

        close_nointr_nofail(fds[2]);

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
        assert(r == -ERANGE);
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
        assert_se(abs(d - 0.2244) < 0.000001);

        r = safe_atod("0,5", &d);
        assert_se(r == -EINVAL);

        errno = 0;
        strtod("0,5", &e);
        assert_se(*e == ',');

        /* Check if this really is locale independent */
        setlocale(LC_NUMERIC, "de_DE.utf8");

        r = safe_atod("0.2244", &d);
        assert_se(r == 0);
        assert_se(abs(d - 0.2244) < 0.000001);

        r = safe_atod("0,5", &d);
        assert_se(r == -EINVAL);

        errno = 0;
        assert_se(abs(strtod("0,5", &e) - 0.5) < 0.00001);

        /* And check again, reset */
        setlocale(LC_NUMERIC, "C");

        r = safe_atod("0.2244", &d);
        assert_se(r == 0);
        assert_se(abs(d - 0.2244) < 0.000001);

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

static void test_foreach_word(void) {
        char *w, *state;
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

        FOREACH_WORD(w, l, test, state) {
                assert_se(strneq(expected[i++], w, l));
        }
}

static void test_foreach_word_quoted(void) {
        char *w, *state;
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
        FOREACH_WORD_QUOTED(w, l, test, state) {
                _cleanup_free_ char *t = NULL;

                assert_se(t = strndup(w, l));
                assert_se(strneq(expected[i++], w, l));
                printf("<%s>\n", t);
        }
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

static void test_bus_path_escape_one(const char *a, const char *b) {
        _cleanup_free_ char *t = NULL, *x = NULL, *y = NULL;

        assert_se(t = bus_path_escape(a));
        assert_se(streq(t, b));

        assert_se(x = bus_path_unescape(t));
        assert_se(streq(a, x));

        assert_se(y = bus_path_unescape(b));
        assert_se(streq(a, y));
}

static void test_bus_path_escape(void) {
        test_bus_path_escape_one("foo123bar", "foo123bar");
        test_bus_path_escape_one("foo.bar", "foo_2ebar");
        test_bus_path_escape_one("foo_2ebar", "foo_5f2ebar");
        test_bus_path_escape_one("", "_");
        test_bus_path_escape_one("_", "_5f");
        test_bus_path_escape_one("1", "_31");
        test_bus_path_escape_one(":1", "_3a1");
}

static void test_hostname_is_valid(void) {
        assert(hostname_is_valid("foobar"));
        assert(hostname_is_valid("foobar.com"));
        assert(!hostname_is_valid("fööbar"));
        assert(!hostname_is_valid(""));
        assert(!hostname_is_valid("."));
        assert(!hostname_is_valid(".."));
        assert(!hostname_is_valid("foobar."));
        assert(!hostname_is_valid(".foobar"));
        assert(!hostname_is_valid("foo..bar"));
        assert(!hostname_is_valid("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
}

static void test_u64log2(void) {
        assert(u64log2(0) == 0);
        assert(u64log2(8) == 3);
        assert(u64log2(9) == 3);
        assert(u64log2(15) == 3);
        assert(u64log2(16) == 4);
        assert(u64log2(1024*1024) == 20);
        assert(u64log2(1024*1024+5) == 20);
}

static void test_get_process_comm(void) {
        _cleanup_free_ char *a = NULL, *c = NULL, *d = NULL, *f = NULL, *i = NULL;
        unsigned long long b;
        pid_t e;
        uid_t u;
        gid_t g;
        dev_t h;
        int r;

        assert_se(get_process_comm(1, &a) >= 0);
        log_info("pid1 comm: '%s'", a);

        assert_se(get_starttime_of_pid(1, &b) >= 0);
        log_info("pid1 starttime: '%llu'", b);

        assert_se(get_process_cmdline(1, 0, true, &c) >= 0);
        log_info("pid1 cmdline: '%s'", c);

        assert_se(get_process_cmdline(1, 8, false, &d) >= 0);
        log_info("pid1 cmdline truncated: '%s'", d);

        assert_se(get_parent_of_pid(1, &e) >= 0);
        log_info("pid1 ppid: '%llu'", (unsigned long long) e);
        assert_se(e == 0);

        assert_se(is_kernel_thread(1) == 0);

        r = get_process_exe(1, &f);
        assert_se(r >= 0 || r == -EACCES);
        log_info("pid1 exe: '%s'", strna(f));

        assert_se(get_process_uid(1, &u) == 0);
        log_info("pid1 uid: '%llu'", (unsigned long long) u);
        assert_se(u == 0);

        assert_se(get_process_gid(1, &g) == 0);
        log_info("pid1 gid: '%llu'", (unsigned long long) g);
        assert_se(g == 0);

        assert(get_ctty_devnr(1, &h) == -ENOENT);

        getenv_for_pid(1, "PATH", &i);
        log_info("pid1 $PATH: '%s'", strna(i));
}

static void test_protect_errno(void) {
        errno = 12;
        {
                PROTECT_ERRNO;
                errno = 11;
        }
        assert(errno == 12);
}

int main(int argc, char *argv[]) {
        test_streq_ptr();
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
        test_foreach_word();
        test_foreach_word_quoted();
        test_default_term_for_tty();
        test_memdup_multiply();
        test_bus_path_escape();
        test_hostname_is_valid();
        test_u64log2();
        test_get_process_comm();
        test_protect_errno();

        return 0;
}
