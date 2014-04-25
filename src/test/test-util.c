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

static void test_cescape(void) {
        _cleanup_free_ char *escaped;
        escaped = cescape("abc\\\"\b\f\n\r\t\v\003\177\234\313");
        assert_se(streq(escaped, "abc\\\\\\\"\\b\\f\\n\\r\\t\\v\\003\\177\\234\\313"));
}

static void test_cunescape(void) {
        _cleanup_free_ char *unescaped;
        unescaped = cunescape("abc\\\\\\\"\\b\\f\\n\\r\\t\\v\\003\\177\\234\\313");
        assert_se(streq(unescaped, "abc\\\"\b\f\n\r\t\v\003\177\234\313"));
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
        assert(r >= 0);

        r = read_full_file(name, &contents, &size);
        assert(r == 0);
        printf("contents: %s", contents);
        assert(streq(contents, "abc\n" ALPHANUMERICAL "\n"));
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

int main(int argc, char *argv[]) {
        log_parse_environment();
        log_open();

        test_streq_ptr();
        test_align_power2();
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

        return 0;
}
