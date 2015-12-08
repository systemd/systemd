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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "cpu-set-util.h"
#include "def.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "fstab-util.h"
#include "glob-util.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "rm-rf.h"
#include "signal-util.h"
#include "special.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"
#include "virt.h"
#include "web-util.h"
#include "xattr-util.h"

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

static void test_div_round_up(void) {
        int div;

        /* basic tests */
        assert_se(DIV_ROUND_UP(0, 8) == 0);
        assert_se(DIV_ROUND_UP(1, 8) == 1);
        assert_se(DIV_ROUND_UP(8, 8) == 1);
        assert_se(DIV_ROUND_UP(12, 8) == 2);
        assert_se(DIV_ROUND_UP(16, 8) == 2);

        /* test multiple evaluation */
        div = 0;
        assert_se(DIV_ROUND_UP(div++, 8) == 0 && div == 1);
        assert_se(DIV_ROUND_UP(++div, 8) == 1 && div == 2);
        assert_se(DIV_ROUND_UP(8, div++) == 4 && div == 3);
        assert_se(DIV_ROUND_UP(8, ++div) == 2 && div == 4);

        /* overflow test with exact division */
        assert_se(sizeof(0U) == 4);
        assert_se(0xfffffffaU % 10U == 0U);
        assert_se(0xfffffffaU / 10U == 429496729U);
        assert_se(DIV_ROUND_UP(0xfffffffaU, 10U) == 429496729U);
        assert_se((0xfffffffaU + 10U - 1U) / 10U == 0U);
        assert_se(0xfffffffaU / 10U + !!(0xfffffffaU % 10U) == 429496729U);

        /* overflow test with rounded division */
        assert_se(0xfffffffdU % 10U == 3U);
        assert_se(0xfffffffdU / 10U == 429496729U);
        assert_se(DIV_ROUND_UP(0xfffffffdU, 10U) == 429496730U);
        assert_se((0xfffffffdU + 10U - 1U) / 10U == 0U);
        assert_se(0xfffffffdU / 10U + !!(0xfffffffdU % 10U) == 429496730U);
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

static void test_parse_uid(void) {
        int r;
        uid_t uid;

        r = parse_uid("100", &uid);
        assert_se(r == 0);
        assert_se(uid == 100);

        r = parse_uid("65535", &uid);
        assert_se(r == -ENXIO);

        r = parse_uid("asdsdas", &uid);
        assert_se(r == -EINVAL);
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

static void test_base32hexchar(void) {
        assert_se(base32hexchar(0) == '0');
        assert_se(base32hexchar(9) == '9');
        assert_se(base32hexchar(10) == 'A');
        assert_se(base32hexchar(31) == 'V');
}

static void test_unbase32hexchar(void) {
        assert_se(unbase32hexchar('0') == 0);
        assert_se(unbase32hexchar('9') == 9);
        assert_se(unbase32hexchar('A') == 10);
        assert_se(unbase32hexchar('V') == 31);
        assert_se(unbase32hexchar('=') == -EINVAL);
}

static void test_base64char(void) {
        assert_se(base64char(0) == 'A');
        assert_se(base64char(26) == 'a');
        assert_se(base64char(63) == '/');
}

static void test_unbase64char(void) {
        assert_se(unbase64char('A') == 0);
        assert_se(unbase64char('Z') == 25);
        assert_se(unbase64char('a') == 26);
        assert_se(unbase64char('z') == 51);
        assert_se(unbase64char('0') == 52);
        assert_se(unbase64char('9') == 61);
        assert_se(unbase64char('+') == 62);
        assert_se(unbase64char('/') == 63);
        assert_se(unbase64char('=') == -EINVAL);
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

static void test_unhexmem(void) {
        const char *hex = "efa214921";
        const char *hex_invalid = "efa214921o";
        _cleanup_free_ char *hex2 = NULL;
        _cleanup_free_ void *mem = NULL;
        size_t len;

        assert_se(unhexmem(hex, strlen(hex), &mem, &len) == 0);
        assert_se(unhexmem(hex, strlen(hex) + 1, &mem, &len) == -EINVAL);
        assert_se(unhexmem(hex_invalid, strlen(hex_invalid), &mem, &len) == -EINVAL);

        assert_se((hex2 = hexmem(mem, len)));

        free(mem);

        assert_se(memcmp(hex, hex2, strlen(hex)) == 0);

        free(hex2);

        assert_se(unhexmem(hex, strlen(hex) - 1, &mem, &len) == 0);
        assert_se((hex2 = hexmem(mem, len)));
        assert_se(memcmp(hex, hex2, strlen(hex) - 1) == 0);
}

/* https://tools.ietf.org/html/rfc4648#section-10 */
static void test_base32hexmem(void) {
        char *b32;

        b32 = base32hexmem("", strlen(""), true);
        assert_se(b32);
        assert_se(streq(b32, ""));
        free(b32);

        b32 = base32hexmem("f", strlen("f"), true);
        assert_se(b32);
        assert_se(streq(b32, "CO======"));
        free(b32);

        b32 = base32hexmem("fo", strlen("fo"), true);
        assert_se(b32);
        assert_se(streq(b32, "CPNG===="));
        free(b32);

        b32 = base32hexmem("foo", strlen("foo"), true);
        assert_se(b32);
        assert_se(streq(b32, "CPNMU==="));
        free(b32);

        b32 = base32hexmem("foob", strlen("foob"), true);
        assert_se(b32);
        assert_se(streq(b32, "CPNMUOG="));
        free(b32);

        b32 = base32hexmem("fooba", strlen("fooba"), true);
        assert_se(b32);
        assert_se(streq(b32, "CPNMUOJ1"));
        free(b32);

        b32 = base32hexmem("foobar", strlen("foobar"), true);
        assert_se(b32);
        assert_se(streq(b32, "CPNMUOJ1E8======"));
        free(b32);

        b32 = base32hexmem("", strlen(""), false);
        assert_se(b32);
        assert_se(streq(b32, ""));
        free(b32);

        b32 = base32hexmem("f", strlen("f"), false);
        assert_se(b32);
        assert_se(streq(b32, "CO"));
        free(b32);

        b32 = base32hexmem("fo", strlen("fo"), false);
        assert_se(b32);
        assert_se(streq(b32, "CPNG"));
        free(b32);

        b32 = base32hexmem("foo", strlen("foo"), false);
        assert_se(b32);
        assert_se(streq(b32, "CPNMU"));
        free(b32);

        b32 = base32hexmem("foob", strlen("foob"), false);
        assert_se(b32);
        assert_se(streq(b32, "CPNMUOG"));
        free(b32);

        b32 = base32hexmem("fooba", strlen("fooba"), false);
        assert_se(b32);
        assert_se(streq(b32, "CPNMUOJ1"));
        free(b32);

        b32 = base32hexmem("foobar", strlen("foobar"), false);
        assert_se(b32);
        assert_se(streq(b32, "CPNMUOJ1E8"));
        free(b32);
}

static void test_unbase32hexmem(void) {
        void *mem;
        size_t len;

        assert_se(unbase32hexmem("", strlen(""), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), ""));
        free(mem);

        assert_se(unbase32hexmem("CO======", strlen("CO======"), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "f"));
        free(mem);

        assert_se(unbase32hexmem("CPNG====", strlen("CPNG===="), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "fo"));
        free(mem);

        assert_se(unbase32hexmem("CPNMU===", strlen("CPNMU==="), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foo"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOG=", strlen("CPNMUOG="), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foob"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOJ1", strlen("CPNMUOJ1"), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "fooba"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOJ1E8======", strlen("CPNMUOJ1E8======"), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foobar"));
        free(mem);

        assert_se(unbase32hexmem("A", strlen("A"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("A=======", strlen("A======="), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAA=====", strlen("AAA====="), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAAAA==", strlen("AAAAAA=="), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AB======", strlen("AB======"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAB====", strlen("AAAB===="), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAAB===", strlen("AAAAB==="), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAAAAB=", strlen("AAAAAAB="), true, &mem, &len) == -EINVAL);

        assert_se(unbase32hexmem("XPNMUOJ1", strlen("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CXNMUOJ1", strlen("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPXMUOJ1", strlen("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPNXUOJ1", strlen("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPNMXOJ1", strlen("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPNMUXJ1", strlen("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPNMUOX1", strlen("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPNMUOJX", strlen("CPNMUOJ1"), true, &mem, &len) == -EINVAL);

        assert_se(unbase32hexmem("", strlen(""), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), ""));
        free(mem);

        assert_se(unbase32hexmem("CO", strlen("CO"), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "f"));
        free(mem);

        assert_se(unbase32hexmem("CPNG", strlen("CPNG"), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "fo"));
        free(mem);

        assert_se(unbase32hexmem("CPNMU", strlen("CPNMU"), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foo"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOG", strlen("CPNMUOG"), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foob"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOJ1", strlen("CPNMUOJ1"), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "fooba"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOJ1E8", strlen("CPNMUOJ1E8"), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foobar"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOG=", strlen("CPNMUOG="), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPNMUOJ1E8======", strlen("CPNMUOJ1E8======"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("A", strlen("A"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("A", strlen("A"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAA", strlen("AAA"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAAAA", strlen("AAAAAA"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AB", strlen("AB"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAB", strlen("AAAB"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAAB", strlen("AAAAB"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAAAAB", strlen("AAAAAAB"), false, &mem, &len) == -EINVAL);
}

/* https://tools.ietf.org/html/rfc4648#section-10 */
static void test_base64mem(void) {
        char *b64;

        b64 = base64mem("", strlen(""));
        assert_se(b64);
        assert_se(streq(b64, ""));
        free(b64);

        b64 = base64mem("f", strlen("f"));
        assert_se(b64);
        assert_se(streq(b64, "Zg=="));
        free(b64);

        b64 = base64mem("fo", strlen("fo"));
        assert_se(b64);
        assert_se(streq(b64, "Zm8="));
        free(b64);

        b64 = base64mem("foo", strlen("foo"));
        assert_se(b64);
        assert_se(streq(b64, "Zm9v"));
        free(b64);

        b64 = base64mem("foob", strlen("foob"));
        assert_se(b64);
        assert_se(streq(b64, "Zm9vYg=="));
        free(b64);

        b64 = base64mem("fooba", strlen("fooba"));
        assert_se(b64);
        assert_se(streq(b64, "Zm9vYmE="));
        free(b64);

        b64 = base64mem("foobar", strlen("foobar"));
        assert_se(b64);
        assert_se(streq(b64, "Zm9vYmFy"));
        free(b64);
}

static void test_unbase64mem(void) {
        void *mem;
        size_t len;

        assert_se(unbase64mem("", strlen(""), &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), ""));
        free(mem);

        assert_se(unbase64mem("Zg==", strlen("Zg=="), &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "f"));
        free(mem);

        assert_se(unbase64mem("Zm8=", strlen("Zm8="), &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "fo"));
        free(mem);

        assert_se(unbase64mem("Zm9v", strlen("Zm9v"), &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foo"));
        free(mem);

        assert_se(unbase64mem("Zm9vYg==", strlen("Zm9vYg=="), &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foob"));
        free(mem);

        assert_se(unbase64mem("Zm9vYmE=", strlen("Zm9vYmE="), &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "fooba"));
        free(mem);

        assert_se(unbase64mem("Zm9vYmFy", strlen("Zm9vYmFy"), &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foobar"));
        free(mem);

        assert_se(unbase64mem("A", strlen("A"), &mem, &len) == -EINVAL);
        assert_se(unbase64mem("A====", strlen("A===="), &mem, &len) == -EINVAL);
        assert_se(unbase64mem("AAB==", strlen("AAB=="), &mem, &len) == -EINVAL);
        assert_se(unbase64mem("AAAB=", strlen("AAAB="), &mem, &len) == -EINVAL);
}

static void test_cescape(void) {
        _cleanup_free_ char *escaped;

        assert_se(escaped = cescape("abc\\\"\b\f\n\r\t\v\a\003\177\234\313"));
        assert_se(streq(escaped, "abc\\\\\\\"\\b\\f\\n\\r\\t\\v\\a\\003\\177\\234\\313"));
}

static void test_cunescape(void) {
        _cleanup_free_ char *unescaped;

        assert_se(cunescape("abc\\\\\\\"\\b\\f\\a\\n\\r\\t\\v\\003\\177\\234\\313\\000\\x00", 0, &unescaped) < 0);
        assert_se(cunescape("abc\\\\\\\"\\b\\f\\a\\n\\r\\t\\v\\003\\177\\234\\313\\000\\x00", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "abc\\\"\b\f\a\n\r\t\v\003\177\234\313\\000\\x00"));
        unescaped = mfree(unescaped);

        /* incomplete sequences */
        assert_se(cunescape("\\x0", 0, &unescaped) < 0);
        assert_se(cunescape("\\x0", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "\\x0"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\x", 0, &unescaped) < 0);
        assert_se(cunescape("\\x", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "\\x"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\", 0, &unescaped) < 0);
        assert_se(cunescape("\\", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "\\"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\11", 0, &unescaped) < 0);
        assert_se(cunescape("\\11", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "\\11"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\1", 0, &unescaped) < 0);
        assert_se(cunescape("\\1", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "\\1"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\u0000", 0, &unescaped) < 0);
        assert_se(cunescape("\\u00DF\\U000000df\\u03a0\\U00000041", UNESCAPE_RELAX, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, "ßßΠA"));
        unescaped = mfree(unescaped);

        assert_se(cunescape("\\073", 0, &unescaped) >= 0);
        assert_se(streq_ptr(unescaped, ";"));
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

static void check(const char *test, char** expected, bool trailing) {
        const char *word, *state;
        size_t l;
        int i = 0;

        printf("<<<%s>>>\n", test);
        FOREACH_WORD_QUOTED(word, l, test, state) {
                _cleanup_free_ char *t = NULL;

                assert_se(t = strndup(word, l));
                assert_se(strneq(expected[i++], word, l));
                printf("<%s>\n", t);
        }
        printf("<<<%s>>>\n", state);
        assert_se(expected[i] == NULL);
        assert_se(isempty(state) == !trailing);
}

static void test_foreach_word_quoted(void) {
        check("test a b c 'd' e '' '' hhh '' '' \"a b c\"",
              STRV_MAKE("test",
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
                        "a b c"),
              false);

        check("test \"xxx",
              STRV_MAKE("test"),
              true);

        check("test\\",
              STRV_MAKE_EMPTY,
              true);
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

static void test_u64log2(void) {
        assert_se(u64log2(0) == 0);
        assert_se(u64log2(8) == 3);
        assert_se(u64log2(9) == 3);
        assert_se(u64log2(15) == 3);
        assert_se(u64log2(16) == 4);
        assert_se(u64log2(1024*1024) == 20);
        assert_se(u64log2(1024*1024+5) == 20);
}

static void test_protect_errno(void) {
        errno = 12;
        {
                PROTECT_ERRNO;
                errno = 11;
        }
        assert_se(errno == 12);
}

static void test_parse_cpu_set(void) {
        cpu_set_t *c = NULL;
        int ncpus;
        int cpu;

        /* Simple range (from CPUAffinity example) */
        ncpus = parse_cpu_set_and_warn("1 2", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_ISSET_S(1, CPU_ALLOC_SIZE(ncpus), c));
        assert_se(CPU_ISSET_S(2, CPU_ALLOC_SIZE(ncpus), c));
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 2);
        c = mfree(c);

        /* A more interesting range */
        ncpus = parse_cpu_set_and_warn("0 1 2 3 8 9 10 11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Quoted strings */
        ncpus = parse_cpu_set_and_warn("8 '9' 10 \"11\"", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 4);
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Use commas as separators */
        ncpus = parse_cpu_set_and_warn("0,1,2,3 8,9,10,11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Commas with spaces (and trailing comma, space) */
        ncpus = parse_cpu_set_and_warn("0, 1, 2, 3, 4, 5, 6, 7, ", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 8; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Ranges */
        ncpus = parse_cpu_set_and_warn("0-3,8-11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Ranges with trailing comma, space */
        ncpus = parse_cpu_set_and_warn("0-3  8-11, ", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Negative range (returns empty cpu_set) */
        ncpus = parse_cpu_set_and_warn("3-0", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 0);
        c = mfree(c);

        /* Overlapping ranges */
        ncpus = parse_cpu_set_and_warn("0-7 4-11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 12);
        for (cpu = 0; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Mix ranges and individual CPUs */
        ncpus = parse_cpu_set_and_warn("0,1 4-11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 10);
        assert_se(CPU_ISSET_S(0, CPU_ALLOC_SIZE(ncpus), c));
        assert_se(CPU_ISSET_S(1, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 4; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Garbage */
        ncpus = parse_cpu_set_and_warn("0 1 2 3 garbage", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus < 0);
        assert_se(!c);

        /* Range with garbage */
        ncpus = parse_cpu_set_and_warn("0-3 8-garbage", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus < 0);
        assert_se(!c);

        /* Empty string */
        c = NULL;
        ncpus = parse_cpu_set_and_warn("", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus == 0);  /* empty string returns 0 */
        assert_se(!c);

        /* Runnaway quoted string */
        ncpus = parse_cpu_set_and_warn("0 1 2 3 \"4 5 6 7 ", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus < 0);
        assert_se(!c);
}

static void test_config_parse_iec_uint64(void) {
        uint64_t offset = 0;
        assert_se(config_parse_iec_uint64(NULL, "/this/file", 11, "Section", 22, "Size", 0, "4M", &offset, NULL) == 0);
        assert_se(offset == 4 * 1024 * 1024);

        assert_se(config_parse_iec_uint64(NULL, "/this/file", 11, "Section", 22, "Size", 0, "4.5M", &offset, NULL) == 0);
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

static void test_filename_is_valid(void) {
        char foo[FILENAME_MAX+2];
        int i;

        assert_se(!filename_is_valid(""));
        assert_se(!filename_is_valid("/bar/foo"));
        assert_se(!filename_is_valid("/"));
        assert_se(!filename_is_valid("."));
        assert_se(!filename_is_valid(".."));

        for (i=0; i<FILENAME_MAX+1; i++)
                foo[i] = 'a';
        foo[FILENAME_MAX+1] = '\0';

        assert_se(!filename_is_valid(foo));

        assert_se(filename_is_valid("foo_bar-333"));
        assert_se(filename_is_valid("o.o"));
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
        assert_se(documentation_url_is_valid("http://www.freedesktop.org/wiki/Software/systemd"));
        assert_se(documentation_url_is_valid("https://www.kernel.org/doc/Documentation/binfmt_misc.txt"));
        assert_se(documentation_url_is_valid("file:/foo/foo"));
        assert_se(documentation_url_is_valid("man:systemd.special(7)"));
        assert_se(documentation_url_is_valid("info:bar"));

        assert_se(!documentation_url_is_valid("foo:"));
        assert_se(!documentation_url_is_valid("info:"));
        assert_se(!documentation_url_is_valid(""));
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

static void test_endswith_no_case(void) {
        assert_se(endswith_no_case("fooBAR", "bar"));
        assert_se(endswith_no_case("foobar", ""));
        assert_se(endswith_no_case("foobar", "FOOBAR"));
        assert_se(endswith_no_case("", ""));

        assert_se(!endswith_no_case("foobar", "FOO"));
        assert_se(!endswith_no_case("foobar", "FOOBARFOOFOO"));
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

        assert_se(rm_rf(tempdir, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
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

static void test_strjoina(void) {
        char *actual;

        actual = strjoina("", "foo", "bar");
        assert_se(streq(actual, "foobar"));

        actual = strjoina("foo", "bar", "baz");
        assert_se(streq(actual, "foobarbaz"));

        actual = strjoina("foo", "", "bar", "baz");
        assert_se(streq(actual, "foobarbaz"));

        actual = strjoina("foo");
        assert_se(streq(actual, "foo"));

        actual = strjoina(NULL);
        assert_se(streq(actual, ""));

        actual = strjoina(NULL, "foo");
        assert_se(streq(actual, ""));

        actual = strjoina("foo", NULL, "bar");
        assert_se(streq(actual, "foo"));
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
        char template_lo[] = "/tmp/test-readlink_and_make_absolute-lo.XXXXXXX";
        char template_hi[] = "/tmp/test-readlink_and_make_absolute-hi.XXXXXXX";
        const char * dirs[] = {template_hi, template_lo, NULL};
        const char *name, *name2, *name3, *overridden, *override, *masked, *mask;

        assert_se(mkdtemp(template_lo));
        assert_se(mkdtemp(template_hi));

        name = strjoina(template_lo, "/script");
        name2 = strjoina(template_hi, "/script2");
        name3 = strjoina(template_lo, "/useless");
        overridden = strjoina(template_lo, "/overridden");
        override = strjoina(template_hi, "/overridden");
        masked = strjoina(template_lo, "/masked");
        mask = strjoina(template_hi, "/masked");

        assert_se(write_string_file(name, "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/it_works", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(name2, "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/it_works2", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(overridden, "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/failed", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(override, "#!/bin/sh\necho 'Executing '$0", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(masked, "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/failed", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(symlink("/dev/null", mask) == 0);
        assert_se(chmod(name, 0755) == 0);
        assert_se(chmod(name2, 0755) == 0);
        assert_se(chmod(overridden, 0755) == 0);
        assert_se(chmod(override, 0755) == 0);
        assert_se(chmod(masked, 0755) == 0);
        assert_se(touch(name3) >= 0);

        execute_directories(dirs, DEFAULT_TIMEOUT_USEC, NULL);

        assert_se(chdir(template_lo) == 0);
        assert_se(access("it_works", F_OK) >= 0);
        assert_se(access("failed", F_OK) < 0);

        assert_se(chdir(template_hi) == 0);
        assert_se(access("it_works2", F_OK) >= 0);
        assert_se(access("failed", F_OK) < 0);

        (void) rm_rf(template_lo, REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf(template_hi, REMOVE_ROOT|REMOVE_PHYSICAL);
}

static int parse_item(const char *key, const char *value) {
        assert_se(key);

        log_info("kernel cmdline option <%s> = <%s>", key, strna(value));
        return 0;
}

static void test_parse_proc_cmdline(void) {
        assert_se(parse_proc_cmdline(parse_item) >= 0);
}

static void test_raw_clone(void) {
        pid_t parent, pid, pid2;

        parent = getpid();
        log_info("before clone: getpid()→"PID_FMT, parent);
        assert_se(raw_getpid() == parent);

        pid = raw_clone(0, NULL);
        assert_se(pid >= 0);

        pid2 = raw_getpid();
        log_info("raw_clone: "PID_FMT" getpid()→"PID_FMT" raw_getpid()→"PID_FMT,
                 pid, getpid(), pid2);
        if (pid == 0) {
                assert_se(pid2 != parent);
                _exit(EXIT_SUCCESS);
        } else {
                int status;

                assert_se(pid2 == parent);
                waitpid(pid, &status, __WCLONE);
                assert_se(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
        }
}

static void test_same_fd(void) {
        _cleanup_close_pair_ int p[2] = { -1, -1 };
        _cleanup_close_ int a = -1, b = -1, c = -1;

        assert_se(pipe2(p, O_CLOEXEC) >= 0);
        assert_se((a = dup(p[0])) >= 0);
        assert_se((b = open("/dev/null", O_RDONLY|O_CLOEXEC)) >= 0);
        assert_se((c = dup(a)) >= 0);

        assert_se(same_fd(p[0], p[0]) > 0);
        assert_se(same_fd(p[1], p[1]) > 0);
        assert_se(same_fd(a, a) > 0);
        assert_se(same_fd(b, b) > 0);

        assert_se(same_fd(a, p[0]) > 0);
        assert_se(same_fd(p[0], a) > 0);
        assert_se(same_fd(c, p[0]) > 0);
        assert_se(same_fd(p[0], c) > 0);
        assert_se(same_fd(a, c) > 0);
        assert_se(same_fd(c, a) > 0);

        assert_se(same_fd(p[0], p[1]) == 0);
        assert_se(same_fd(p[1], p[0]) == 0);
        assert_se(same_fd(p[0], b) == 0);
        assert_se(same_fd(b, p[0]) == 0);
        assert_se(same_fd(p[1], a) == 0);
        assert_se(same_fd(a, p[1]) == 0);
        assert_se(same_fd(p[1], b) == 0);
        assert_se(same_fd(b, p[1]) == 0);

        assert_se(same_fd(a, b) == 0);
        assert_se(same_fd(b, a) == 0);
}

static void test_uid_ptr(void) {

        assert_se(UID_TO_PTR(0) != NULL);
        assert_se(UID_TO_PTR(1000) != NULL);

        assert_se(PTR_TO_UID(UID_TO_PTR(0)) == 0);
        assert_se(PTR_TO_UID(UID_TO_PTR(1000)) == 1000);
}

static void test_sparse_write_one(int fd, const char *buffer, size_t n) {
        char check[n];

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) >= 0);
        assert_se(sparse_write(fd, buffer, n, 4) == (ssize_t) n);

        assert_se(lseek(fd, 0, SEEK_CUR) == (off_t) n);
        assert_se(ftruncate(fd, n) >= 0);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(read(fd, check, n) == (ssize_t) n);

        assert_se(memcmp(buffer, check, n) == 0);
}

static void test_sparse_write(void) {
        const char test_a[] = "test";
        const char test_b[] = "\0\0\0\0test\0\0\0\0";
        const char test_c[] = "\0\0test\0\0\0\0";
        const char test_d[] = "\0\0test\0\0\0test\0\0\0\0test\0\0\0\0\0test\0\0\0test\0\0\0\0test\0\0\0\0\0\0\0\0";
        const char test_e[] = "test\0\0\0\0test";
        _cleanup_close_ int fd = -1;
        char fn[] = "/tmp/sparseXXXXXX";

        fd = mkostemp(fn, O_CLOEXEC);
        assert_se(fd >= 0);
        unlink(fn);

        test_sparse_write_one(fd, test_a, sizeof(test_a));
        test_sparse_write_one(fd, test_b, sizeof(test_b));
        test_sparse_write_one(fd, test_c, sizeof(test_c));
        test_sparse_write_one(fd, test_d, sizeof(test_d));
        test_sparse_write_one(fd, test_e, sizeof(test_e));
}

static void test_shell_escape_one(const char *s, const char *bad, const char *expected) {
        _cleanup_free_ char *r;

        assert_se(r = shell_escape(s, bad));
        assert_se(streq_ptr(r, expected));
}

static void test_shell_escape(void) {
        test_shell_escape_one("", "", "");
        test_shell_escape_one("\\", "", "\\\\");
        test_shell_escape_one("foobar", "", "foobar");
        test_shell_escape_one("foobar", "o", "f\\o\\obar");
        test_shell_escape_one("foo:bar,baz", ",:", "foo\\:bar\\,baz");
}

static void test_shell_maybe_quote_one(const char *s, const char *expected) {
        _cleanup_free_ char *r;

        assert_se(r = shell_maybe_quote(s));
        assert_se(streq(r, expected));
}

static void test_shell_maybe_quote(void) {

        test_shell_maybe_quote_one("", "");
        test_shell_maybe_quote_one("\\", "\"\\\\\"");
        test_shell_maybe_quote_one("\"", "\"\\\"\"");
        test_shell_maybe_quote_one("foobar", "foobar");
        test_shell_maybe_quote_one("foo bar", "\"foo bar\"");
        test_shell_maybe_quote_one("foo \"bar\" waldo", "\"foo \\\"bar\\\" waldo\"");
        test_shell_maybe_quote_one("foo$bar", "\"foo\\$bar\"");
}

static void test_tempfn(void) {
        char *ret = NULL, *p;

        assert_se(tempfn_xxxxxx("/foo/bar/waldo", NULL, &ret) >= 0);
        assert_se(streq_ptr(ret, "/foo/bar/.#waldoXXXXXX"));
        free(ret);

        assert_se(tempfn_xxxxxx("/foo/bar/waldo", "[miau]", &ret) >= 0);
        assert_se(streq_ptr(ret, "/foo/bar/.#[miau]waldoXXXXXX"));
        free(ret);

        assert_se(tempfn_random("/foo/bar/waldo", NULL, &ret) >= 0);
        assert_se(p = startswith(ret, "/foo/bar/.#waldo"));
        assert_se(strlen(p) == 16);
        assert_se(in_charset(p, "0123456789abcdef"));
        free(ret);

        assert_se(tempfn_random("/foo/bar/waldo", "[wuff]", &ret) >= 0);
        assert_se(p = startswith(ret, "/foo/bar/.#[wuff]waldo"));
        assert_se(strlen(p) == 16);
        assert_se(in_charset(p, "0123456789abcdef"));
        free(ret);

        assert_se(tempfn_random_child("/foo/bar/waldo", NULL, &ret) >= 0);
        assert_se(p = startswith(ret, "/foo/bar/waldo/.#"));
        assert_se(strlen(p) == 16);
        assert_se(in_charset(p, "0123456789abcdef"));
        free(ret);

        assert_se(tempfn_random_child("/foo/bar/waldo", "[kikiriki]", &ret) >= 0);
        assert_se(p = startswith(ret, "/foo/bar/waldo/.#[kikiriki]"));
        assert_se(strlen(p) == 16);
        assert_se(in_charset(p, "0123456789abcdef"));
        free(ret);
}

static void test_strcmp_ptr(void) {
        assert_se(strcmp_ptr(NULL, NULL) == 0);
        assert_se(strcmp_ptr("", NULL) > 0);
        assert_se(strcmp_ptr("foo", NULL) > 0);
        assert_se(strcmp_ptr(NULL, "") < 0);
        assert_se(strcmp_ptr(NULL, "bar") < 0);
        assert_se(strcmp_ptr("foo", "bar") > 0);
        assert_se(strcmp_ptr("bar", "baz") < 0);
        assert_se(strcmp_ptr("foo", "foo") == 0);
        assert_se(strcmp_ptr("", "") == 0);
}

static void test_fgetxattrat_fake(void) {
        char t[] = "/var/tmp/xattrtestXXXXXX";
        _cleanup_close_ int fd = -1;
        const char *x;
        char v[3] = {};
        int r;

        assert_se(mkdtemp(t));
        x = strjoina(t, "/test");
        assert_se(touch(x) >= 0);

        r = setxattr(x, "user.foo", "bar", 3, 0);
        if (r < 0 && errno == EOPNOTSUPP) /* no xattrs supported on /var/tmp... */
                goto cleanup;
        assert_se(r >= 0);

        fd = open(t, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOCTTY);
        assert_se(fd >= 0);

        assert_se(fgetxattrat_fake(fd, "test", "user.foo", v, 3, 0) >= 0);
        assert_se(memcmp(v, "bar", 3) == 0);

        safe_close(fd);
        fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOCTTY);
        assert_se(fd >= 0);
        assert_se(fgetxattrat_fake(fd, "usr", "user.idontexist", v, 3, 0) == -ENODATA);

cleanup:
        assert_se(unlink(x) >= 0);
        assert_se(rmdir(t) >= 0);
}

static void test_runlevel_to_target(void) {
        assert_se(streq_ptr(runlevel_to_target(NULL), NULL));
        assert_se(streq_ptr(runlevel_to_target("unknown-runlevel"), NULL));
        assert_se(streq_ptr(runlevel_to_target("3"), SPECIAL_MULTI_USER_TARGET));
}

int main(int argc, char *argv[]) {
        log_parse_environment();
        log_open();

        test_streq_ptr();
        test_align_power2();
        test_max();
        test_container_of();
        test_alloca();
        test_div_round_up();
        test_first_word();
        test_close_many();
        test_parse_uid();
        test_strappend();
        test_strstrip();
        test_delete_chars();
        test_in_charset();
        test_hexchar();
        test_unhexchar();
        test_base32hexchar();
        test_unbase32hexchar();
        test_base64char();
        test_unbase64char();
        test_octchar();
        test_unoctchar();
        test_decchar();
        test_undecchar();
        test_unhexmem();
        test_base32hexmem();
        test_unbase32hexmem();
        test_base64mem();
        test_unbase64mem();
        test_cescape();
        test_cunescape();
        test_foreach_word();
        test_foreach_word_quoted();
        test_memdup_multiply();
        test_u64log2();
        test_protect_errno();
        test_parse_cpu_set();
        test_config_parse_iec_uint64();
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
        test_filename_is_valid();
        test_string_has_cc();
        test_ascii_strlower();
        test_files_same();
        test_is_valid_documentation_url();
        test_file_in_same_dir();
        test_endswith();
        test_endswith_no_case();
        test_close_nointr();
        test_unlink_noerrno();
        test_readlink_and_make_absolute();
        test_ignore_signals();
        test_strshorten();
        test_strjoina();
        test_is_symlink();
        test_search_and_fopen();
        test_search_and_fopen_nulstr();
        test_glob_exists();
        test_execute_directory();
        test_parse_proc_cmdline();
        test_raw_clone();
        test_same_fd();
        test_uid_ptr();
        test_sparse_write();
        test_shell_escape();
        test_shell_maybe_quote();
        test_tempfn();
        test_strcmp_ptr();
        test_fgetxattrat_fake();
        test_runlevel_to_target();

        return 0;
}
