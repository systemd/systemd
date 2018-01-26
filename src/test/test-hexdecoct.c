/* SPDX-License-Identifier: LGPL-2.1+ */
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

#include "alloc-util.h"
#include "hexdecoct.h"
#include "macro.h"
#include "string-util.h"

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
        const char *hex = "efa2149213";
        const char *hex_invalid = "efa214921o";
        _cleanup_free_ char *hex2 = NULL;
        _cleanup_free_ void *mem = NULL;
        size_t len;

        assert_se(unhexmem(hex_invalid, strlen(hex_invalid), &mem, &len) == -EINVAL);
        assert_se(unhexmem(hex, strlen(hex) + 1, &mem, &len) == -EINVAL);
        assert_se(unhexmem(hex, strlen(hex) - 1, &mem, &len) == -EINVAL);
        assert_se(unhexmem(hex, strlen(hex), &mem, &len) == 0);

        assert_se((hex2 = hexmem(mem, len)));
        assert_se(streq(hex, hex2));
}

/* https://tools.ietf.org/html/rfc4648#section-10 */
static void test_base32hexmem(void) {
        char *b32;

        b32 = base32hexmem("", STRLEN(""), true);
        assert_se(b32);
        assert_se(streq(b32, ""));
        free(b32);

        b32 = base32hexmem("f", STRLEN("f"), true);
        assert_se(b32);
        assert_se(streq(b32, "CO======"));
        free(b32);

        b32 = base32hexmem("fo", STRLEN("fo"), true);
        assert_se(b32);
        assert_se(streq(b32, "CPNG===="));
        free(b32);

        b32 = base32hexmem("foo", STRLEN("foo"), true);
        assert_se(b32);
        assert_se(streq(b32, "CPNMU==="));
        free(b32);

        b32 = base32hexmem("foob", STRLEN("foob"), true);
        assert_se(b32);
        assert_se(streq(b32, "CPNMUOG="));
        free(b32);

        b32 = base32hexmem("fooba", STRLEN("fooba"), true);
        assert_se(b32);
        assert_se(streq(b32, "CPNMUOJ1"));
        free(b32);

        b32 = base32hexmem("foobar", STRLEN("foobar"), true);
        assert_se(b32);
        assert_se(streq(b32, "CPNMUOJ1E8======"));
        free(b32);

        b32 = base32hexmem("", STRLEN(""), false);
        assert_se(b32);
        assert_se(streq(b32, ""));
        free(b32);

        b32 = base32hexmem("f", STRLEN("f"), false);
        assert_se(b32);
        assert_se(streq(b32, "CO"));
        free(b32);

        b32 = base32hexmem("fo", STRLEN("fo"), false);
        assert_se(b32);
        assert_se(streq(b32, "CPNG"));
        free(b32);

        b32 = base32hexmem("foo", STRLEN("foo"), false);
        assert_se(b32);
        assert_se(streq(b32, "CPNMU"));
        free(b32);

        b32 = base32hexmem("foob", STRLEN("foob"), false);
        assert_se(b32);
        assert_se(streq(b32, "CPNMUOG"));
        free(b32);

        b32 = base32hexmem("fooba", STRLEN("fooba"), false);
        assert_se(b32);
        assert_se(streq(b32, "CPNMUOJ1"));
        free(b32);

        b32 = base32hexmem("foobar", STRLEN("foobar"), false);
        assert_se(b32);
        assert_se(streq(b32, "CPNMUOJ1E8"));
        free(b32);
}

static void test_unbase32hexmem(void) {
        void *mem;
        size_t len;

        assert_se(unbase32hexmem("", STRLEN(""), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), ""));
        free(mem);

        assert_se(unbase32hexmem("CO======", STRLEN("CO======"), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "f"));
        free(mem);

        assert_se(unbase32hexmem("CPNG====", STRLEN("CPNG===="), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "fo"));
        free(mem);

        assert_se(unbase32hexmem("CPNMU===", STRLEN("CPNMU==="), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foo"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOG=", STRLEN("CPNMUOG="), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foob"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOJ1", STRLEN("CPNMUOJ1"), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "fooba"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOJ1E8======", STRLEN("CPNMUOJ1E8======"), true, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foobar"));
        free(mem);

        assert_se(unbase32hexmem("A", STRLEN("A"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("A=======", STRLEN("A======="), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAA=====", STRLEN("AAA====="), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAAAA==", STRLEN("AAAAAA=="), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AB======", STRLEN("AB======"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAB====", STRLEN("AAAB===="), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAAB===", STRLEN("AAAAB==="), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAAAAB=", STRLEN("AAAAAAB="), true, &mem, &len) == -EINVAL);

        assert_se(unbase32hexmem("XPNMUOJ1", STRLEN("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CXNMUOJ1", STRLEN("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPXMUOJ1", STRLEN("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPNXUOJ1", STRLEN("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPNMXOJ1", STRLEN("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPNMUXJ1", STRLEN("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPNMUOX1", STRLEN("CPNMUOJ1"), true, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPNMUOJX", STRLEN("CPNMUOJ1"), true, &mem, &len) == -EINVAL);

        assert_se(unbase32hexmem("", STRLEN(""), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), ""));
        free(mem);

        assert_se(unbase32hexmem("CO", STRLEN("CO"), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "f"));
        free(mem);

        assert_se(unbase32hexmem("CPNG", STRLEN("CPNG"), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "fo"));
        free(mem);

        assert_se(unbase32hexmem("CPNMU", STRLEN("CPNMU"), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foo"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOG", STRLEN("CPNMUOG"), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foob"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOJ1", STRLEN("CPNMUOJ1"), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "fooba"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOJ1E8", STRLEN("CPNMUOJ1E8"), false, &mem, &len) == 0);
        assert_se(streq(strndupa(mem, len), "foobar"));
        free(mem);

        assert_se(unbase32hexmem("CPNMUOG=", STRLEN("CPNMUOG="), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("CPNMUOJ1E8======", STRLEN("CPNMUOJ1E8======"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("A", STRLEN("A"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("A", STRLEN("A"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAA", STRLEN("AAA"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAAAA", STRLEN("AAAAAA"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AB", STRLEN("AB"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAB", STRLEN("AAAB"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAAB", STRLEN("AAAAB"), false, &mem, &len) == -EINVAL);
        assert_se(unbase32hexmem("AAAAAAB", STRLEN("AAAAAAB"), false, &mem, &len) == -EINVAL);
}

/* https://tools.ietf.org/html/rfc4648#section-10 */
static void test_base64mem(void) {
        char *b64;

        assert_se(base64mem("", STRLEN(""), &b64) == 0);
        assert_se(streq(b64, ""));
        free(b64);

        assert_se(base64mem("f", STRLEN("f"), &b64) == 4);
        assert_se(streq(b64, "Zg=="));
        free(b64);

        assert_se(base64mem("fo", STRLEN("fo"), &b64) == 4);
        assert_se(streq(b64, "Zm8="));
        free(b64);

        assert_se(base64mem("foo", STRLEN("foo"), &b64) == 4);
        assert_se(streq(b64, "Zm9v"));
        free(b64);

        assert_se(base64mem("foob", STRLEN("foob"), &b64) == 8);
        assert_se(streq(b64, "Zm9vYg=="));
        free(b64);

        assert_se(base64mem("fooba", STRLEN("fooba"), &b64) == 8);
        assert_se(streq(b64, "Zm9vYmE="));
        free(b64);

        assert_se(base64mem("foobar", STRLEN("foobar"), &b64) == 8);
        assert_se(streq(b64, "Zm9vYmFy"));
        free(b64);
}

static void test_unbase64mem_one(const char *input, const char *output, int ret) {
        _cleanup_free_ void *buffer = NULL;
        size_t size = 0;

        assert_se(unbase64mem(input, (size_t) -1, &buffer, &size) == ret);

        if (ret >= 0) {
                assert_se(size == strlen(output));
                assert_se(memcmp(buffer, output, size) == 0);
                assert_se(((char*) buffer)[size] == 0);
        }
}

static void test_unbase64mem(void) {

        test_unbase64mem_one("", "", 0);
        test_unbase64mem_one("Zg==", "f", 0);
        test_unbase64mem_one("Zm8=", "fo", 0);
        test_unbase64mem_one("Zm9v", "foo", 0);
        test_unbase64mem_one("Zm9vYg==", "foob", 0);
        test_unbase64mem_one("Zm9vYmE=", "fooba", 0);
        test_unbase64mem_one("Zm9vYmFy", "foobar", 0);

        test_unbase64mem_one(" ", "", 0);
        test_unbase64mem_one(" \n\r ", "", 0);
        test_unbase64mem_one("    Zg\n==       ", "f", 0);
        test_unbase64mem_one(" Zm 8=\r", "fo", 0);
        test_unbase64mem_one("  Zm9\n\r\r\nv   ", "foo", 0);
        test_unbase64mem_one(" Z m9vYg==\n\r", "foob", 0);
        test_unbase64mem_one(" Zm 9vYmE=   ", "fooba", 0);
        test_unbase64mem_one("   Z m9v    YmFy   ", "foobar", 0);

        test_unbase64mem_one("A", NULL, -EPIPE);
        test_unbase64mem_one("A====", NULL, -EINVAL);
        test_unbase64mem_one("AAB==", NULL, -EINVAL);
        test_unbase64mem_one(" A A A B = ", NULL, -EINVAL);
        test_unbase64mem_one(" Z m 8 = q u u x ", NULL, -ENAMETOOLONG);
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

int main(int argc, char *argv[]) {
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
        test_hexdump();

        return 0;
}
