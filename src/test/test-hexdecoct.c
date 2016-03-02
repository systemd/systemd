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

        assert_se(base64mem("", strlen(""), &b64) == 0);
        assert_se(streq(b64, ""));
        free(b64);

        assert_se(base64mem("f", strlen("f"), &b64) == 4);
        assert_se(streq(b64, "Zg=="));
        free(b64);

        assert_se(base64mem("fo", strlen("fo"), &b64) == 4);
        assert_se(streq(b64, "Zm8="));
        free(b64);

        assert_se(base64mem("foo", strlen("foo"), &b64) == 4);
        assert_se(streq(b64, "Zm9v"));
        free(b64);

        assert_se(base64mem("foob", strlen("foob"), &b64) == 8);
        assert_se(streq(b64, "Zm9vYg=="));
        free(b64);

        assert_se(base64mem("fooba", strlen("fooba"), &b64) == 8);
        assert_se(streq(b64, "Zm9vYmE="));
        free(b64);

        assert_se(base64mem("foobar", strlen("foobar"), &b64) == 8);
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
