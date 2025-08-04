/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hexdecoct.h"
#include "random-util.h"
#include "string-util.h"
#include "tests.h"

TEST(hexchar) {
        assert_se(hexchar(0xa) == 'a');
        assert_se(hexchar(0x0) == '0');
}

TEST(unhexchar) {
        assert_se(unhexchar('a') == 0xA);
        assert_se(unhexchar('A') == 0xA);
        assert_se(unhexchar('0') == 0x0);
}

TEST(base32hexchar) {
        assert_se(base32hexchar(0) == '0');
        assert_se(base32hexchar(9) == '9');
        assert_se(base32hexchar(10) == 'A');
        assert_se(base32hexchar(31) == 'V');
}

TEST(unbase32hexchar) {
        assert_se(unbase32hexchar('0') == 0);
        assert_se(unbase32hexchar('9') == 9);
        assert_se(unbase32hexchar('A') == 10);
        assert_se(unbase32hexchar('V') == 31);
        assert_se(unbase32hexchar('=') == -EINVAL);
}

TEST(base64char) {
        assert_se(base64char(0) == 'A');
        assert_se(base64char(26) == 'a');
        assert_se(base64char(63) == '/');
}

TEST(unbase64char) {
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

TEST(octchar) {
        assert_se(octchar(00) == '0');
        assert_se(octchar(07) == '7');
}

TEST(unoctchar) {
        assert_se(unoctchar('0') == 00);
        assert_se(unoctchar('7') == 07);
}

TEST(decchar) {
        assert_se(decchar(0) == '0');
        assert_se(decchar(9) == '9');
}

TEST(undecchar) {
        assert_se(undecchar('0') == 0);
        assert_se(undecchar('9') == 9);
}

static void test_hexmem_one(const char *in, const char *expected) {
        _cleanup_free_ char *result = NULL;
        _cleanup_free_ void *mem = NULL;
        size_t len;

        assert_se(result = hexmem(in, strlen_ptr(in)));
        log_debug("hexmem(\"%s\") → \"%s\" (expected: \"%s\")", strnull(in), result, expected);
        ASSERT_STREQ(result, expected);

        assert_se(unhexmem(result, &mem, &len) >= 0);
        assert_se(memcmp_safe(mem, in, len) == 0);
}

TEST(hexmem) {
        test_hexmem_one(NULL, "");
        test_hexmem_one("", "");
        test_hexmem_one("foo", "666f6f");
}

static void test_unhexmem_one(const char *s, size_t l, int retval) {
        _cleanup_free_ char *hex = NULL;
        _cleanup_free_ void *mem = NULL;
        size_t len;

        assert_se(unhexmem_full(s, l, /* secure = */ false, &mem, &len) == retval);
        if (retval == 0) {
                char *answer;

                if (l == SIZE_MAX)
                        l = strlen(s);

                assert_se(hex = hexmem(mem, len));
                answer = strndupa_safe(strempty(s), l);
                ASSERT_STREQ(delete_chars(answer, WHITESPACE), hex);
        }
}

TEST(unhexmem) {
        const char *hex = "efa2149213";
        const char *hex_space = "  e f   a\n 2\r  14\n\r\t9\t2 \n1\r3 \r\r\t";
        const char *hex_invalid = "efa214921o";

        test_unhexmem_one(NULL, 0, 0);
        test_unhexmem_one("", 0, 0);
        test_unhexmem_one("", SIZE_MAX, 0);
        test_unhexmem_one("   \n \t\r   \t\t \n\n\n", SIZE_MAX, 0);
        test_unhexmem_one(hex_invalid, strlen(hex_invalid), -EINVAL);
        test_unhexmem_one(hex_invalid, (size_t) - 1, -EINVAL);
        test_unhexmem_one(hex, strlen(hex) - 1, -EPIPE);
        test_unhexmem_one(hex, strlen(hex), 0);
        test_unhexmem_one(hex, SIZE_MAX, 0);
        test_unhexmem_one(hex_space, strlen(hex_space), 0);
        test_unhexmem_one(hex_space, SIZE_MAX, 0);
}

/* https://tools.ietf.org/html/rfc4648#section-10 */
TEST(base32hexmem) {
        char *b32;

        b32 = base32hexmem("", STRLEN(""), true);
        assert_se(b32);
        ASSERT_STREQ(b32, "");
        free(b32);

        b32 = base32hexmem("f", STRLEN("f"), true);
        assert_se(b32);
        ASSERT_STREQ(b32, "CO======");
        free(b32);

        b32 = base32hexmem("fo", STRLEN("fo"), true);
        assert_se(b32);
        ASSERT_STREQ(b32, "CPNG====");
        free(b32);

        b32 = base32hexmem("foo", STRLEN("foo"), true);
        assert_se(b32);
        ASSERT_STREQ(b32, "CPNMU===");
        free(b32);

        b32 = base32hexmem("foob", STRLEN("foob"), true);
        assert_se(b32);
        ASSERT_STREQ(b32, "CPNMUOG=");
        free(b32);

        b32 = base32hexmem("fooba", STRLEN("fooba"), true);
        assert_se(b32);
        ASSERT_STREQ(b32, "CPNMUOJ1");
        free(b32);

        b32 = base32hexmem("foobar", STRLEN("foobar"), true);
        assert_se(b32);
        ASSERT_STREQ(b32, "CPNMUOJ1E8======");
        free(b32);

        b32 = base32hexmem("", STRLEN(""), false);
        assert_se(b32);
        ASSERT_STREQ(b32, "");
        free(b32);

        b32 = base32hexmem("f", STRLEN("f"), false);
        assert_se(b32);
        ASSERT_STREQ(b32, "CO");
        free(b32);

        b32 = base32hexmem("fo", STRLEN("fo"), false);
        assert_se(b32);
        ASSERT_STREQ(b32, "CPNG");
        free(b32);

        b32 = base32hexmem("foo", STRLEN("foo"), false);
        assert_se(b32);
        ASSERT_STREQ(b32, "CPNMU");
        free(b32);

        b32 = base32hexmem("foob", STRLEN("foob"), false);
        assert_se(b32);
        ASSERT_STREQ(b32, "CPNMUOG");
        free(b32);

        b32 = base32hexmem("fooba", STRLEN("fooba"), false);
        assert_se(b32);
        ASSERT_STREQ(b32, "CPNMUOJ1");
        free(b32);

        b32 = base32hexmem("foobar", STRLEN("foobar"), false);
        assert_se(b32);
        ASSERT_STREQ(b32, "CPNMUOJ1E8");
        free(b32);
}

static void test_unbase32hexmem_one(const char *hex, bool padding, int retval, const char *ans) {
        _cleanup_free_ void *mem = NULL;
        size_t len;

        assert_se(unbase32hexmem(hex, SIZE_MAX, padding, &mem, &len) == retval);
        if (retval == 0) {
                char *str;

                str = strndupa_safe(mem, len);
                ASSERT_STREQ(str, ans);
        }
}

TEST(unbase32hexmem) {
        test_unbase32hexmem_one("", true, 0, "");

        test_unbase32hexmem_one("CO======", true, 0, "f");
        test_unbase32hexmem_one("CPNG====", true, 0, "fo");
        test_unbase32hexmem_one("CPNMU===", true, 0, "foo");
        test_unbase32hexmem_one("CPNMUOG=", true, 0, "foob");
        test_unbase32hexmem_one("CPNMUOJ1", true, 0, "fooba");
        test_unbase32hexmem_one("CPNMUOJ1E8======", true, 0, "foobar");

        test_unbase32hexmem_one("A", true, -EINVAL, NULL);
        test_unbase32hexmem_one("A=======", true, -EINVAL, NULL);
        test_unbase32hexmem_one("AAA=====", true, -EINVAL, NULL);
        test_unbase32hexmem_one("AAAAAA==", true, -EINVAL, NULL);
        test_unbase32hexmem_one("AB======", true, -EINVAL, NULL);
        test_unbase32hexmem_one("AAAB====", true, -EINVAL, NULL);
        test_unbase32hexmem_one("AAAAB===", true, -EINVAL, NULL);
        test_unbase32hexmem_one("AAAAAAB=", true, -EINVAL, NULL);

        test_unbase32hexmem_one("XPNMUOJ1", true, -EINVAL, NULL);
        test_unbase32hexmem_one("CXNMUOJ1", true, -EINVAL, NULL);
        test_unbase32hexmem_one("CPXMUOJ1", true, -EINVAL, NULL);
        test_unbase32hexmem_one("CPNXUOJ1", true, -EINVAL, NULL);
        test_unbase32hexmem_one("CPNMXOJ1", true, -EINVAL, NULL);
        test_unbase32hexmem_one("CPNMUXJ1", true, -EINVAL, NULL);
        test_unbase32hexmem_one("CPNMUOX1", true, -EINVAL, NULL);
        test_unbase32hexmem_one("CPNMUOJX", true, -EINVAL, NULL);

        test_unbase32hexmem_one("", false, 0, "");
        test_unbase32hexmem_one("CO", false, 0, "f");
        test_unbase32hexmem_one("CPNG", false, 0, "fo");
        test_unbase32hexmem_one("CPNMU", false, 0, "foo");
        test_unbase32hexmem_one("CPNMUOG", false, 0, "foob");
        test_unbase32hexmem_one("CPNMUOJ1", false, 0, "fooba");
        test_unbase32hexmem_one("CPNMUOJ1E8", false, 0, "foobar");
        test_unbase32hexmem_one("CPNMUOG=", false, -EINVAL, NULL);
        test_unbase32hexmem_one("CPNMUOJ1E8======", false, -EINVAL, NULL);

        test_unbase32hexmem_one("A", false, -EINVAL, NULL);
        test_unbase32hexmem_one("AAA", false, -EINVAL, NULL);
        test_unbase32hexmem_one("AAAAAA", false, -EINVAL, NULL);
        test_unbase32hexmem_one("AB", false, -EINVAL, NULL);
        test_unbase32hexmem_one("AAAB", false, -EINVAL, NULL);
        test_unbase32hexmem_one("AAAAB", false, -EINVAL, NULL);
        test_unbase32hexmem_one("AAAAAAB", false, -EINVAL, NULL);
}

/* https://tools.ietf.org/html/rfc4648#section-10 */
TEST(base64mem) {
        char *b64;

        assert_se(base64mem("", STRLEN(""), &b64) == 0);
        ASSERT_STREQ(b64, "");
        free(b64);

        assert_se(base64mem("f", STRLEN("f"), &b64) == 4);
        ASSERT_STREQ(b64, "Zg==");
        free(b64);

        assert_se(base64mem("fo", STRLEN("fo"), &b64) == 4);
        ASSERT_STREQ(b64, "Zm8=");
        free(b64);

        assert_se(base64mem("foo", STRLEN("foo"), &b64) == 4);
        ASSERT_STREQ(b64, "Zm9v");
        free(b64);

        assert_se(base64mem("foob", STRLEN("foob"), &b64) == 8);
        ASSERT_STREQ(b64, "Zm9vYg==");
        free(b64);

        assert_se(base64mem("fooba", STRLEN("fooba"), &b64) == 8);
        ASSERT_STREQ(b64, "Zm9vYmE=");
        free(b64);

        assert_se(base64mem("foobar", STRLEN("foobar"), &b64) == 8);
        ASSERT_STREQ(b64, "Zm9vYmFy");
        free(b64);
}

TEST(base64mem_linebreak) {
        uint8_t data[4096];

        for (size_t i = 0; i < 20; i++) {
                _cleanup_free_ char *encoded = NULL;
                _cleanup_free_ void *decoded = NULL;
                size_t decoded_size;
                uint64_t n, m;
                ssize_t l;

                /* Try a bunch of differently sized blobs */
                n = random_u64_range(sizeof(data));
                random_bytes(data, n);

                /* Break at various different columns */
                m = 1 + random_u64_range(n + 5);

                l = base64mem_full(data, n, m, &encoded);
                assert_se(l >= 0);
                assert_se(encoded);
                assert_se((size_t) l == strlen(encoded));

                assert_se(unbase64mem(encoded, &decoded, &decoded_size) >= 0);
                assert_se(decoded_size == n);
                assert_se(memcmp(data, decoded, n) == 0);

                /* Also try in secure mode */
                decoded = mfree(decoded);
                decoded_size = 0;
                assert_se(unbase64mem_full(encoded, SIZE_MAX, /* secure= */ true, &decoded, &decoded_size) >= 0);
                assert_se(decoded_size == n);
                assert_se(memcmp(data, decoded, n) == 0);

                for (size_t j = 0; j < (size_t) l; j++)
                        assert_se((encoded[j] == '\n') == (j % (m + 1) == m));
        }
}

static void test_base64_append_one(char **buf, size_t *len, const char *in, const char *expected) {
        ssize_t new_len;

        new_len = base64_append(buf, *len, in, strlen_ptr(in), 8, 12);
        assert_se(new_len >= 0);
        log_debug("base64_append_one(\"%s\")\nresult:\n%s\nexpected:\n%s", in, strnull(*buf), strnull(expected));
        assert_se((size_t) new_len == strlen_ptr(*buf));
        ASSERT_STREQ(*buf, expected);
        *len = new_len;
}

TEST(base64_append) {
        _cleanup_free_ char *buf = NULL;
        size_t len = 0;

        test_base64_append_one(&buf, &len, "", NULL);
        test_base64_append_one(&buf, &len, "f",
                               "Zg==");
        test_base64_append_one(&buf, &len, "fo",
                               "Zg== Zm8=");
        test_base64_append_one(&buf, &len, "foo",
                               "Zg== Zm8=\n"
                               "        Zm9v");
        test_base64_append_one(&buf, &len, "foob",
                               "Zg== Zm8=\n"
                               "        Zm9v\n"
                               "        Zm9v\n"
                               "        Yg==");
        test_base64_append_one(&buf, &len, "fooba",
                               "Zg== Zm8=\n"
                               "        Zm9v\n"
                               "        Zm9v\n"
                               "        Yg==\n"
                               "        Zm9v\n"
                               "        YmE=");
        test_base64_append_one(&buf, &len, "foobar",
                               "Zg== Zm8=\n"
                               "        Zm9v\n"
                               "        Zm9v\n"
                               "        Yg==\n"
                               "        Zm9v\n"
                               "        YmE=\n"
                               "        Zm9v\n"
                               "        YmFy");

        assert_se(free_and_strdup(&buf, "hogehogehogehoge") >= 0);
        len = strlen(buf);

        test_base64_append_one(&buf, &len, "",
                               "hogehogehogehoge");
        test_base64_append_one(&buf, &len, "f",
                               "hogehogehogehoge\n"
                               "        Zg==");
        test_base64_append_one(&buf, &len, "fo",
                               "hogehogehogehoge\n"
                               "        Zg==\n"
                               "        Zm8=");
        test_base64_append_one(&buf, &len, "foo",
                               "hogehogehogehoge\n"
                               "        Zg==\n"
                               "        Zm8=\n"
                               "        Zm9v");
        test_base64_append_one(&buf, &len, "foob",
                               "hogehogehogehoge\n"
                               "        Zg==\n"
                               "        Zm8=\n"
                               "        Zm9v\n"
                               "        Zm9v\n"
                               "        Yg==");
        test_base64_append_one(&buf, &len, "fooba",
                               "hogehogehogehoge\n"
                               "        Zg==\n"
                               "        Zm8=\n"
                               "        Zm9v\n"
                               "        Zm9v\n"
                               "        Yg==\n"
                               "        Zm9v\n"
                               "        YmE=");
        test_base64_append_one(&buf, &len, "foobar",
                               "hogehogehogehoge\n"
                               "        Zg==\n"
                               "        Zm8=\n"
                               "        Zm9v\n"
                               "        Zm9v\n"
                               "        Yg==\n"
                               "        Zm9v\n"
                               "        YmE=\n"
                               "        Zm9v\n"
                               "        YmFy");

        assert_se(free_and_strdup(&buf, "hogehogehogehoge") >= 0);
        len = strlen(buf);

        test_base64_append_one(&buf, &len, "foobarfoobarfoobarfoobar",
                               "hogehogehogehoge\n"
                               "        Zm9v\n"
                               "        YmFy\n"
                               "        Zm9v\n"
                               "        YmFy\n"
                               "        Zm9v\n"
                               "        YmFy\n"
                               "        Zm9v\n"
                               "        YmFy");

        assert_se(free_and_strdup(&buf, "aaa") >= 0);
        len = strlen(buf);

        test_base64_append_one(&buf, &len, "foobarfoobarfoobarfoobar",
                               "aaa Zm9vYmFy\n"
                               "    Zm9vYmFy\n"
                               "    Zm9vYmFy\n"
                               "    Zm9vYmFy");
}

static void test_unbase64mem_one(const char *input, const char *output, int ret) {
        _cleanup_free_ void *buffer = NULL;
        size_t size = 0;

        assert_se(unbase64mem(input, &buffer, &size) == ret);
        if (ret >= 0) {
                assert_se(size == strlen(output));
                assert_se(memcmp(buffer, output, size) == 0);
                assert_se(((char*) buffer)[size] == 0);
        }

        /* also try in secure mode */
        buffer = mfree(buffer);
        size = 0;

        assert_se(unbase64mem_full(input, SIZE_MAX, /* secure=*/ true, &buffer, &size) == ret);
        if (ret >= 0) {
                assert_se(size == strlen(output));
                assert_se(memcmp(buffer, output, size) == 0);
                assert_se(((char*) buffer)[size] == 0);
        }
}

TEST(unbase64mem) {

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

TEST(hexdump) {
        uint8_t data[146];
        unsigned i;

        hexdump(stdout, NULL, 0);
        hexdump(stdout, "", 0);
        hexdump(stdout, "", SIZE_MAX);
        hexdump(stdout, "", 1);
        hexdump(stdout, "x", 1);
        hexdump(stdout, "x", SIZE_MAX);
        hexdump(stdout, "x", 2);
        hexdump(stdout, "foobar", 7);
        hexdump(stdout, "foobar", SIZE_MAX);
        hexdump(stdout, "f\nobar", 7);
        hexdump(stdout, "f\nobar", SIZE_MAX);
        hexdump(stdout, "xxxxxxxxxxxxxxxxxxxxyz", 23);

        for (i = 0; i < ELEMENTSOF(data); i++)
                data[i] = i*2;

        hexdump(stdout, data, sizeof(data));
}

TEST(base64withwithouturl) {
        static const uint8_t plaintext[] = {
                0xcc, 0xa1, 0x72, 0x22, 0xae, 0xda, 0x66, 0x7e, 0x04, 0xa6, 0xe0, 0x82,
                0x9a, 0x97, 0x05, 0xf6, 0x33, 0xe0, 0x0f, 0xc2, 0x45, 0x13, 0x58, 0x3f,
                0xc5, 0xf4, 0xf4, 0x31, 0xab, 0x3c, 0x5f, 0x83, 0x34, 0x5b, 0x27, 0x32,
                0x8a, 0x04, 0x6c, 0x43, 0x82, 0x07, 0xe3, 0x2c, 0xac, 0xb9, 0xfb, 0xac,
                0xd0, 0x03, 0x91, 0x42, 0xcb, 0xa4, 0xde, 0x87, 0x86, 0x85, 0x10, 0xbb,
                0xb7, 0x5b, 0x4b, 0xc8, 0xa0, 0xf4, 0x22, 0x1d, 0x15, 0x71, 0x87, 0x9d,
                0xbf, 0x9f, 0xa9, 0xf1, 0xee, 0xa2, 0xb6, 0xaa, 0xc8, 0xc3, 0x37, 0x9c,
                0xbb, 0xdf, 0x3e, 0xac, 0xdc, 0x94, 0x54, 0x38, 0x56, 0x07, 0x34, 0xb4,
                0x3c, 0xcc, 0x31, 0x13
        };

        _cleanup_free_ void *buffer = NULL;
        size_t size;

        /* This is regular base64 */
        assert_se(unbase64mem("zKFyIq7aZn4EpuCCmpcF9jPgD8JFE1g/xfT0Mas8X4M0WycyigRsQ4IH4yysufus0AORQsuk3oeGhRC7t1tLyKD0Ih0VcYedv5+p8e6itqrIwzecu98+rNyUVDhWBzS0PMwxEw==", &buffer, &size) >= 0);
        assert_se(memcmp_nn(plaintext, sizeof(plaintext), buffer, size) == 0);
        buffer = mfree(buffer);

        /* This is the same but in base64url */
        assert_se(unbase64mem("zKFyIq7aZn4EpuCCmpcF9jPgD8JFE1g_xfT0Mas8X4M0WycyigRsQ4IH4yysufus0AORQsuk3oeGhRC7t1tLyKD0Ih0VcYedv5-p8e6itqrIwzecu98-rNyUVDhWBzS0PMwxEw==", &buffer, &size) >= 0);
        assert_se(memcmp_nn(plaintext, sizeof(plaintext), buffer, size) == 0);

        /* Hint: use xxd -i to generate the static C array from some data, and basenc --base64 + basenc
         * --base64url to generate the correctly encoded base64 strings */
}

DEFINE_TEST_MAIN(LOG_INFO);
