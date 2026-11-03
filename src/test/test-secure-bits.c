/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "securebits-util.h"
#include "strv.h"
#include "tests.h"

static const char * const string_bits[] = {
        "keep-caps",
        "keep-caps-locked",
        "no-setuid-fixup",
        "no-setuid-fixup-locked",
        "noroot",
        "noroot-locked",
        "no-cap-ambient-raise",
        "no-cap-ambient-raise-locked",
        "exec-restrict-file",
        "exec-restrict-file-locked",
        "exec-deny-interactive",
        "exec-deny-interactive-locked",
        NULL
};

TEST(secure_bits_basic) {
        _cleanup_free_ char *joined = NULL, *str = NULL, *joined_ssv = NULL;
        _cleanup_strv_free_ char **ssv = NULL;
        int r;

        /* Check if converting each bit from string and back to string yields
         * the same value */
        STRV_FOREACH(bit, string_bits) {
                _cleanup_free_ char *s = NULL;
                _cleanup_strv_free_ char **sv = NULL;

                r = ASSERT_OK_POSITIVE(secure_bits_from_string(*bit));
                ASSERT_TRUE(secure_bits_is_valid(r));

                ASSERT_OK(secure_bits_to_string_alloc(r, &s));
                printf("%s = 0x%x = %s\n", *bit, (unsigned)r, s);
                ASSERT_STREQ(*bit, s);

                ASSERT_OK(secure_bits_to_strv(r, &sv));
                ASSERT_EQ(strv_length(sv), (size_t) 1);
                ASSERT_STREQ(*bit, sv[0]);
        }

        /* Ditto, but with all bits at once */
        joined = ASSERT_NOT_NULL(strv_join((char**)string_bits, " "));
        r = ASSERT_OK_POSITIVE(secure_bits_from_string(joined));
        ASSERT_TRUE(secure_bits_is_valid(r));
        ASSERT_OK(secure_bits_to_string_alloc(r, &str));
        printf("%s = 0x%x = %s\n", joined, (unsigned)r, str);
        ASSERT_STREQ(joined, str);

        ASSERT_OK(secure_bits_to_strv(r, &ssv));
        joined_ssv = strv_join(ssv, " ");
        ASSERT_STREQ(joined, joined_ssv);

        str = mfree(str);
        ssv = strv_free(ssv);

        /* Empty string */
        ASSERT_OK_ZERO(secure_bits_from_string(""));
        ASSERT_OK_ZERO(secure_bits_from_string("     "));

        /* Only invalid entries */
        ASSERT_OK_ZERO(secure_bits_from_string("foo bar baz"));

        /* Empty secure bits */
        ASSERT_OK(secure_bits_to_string_alloc(0, &str));
        ASSERT_TRUE(isempty(str));
        ASSERT_OK(secure_bits_to_strv(0, &ssv));
        ASSERT_TRUE(strv_isempty(ssv));

        str = mfree(str);

        /* Bits to string with check */
        ASSERT_ERROR(secure_bits_to_string_alloc_with_check(INT_MAX, &str), EINVAL);
        ASSERT_NULL(str);
        ASSERT_OK(secure_bits_to_string_alloc_with_check(
                                (1 << SECURE_KEEP_CAPS) | (1 << SECURE_KEEP_CAPS_LOCKED),
                                &str));
        ASSERT_STREQ(str, "keep-caps keep-caps-locked");
}

TEST(secure_bits_mix) {
        static struct sbit_table {
                const char *input;
                const char *expected;
        } sbit_table[] = {
                { "keep-caps keep-caps keep-caps",  "keep-caps" },
                { "keep-caps noroot keep-caps",     "keep-caps noroot" },
                { "noroot foo bar baz noroot",      "noroot" },
                { "noroot \"foo\" \"bar keep-caps", "noroot" },
                { "\"noroot foo\" bar keep-caps",   "keep-caps" },
                {}
        };

        for (const struct sbit_table *s = sbit_table; s->input; s++) {
                _cleanup_free_ char *str = NULL;
                int r;

                r = ASSERT_OK_POSITIVE(secure_bits_from_string(s->input));
                ASSERT_TRUE(secure_bits_is_valid(r));
                ASSERT_OK(secure_bits_to_string_alloc(r, &str));
                printf("%s = 0x%x = %s\n", s->input, (unsigned)r, str);
                ASSERT_STREQ(s->expected, str);
        }
}

TEST(secure_bits_keep_locked) {
        int locked = (1 << SECURE_EXEC_RESTRICT_FILE) | (1 << SECURE_EXEC_RESTRICT_FILE_LOCKED);

        /* Nothing locked, the wanted bits win. */
        ASSERT_EQ(secure_bits_keep_locked(/* current= */ 0, 1 << SECURE_NOROOT), 1 << SECURE_NOROOT);
        ASSERT_EQ(secure_bits_keep_locked(1 << SECURE_NOROOT, /* bits= */ 0), 0);

        /* A locked pair stays as it is, everything else follows the wanted bits. */
        ASSERT_EQ(secure_bits_keep_locked(locked, /* bits= */ 0), locked);
        ASSERT_EQ(secure_bits_keep_locked(locked, 1 << SECURE_EXEC_DENY_INTERACTIVE),
                  locked | (1 << SECURE_EXEC_DENY_INTERACTIVE));
        ASSERT_EQ(secure_bits_keep_locked(locked | (1 << SECURE_KEEP_CAPS), 1 << SECURE_EXEC_RESTRICT_FILE), locked);

        /* A lock on a cleared bit keeps it cleared. */
        ASSERT_EQ(secure_bits_keep_locked(1 << SECURE_NOROOT_LOCKED, 1 << SECURE_NOROOT), 1 << SECURE_NOROOT_LOCKED);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
