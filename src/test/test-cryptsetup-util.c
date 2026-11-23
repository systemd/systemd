/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "tests.h"

static sd_json_variant* parse(const char *json) {
        sd_json_variant *v = NULL;

        ASSERT_OK(sd_json_parse(json, SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        return v;
}

TEST(cryptsetup_token_parse_common) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ int *keyslots = NULL;
        size_t n_keyslots;
        const char *type;

        v = parse("{\"type\":\"systemd-tpm2\",\"keyslots\":[\"1\",\"7\"],\"tpm2-pin\":true}");
        ASSERT_OK(cryptsetup_token_parse_common(v, &type, &keyslots, &n_keyslots));
        ASSERT_STREQ(type, "systemd-tpm2");
        ASSERT_EQ(n_keyslots, 2U);
        ASSERT_EQ(keyslots[0], 1);
        ASSERT_EQ(keyslots[1], 7);

        /* An empty array is fine */
        v = sd_json_variant_unref(v);
        keyslots = mfree(keyslots);
        v = parse("{\"type\":\"foo\",\"keyslots\":[]}");
        ASSERT_OK(cryptsetup_token_parse_common(v, &type, &keyslots, &n_keyslots));
        ASSERT_EQ(n_keyslots, 0U);
}

TEST(cryptsetup_token_parse_common_invalid) {
        static const char *const invalid[] = {
                "{\"keyslots\":[\"1\"]}",                  /* no type */
                "{\"type\":\"foo\"}",                      /* no keyslots */
                "{\"type\":1,\"keyslots\":[\"1\"]}",       /* type not a string */
                "{\"type\":\"foo\",\"keyslots\":\"1\"}",   /* keyslots not an array */
                "{\"type\":\"foo\",\"keyslots\":[1]}",     /* element not a string */
                "{\"type\":\"foo\",\"keyslots\":[\"x\"]}", /* element not a number */
                "{\"type\":\"foo\",\"keyslots\":[\"-1\"]}",/* negative */
        };

        FOREACH_ELEMENT(j, invalid) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = parse(*j);

                ASSERT_FAIL(cryptsetup_token_parse_common(v, /* ret_type= */ NULL, /* ret_keyslots= */ NULL, /* ret_n_keyslots= */ NULL));
        }
}

TEST(cryptsetup_get_keyslot_from_token) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        v = parse("{\"type\":\"systemd-fido2\",\"keyslots\":[\"3\"]}");
        ASSERT_EQ(cryptsetup_get_keyslot_from_token(v), 3);

        /* The callers rely on these error codes */
        v = sd_json_variant_unref(v);
        v = parse("{\"type\":\"systemd-fido2\"}");
        ASSERT_ERROR(cryptsetup_get_keyslot_from_token(v), ENOENT);

        v = sd_json_variant_unref(v);
        v = parse("{\"type\":\"systemd-fido2\",\"keyslots\":[\"3\",\"4\"]}");
        ASSERT_ERROR(cryptsetup_get_keyslot_from_token(v), EMEDIUMTYPE);

        v = sd_json_variant_unref(v);
        v = parse("{\"type\":\"systemd-fido2\",\"keyslots\":[3]}");
        ASSERT_ERROR(cryptsetup_get_keyslot_from_token(v), EMEDIUMTYPE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
