/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "iovec-util.h"
#include "pkcs11-util.h"
#include "tests.h"

static int parse(const char *json, Pkcs11Luks2Token *ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        ASSERT_OK(sd_json_parse(json, SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL));

        return pkcs11_luks2_token_parse(v, ret);
}

TEST(pkcs11_luks2_token_parse_full) {
        _cleanup_(pkcs11_luks2_token_done) Pkcs11Luks2Token t = {};

        /* "AQID" is 01 02 03 */
        ASSERT_OK(parse("{\"type\":\"systemd-pkcs11\",\"keyslots\":[\"1\"],"
                        "\"pkcs11-uri\":\"pkcs11:token=foo\",\"pkcs11-key\":\"AQID\",\"pkcs11-padding\":\"oaep-sha256\"}",
                        &t));

        ASSERT_STREQ(t.uri, "pkcs11:token=foo");
        ASSERT_EQ(t.key.iov_len, 3U);
        ASSERT_EQ(((const uint8_t*) t.key.iov_base)[0], 1U);
        ASSERT_EQ(t.rsa_padding, PKCS11_RSA_PADDING_OAEP_SHA256);
}

TEST(pkcs11_luks2_token_parse_legacy) {
        _cleanup_(pkcs11_luks2_token_done) Pkcs11Luks2Token t = {};

        /* Old tokens do not have the "pkcs11-padding" field */
        ASSERT_OK(parse("{\"pkcs11-uri\":\"pkcs11:token=foo\",\"pkcs11-key\":\"AQID\"}", &t));
        ASSERT_EQ(t.rsa_padding, PKCS11_RSA_PADDING_PKCS1V15);
}

TEST(pkcs11_luks2_token_parse_invalid) {
        Pkcs11Luks2Token t = {};

        /* Missing mandatory fields */
        ASSERT_ERROR(parse("{\"pkcs11-key\":\"AQID\"}", &t), ENXIO);
        ASSERT_ERROR(parse("{\"pkcs11-uri\":\"pkcs11:token=foo\"}", &t), ENXIO);

        /* Invalid URI, unknown padding, wrong type, bad base64 */
        ASSERT_ERROR(parse("{\"pkcs11-uri\":\"http://foo\",\"pkcs11-key\":\"AQID\"}", &t), EINVAL);
        ASSERT_FAIL(parse("{\"pkcs11-uri\":\"pkcs11:token=foo\",\"pkcs11-key\":\"AQID\",\"pkcs11-padding\":\"rot13\"}", &t));
        ASSERT_FAIL(parse("{\"pkcs11-uri\":\"pkcs11:token=foo\",\"pkcs11-key\":\"AQID\",\"pkcs11-padding\":1}", &t));
        ASSERT_FAIL(parse("{\"pkcs11-uri\":\"pkcs11:token=foo\",\"pkcs11-key\":\"%%%\"}", &t));

        /* Nothing is returned on failure */
        ASSERT_NULL(t.uri);
        ASSERT_FALSE(iovec_is_set(&t.key));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
