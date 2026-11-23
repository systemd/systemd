/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "cryptsetup-fido2.h"
#include "iovec-util.h"
#include "libfido2-util.h"
#include "tests.h"

static int parse(const char *json, Fido2Luks2Token *ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        ASSERT_OK(sd_json_parse(json, SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL));

        return fido2_luks2_token_parse(v, ret);
}

TEST(fido2_luks2_token_parse_full) {
        _cleanup_(fido2_luks2_token_done) Fido2Luks2Token t = {};

        /* "AQID" is 01 02 03, "BAU=" is 04 05 */
        ASSERT_OK(parse("{\"type\":\"systemd-fido2\",\"keyslots\":[\"1\"],"
                        "\"fido2-credential\":\"AQID\",\"fido2-salt\":\"BAU=\",\"fido2-rp\":\"io.systemd.cryptsetup\","
                        "\"fido2-clientPin-required\":true,\"fido2-up-required\":false,\"fido2-uv-required\":true}",
                        &t));

        ASSERT_EQ(t.cid.iov_len, 3U);
        ASSERT_EQ(((const uint8_t*) t.cid.iov_base)[2], 3U);
        ASSERT_EQ(t.salt.iov_len, 2U);
        ASSERT_EQ(((const uint8_t*) t.salt.iov_base)[1], 5U);
        ASSERT_STREQ(t.rp_id, "io.systemd.cryptsetup");
        ASSERT_EQ(t.required, (Fido2EnrollFlags) (FIDO2ENROLL_PIN|FIDO2ENROLL_UV));
}

TEST(fido2_luks2_token_parse_v248) {
        _cleanup_(fido2_luks2_token_done) Fido2Luks2Token t = {};

        /* Tokens enrolled by v248 have neither "fido2-rp" nor the "fido2-*-required" fields */
        ASSERT_OK(parse("{\"type\":\"systemd-fido2\",\"keyslots\":[\"1\"],"
                        "\"fido2-credential\":\"AQID\",\"fido2-salt\":\"BAU=\"}",
                        &t));

        ASSERT_NULL(t.rp_id);
        ASSERT_EQ(t.required, (Fido2EnrollFlags) (FIDO2ENROLL_PIN_IF_NEEDED|FIDO2ENROLL_UP_IF_NEEDED|FIDO2ENROLL_UV_OMIT));
}

TEST(fido2_luks2_token_parse_invalid) {
        Fido2Luks2Token t = {};

        /* Missing mandatory fields */
        ASSERT_ERROR(parse("{\"fido2-salt\":\"BAU=\"}", &t), ENXIO);
        ASSERT_ERROR(parse("{\"fido2-credential\":\"AQID\"}", &t), ENXIO);

        /* Wrong types and bad base64 */
        ASSERT_FAIL(parse("{\"fido2-credential\":\"AQID\",\"fido2-salt\":\"BAU=\",\"fido2-rp\":42}", &t));
        ASSERT_FAIL(parse("{\"fido2-credential\":\"AQID\",\"fido2-salt\":\"BAU=\",\"fido2-up-required\":\"yes\"}", &t));
        ASSERT_FAIL(parse("{\"fido2-credential\":\"%%%\",\"fido2-salt\":\"BAU=\"}", &t));

        /* Nothing is returned on failure */
        ASSERT_FALSE(iovec_is_set(&t.cid));
        ASSERT_NULL(t.rp_id);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
