/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dhcp-rkap.h"
#include "tests.h"

TEST(hmac_md5) {
        uint8_t key[DHCP_RKAP_KEY_SIZE], data[50], digest[DHCP_RKAP_KEY_SIZE];

        if (!dhcp_rkap_supported())
                return (void) log_tests_skipped("HMAC-MD5 is not available");

        /* RFC 2202 section 2, test cases 1 and 3. */
        memset(key, 0x0b, sizeof(key));
        ASSERT_OK(dhcp_rkap_hmac_md5(key, "Hi There", strlen("Hi There"), digest));
        ASSERT_MEMEQ(digest, ((const uint8_t[]) { 0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
                                                   0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d }), sizeof(digest));

        memset(key, 0xaa, sizeof(key));
        memset(data, 0xdd, sizeof(data));
        ASSERT_OK(dhcp_rkap_hmac_md5(key, data, sizeof(data), digest));
        ASSERT_MEMEQ(digest, ((const uint8_t[]) { 0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88,
                                                   0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8, 0xb3, 0xf6 }), sizeof(digest));
}

typedef struct TestMessage {
        uint8_t header[8];
        DHCPRKAPAuth auth;
} _packed_ TestMessage;

static void sign(const DHCPRKAPKey *key, TestMessage *m, uint64_t replay) {
        assert(key);
        assert(m);

        m->auth = (DHCPRKAPAuth) {
                .protocol = DHCP_RKAP_PROTOCOL,
                .algorithm = DHCP_RKAP_ALGORITHM_HMAC_MD5,
                .rdm = DHCP_RKAP_RDM_MONOTONIC,
                .replay = htobe64(replay),
                .type = DHCP_RKAP_TYPE_HMAC_MD5,
        };
        ASSERT_OK(dhcp_rkap_hmac_md5(key->key, m, sizeof(*m), m->auth.value));
}

TEST(verify) {
        DHCPRKAPKey key = {}, verifier = {};
        TestMessage m = { .header = { 1, 2, 3, 4, 5, 6, 7, 8 } };

        ASSERT_ERROR(dhcp_rkap_verify(&verifier, &m, sizeof(m), &m.auth, sizeof(m.auth)), ENOKEY);

        if (!dhcp_rkap_supported())
                return (void) log_tests_skipped("HMAC-MD5 is not available");

        DHCPRKAPAuth auth = {
                .protocol = DHCP_RKAP_PROTOCOL,
                .algorithm = DHCP_RKAP_ALGORITHM_HMAC_MD5,
                .rdm = DHCP_RKAP_RDM_MONOTONIC,
                .replay = htobe64(10),
                .type = DHCP_RKAP_TYPE_KEY,
                .value = { 1, 2, 3 },
        };
        ASSERT_OK(dhcp_rkap_key_set_from_auth(&verifier, &auth, sizeof(auth)));
        ASSERT_TRUE(verifier.set);
        ASSERT_EQ(verifier.replay, 10u);
        key = verifier;

        sign(&key, &m, 11);
        ASSERT_OK(dhcp_rkap_verify(&verifier, &m, sizeof(m), &m.auth, sizeof(m.auth)));
        ASSERT_EQ(verifier.replay, 11u);

        /* Replayed. */
        ASSERT_ERROR(dhcp_rkap_verify(&verifier, &m, sizeof(m), &m.auth, sizeof(m.auth)), ESTALE);

        /* Modified. */
        sign(&key, &m, 12);
        m.header[0] ^= 0x01;
        ASSERT_ERROR(dhcp_rkap_verify(&verifier, &m, sizeof(m), &m.auth, sizeof(m.auth)), EPERM);
        ASSERT_EQ(verifier.replay, 11u);

        /* Malformed, other protocol, or not a digest. */
        ASSERT_ERROR(dhcp_rkap_verify(&verifier, &m, sizeof(m), &m.auth, sizeof(m.auth) - 1), EBADMSG);
        m.auth.protocol = 2;
        ASSERT_ERROR(dhcp_rkap_verify(&verifier, &m, sizeof(m), &m.auth, sizeof(m.auth)), EOPNOTSUPP);
        m.auth.protocol = DHCP_RKAP_PROTOCOL;
        m.auth.type = DHCP_RKAP_TYPE_KEY;
        ASSERT_ERROR(dhcp_rkap_verify(&verifier, &m, sizeof(m), &m.auth, sizeof(m.auth)), ENOKEY);

        dhcp_rkap_key_clear(&verifier);
        ASSERT_FALSE(verifier.set);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
