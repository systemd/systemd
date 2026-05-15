/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dhcp-client-id-internal.h"
#include "hashmap.h"
#include "siphash24.h"
#include "tests.h"

static uint64_t client_id_hash_helper(sd_dhcp_client_id *id, uint8_t key[HASH_KEY_SIZE]) {
        struct siphash state;

        siphash24_init(&state, key);
        client_id_hash_func(id, &state);

        return htole64(siphash24_finalize(&state));
}

TEST(client_id_hash) {
        sd_dhcp_client_id a = {
                .size = 4,
        }, b = {
                .size = 4,
        };
        uint8_t hash_key[HASH_KEY_SIZE] = {
                '0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        };

        log_debug("/* %s */", __func__);

        memcpy(a.raw, "abcd", 4);
        memcpy(b.raw, "abcd", 4);

        ASSERT_EQ(client_id_compare_func(&a, &b), 0);
        ASSERT_EQ(client_id_hash_helper(&a, hash_key), client_id_hash_helper(&b, hash_key));
        a.size = 3;
        ASSERT_NE(client_id_compare_func(&a, &b), 0);
        a.size = 4;
        ASSERT_EQ(client_id_compare_func(&a, &b), 0);
        ASSERT_EQ(client_id_hash_helper(&a, hash_key), client_id_hash_helper(&b, hash_key));

        b.size = 3;
        ASSERT_NE(client_id_compare_func(&a, &b), 0);
        b.size = 4;
        ASSERT_EQ(client_id_compare_func(&a, &b), 0);
        ASSERT_EQ(client_id_hash_helper(&a, hash_key), client_id_hash_helper(&b, hash_key));

        memcpy(b.raw, "abce", 4);
        ASSERT_NE(client_id_compare_func(&a, &b), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
