/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dhcp-duid-internal.h"
#include "ether-addr-util.h"
#include "tests.h"

TEST(dhcp_identifier_set_iaid) {
        uint32_t iaid_legacy;
        be32_t iaid;

        static struct hw_addr_data hw_addr = {
                .length = ETH_ALEN,
                .ether = {{ 'A', 'B', 'C', '1', '2', '3' }},
        };

        ASSERT_OK(dhcp_identifier_set_iaid(/* dev= */ NULL, &hw_addr, /* legacy_unstable_byteorder= */ true, &iaid_legacy));
        ASSERT_OK(dhcp_identifier_set_iaid(/* dev= */ NULL, &hw_addr, /* legacy_unstable_byteorder= */ false, &iaid));

        /* we expect, that the MAC address was hashed. The legacy value is in native endianness. */
        ASSERT_EQ(iaid_legacy, 0x8dde4ba8u);
        ASSERT_EQ(iaid, htole32(0x8dde4ba8u));
#if __BYTE_ORDER == __LITTLE_ENDIAN
        ASSERT_EQ(iaid, iaid_legacy);
#else
        ASSERT_EQ(iaid, bswap_32(iaid_legacy));
#endif
}

DEFINE_TEST_MAIN(LOG_DEBUG);
