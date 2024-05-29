/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "resolved-dns-rr.h"

#include "log.h"
#include "tests.h"

/* ================================================================
 * DNS_RESOURCE_RECORD_RDATA()
 * ================================================================ */

TEST(dns_resource_record_rdata) {
        DnsResourceRecord rr = (DnsResourceRecord) {
                .wire_format = (void *)"abcdefghi",
                .wire_format_size = 9,
                .wire_format_rdata_offset = 3
        };

        const void *ptr = DNS_RESOURCE_RECORD_RDATA(&rr);
        ASSERT_STREQ(ptr, "defghi");

        size_t size = DNS_RESOURCE_RECORD_RDATA_SIZE(&rr);
        ASSERT_EQ(size, 6u);

        rr.wire_format = NULL;

        ptr = DNS_RESOURCE_RECORD_RDATA(&rr);
        ASSERT_NULL(ptr);

        size = DNS_RESOURCE_RECORD_RDATA_SIZE(&rr);
        ASSERT_EQ(size, 0u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
