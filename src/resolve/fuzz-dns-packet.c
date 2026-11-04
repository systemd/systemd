/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-packet.h"
#include "fuzz.h"
#include "tests.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        if (outside_size_range(size, /* lower= */ 0, DNS_PACKET_SIZE_MAX))
                return 0;

        fuzz_setup_logging();

        ASSERT_OK(dns_packet_new(&p, DNS_PROTOCOL_DNS, /* min_alloc_dsize= */ 0, DNS_PACKET_SIZE_MAX));
        p->size = 0; /* by default append starts after the header, undo that */
        ASSERT_OK(dns_packet_append_blob(p, data, size, /* start= */ NULL));
        if (size < DNS_PACKET_HEADER_SIZE) {
                /* make sure we pad the packet back up to the minimum header size */
                ASSERT_GE(p->allocated, (size_t) DNS_PACKET_HEADER_SIZE);
                memzero(DNS_PACKET_DATA(p) + size, DNS_PACKET_HEADER_SIZE - size);
                p->size = DNS_PACKET_HEADER_SIZE;
        }
        (void) dns_packet_extract(p);

        return 0;
}
