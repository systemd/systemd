/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "memory-util.h"
#include "resolved-dns-packet.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        if (outside_size_range(size, 0, DNS_PACKET_SIZE_MAX))
                return 0;

        assert_se(dns_packet_new(&p, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX) >= 0);
        p->size = 0; /* by default append starts after the header, undo that */
        assert_se(dns_packet_append_blob(p, data, size, NULL) >= 0);
        if (size < DNS_PACKET_HEADER_SIZE) {
                /* make sure we pad the packet back up to the minimum header size */
                assert_se(p->allocated >= DNS_PACKET_HEADER_SIZE);
                memzero(DNS_PACKET_DATA(p) + size, DNS_PACKET_HEADER_SIZE - size);
                p->size = DNS_PACKET_HEADER_SIZE;
        }
        (void) dns_packet_extract(p);

        return 0;
}
