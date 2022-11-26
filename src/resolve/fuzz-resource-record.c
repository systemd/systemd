/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fuzz.h"
#include "memory-util.h"
#include "resolved-dns-packet.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *out = NULL; /* out should be freed after f */
        size_t out_size;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL, *copy = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        if (outside_size_range(size, 0, DNS_PACKET_SIZE_MAX))
                return 0;

        if (dns_resource_record_new_from_raw(&rr, data, size) < 0)
                return 0;

        assert_se(copy = dns_resource_record_copy(rr));
        assert_se(dns_resource_record_equal(copy, rr) > 0);

        assert_se(f = open_memstream_unlocked(&out, &out_size));
        (void) fprintf(f, "%s", strna(dns_resource_record_to_string(rr)));

        if (dns_resource_record_to_json(rr, &v) < 0)
                return 0;

        (void) json_variant_dump(v, JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR|JSON_FORMAT_SOURCE, f, NULL);
        (void) dns_resource_record_to_wire_format(rr, false);
        (void) dns_resource_record_to_wire_format(rr, true);

        return 0;
}
