/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fuzz.h"
#include "memory-util.h"
#include "memstream-util.h"
#include "resolved-dns-packet.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL, *copy = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(memstream_done) MemStream m = {};
        FILE *f;

        if (outside_size_range(size, 0, DNS_PACKET_SIZE_MAX))
                return 0;

        if (dns_resource_record_new_from_raw(&rr, data, size) < 0)
                return 0;

        fuzz_setup_logging();

        assert_se(copy = dns_resource_record_copy(rr));
        assert_se(dns_resource_record_equal(copy, rr) > 0);

        assert_se(f = memstream_init(&m));
        (void) fprintf(f, "%s", strna(dns_resource_record_to_string(rr)));

        assert_se(dns_resource_record_to_json(rr, &v) >= 0);
        assert_se(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_SOURCE, f, NULL) >= 0);
        assert_se(dns_resource_record_to_wire_format(rr, false) >= 0);
        assert_se(dns_resource_record_to_wire_format(rr, true) >= 0);

        return 0;
}
