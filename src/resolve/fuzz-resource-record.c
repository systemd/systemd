/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "dns-packet.h"
#include "dns-rr.h"
#include "fuzz.h"
#include "memstream-util.h"
#include "string-util.h"
#include "tests.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL, *copy = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(memstream_done) MemStream m = {};
        FILE *f;

        if (outside_size_range(size, /* lower= */ 0, DNS_PACKET_SIZE_MAX))
                return 0;

        if (dns_resource_record_new_from_raw(&rr, data, size) < 0)
                return 0;

        fuzz_setup_logging();

        copy = ASSERT_NOT_NULL(dns_resource_record_copy(rr));
        ASSERT_OK_POSITIVE(dns_resource_record_equal(copy, rr));

        f = ASSERT_NOT_NULL(memstream_init(&m));
        (void) fprintf(f, "%s", strna(dns_resource_record_to_string(rr)));

        ASSERT_OK(dns_resource_record_to_json(rr, &v));
        ASSERT_OK(sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_SOURCE, f, /* prefix= */ NULL));
        ASSERT_OK(dns_resource_record_to_wire_format(rr, /* canonical= */ false));
        ASSERT_OK(dns_resource_record_to_wire_format(rr, /* canonical= */ true));

        return 0;
}
