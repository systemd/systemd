/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"

#include "alloc-util.h"
#include "dns-packet.h"
#include "dns-rr.h"
#include "fileio.h"
#include "glob-util.h"
#include "log.h"
#include "siphash24.h"
#include "strv.h"
#include "tests.h"
#include "unaligned.h"

#define HASH_KEY SD_ID128_MAKE(d3,1e,48,90,4b,fa,4c,fe,af,9d,d5,a1,d7,2e,8a,b1)

static void verify_rr_copy(DnsResourceRecord *rr) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *copy = NULL;
        const char *a, *b;

        assert_se(copy = dns_resource_record_copy(rr));
        assert_se(dns_resource_record_equal(copy, rr) > 0);

        assert_se(a = dns_resource_record_to_string(rr));
        assert_se(b = dns_resource_record_to_string(copy));

        assert_se(streq(a, b));
}

static uint64_t hash(DnsResourceRecord *rr) {
        struct siphash state;

        siphash24_init(&state, HASH_KEY.bytes);
        dns_resource_record_hash_func(rr, &state);
        return siphash24_finalize(&state);
}

static void test_packet_from_file(const char* filename, bool canonical) {
        _cleanup_free_ char *data = NULL;
        size_t data_size, packet_size, offset;

        assert_se(read_full_file(filename, &data, &data_size) >= 0);
        assert_se(data);
        assert_se(data_size > 8);

        log_info("============== %s %s==============", filename, canonical ? "canonical " : "");

        for (offset = 0; offset < data_size; offset += 8 + packet_size) {
                _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL, *p2 = NULL;
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL, *rr2 = NULL;
                const char *s, *s2;
                uint64_t hash1, hash2;

                packet_size = unaligned_read_le64(data + offset);
                assert_se(packet_size > 0);
                assert_se(offset + 8 + packet_size <= data_size);

                assert_se(dns_packet_new(&p, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX) >= 0);

                assert_se(dns_packet_append_blob(p, data + offset + 8, packet_size, NULL) >= 0);
                assert_se(dns_packet_read_rr(p, &rr, NULL, NULL) >= 0);

                verify_rr_copy(rr);

                s = dns_resource_record_to_string(rr);
                assert_se(s);
                puts(s);

                hash1 = hash(rr);

                assert_se(dns_resource_record_to_wire_format(rr, canonical) >= 0);

                assert_se(dns_packet_new(&p2, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX) >= 0);
                assert_se(dns_packet_append_blob(p2, rr->wire_format, rr->wire_format_size, NULL) >= 0);
                assert_se(dns_packet_read_rr(p2, &rr2, NULL, NULL) >= 0);

                verify_rr_copy(rr);

                s2 = dns_resource_record_to_string(rr);
                assert_se(s2);
                assert_se(streq(s, s2));

                hash2 = hash(rr);
                assert_se(hash1 == hash2);
        }
}

static void test_dns_resource_record_get_cname_target(void) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *cname = NULL, *dname = NULL;
        _cleanup_free_ char *target = NULL;

        assert_se(cname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "quux.foobar"));
        assert_se(cname->cname.name = strdup("wuff.wuff"));

        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, "waldo"), cname, &target) == -EUNATCH);
        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, "foobar"), cname, &target) == -EUNATCH);
        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, "quux"), cname, &target) == -EUNATCH);
        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, ""), cname, &target) == -EUNATCH);
        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, "."), cname, &target) == -EUNATCH);
        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, "nope.quux.foobar"), cname, &target) == -EUNATCH);
        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, "quux.foobar"), cname, &target) == 0);
        assert_se(streq(target, "wuff.wuff"));
        target = mfree(target);

        assert_se(dname = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "quux.foobar"));
        assert_se(dname->dname.name = strdup("wuff.wuff"));

        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, "waldo"), dname, &target) == -EUNATCH);
        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, "foobar"), dname, &target) == -EUNATCH);
        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, "quux"), dname, &target) == -EUNATCH);
        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, ""), dname, &target) == -EUNATCH);
        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, "."), dname, &target) == -EUNATCH);
        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, "yupp.quux.foobar"), dname, &target) == 0);
        assert_se(streq(target, "yupp.wuff.wuff"));
        target = mfree(target);

        assert_se(dns_resource_record_get_cname_target(&DNS_RESOURCE_KEY_CONST(DNS_CLASS_IN, DNS_TYPE_A, "quux.foobar"), cname, &target) == 0);
        assert_se(streq(target, "wuff.wuff"));
}

int main(int argc, char **argv) {
        _cleanup_strv_free_ char **v = NULL;
        char **fnames;

        test_setup_logging(LOG_DEBUG);

        if (argc >= 2)
                fnames = argv + 1;
        else {
                _cleanup_free_ char *pkts_glob = NULL;
                ASSERT_OK(get_testdata_dir("test-resolve/*.pkts", &pkts_glob));
                ASSERT_OK(safe_glob(pkts_glob, GLOB_NOSORT, &v));
                fnames = v;
        }

        STRV_FOREACH(p, fnames) {
                if (p != fnames)
                        puts("");
                test_packet_from_file(*p, false);
                puts("");
                test_packet_from_file(*p, true);
        }

        test_dns_resource_record_get_cname_target();

        return EXIT_SUCCESS;
}
