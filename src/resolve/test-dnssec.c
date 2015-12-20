/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "alloc-util.h"
#include "resolved-dns-dnssec.h"
#include "resolved-dns-rr.h"
#include "string-util.h"
#include "hexdecoct.h"

static void test_dnssec_verify_rrset2(void) {

        static const uint8_t signature_blob[] = {
                0x48, 0x45, 0xc8, 0x8b, 0xc0, 0x14, 0x92, 0xf5, 0x15, 0xc6, 0x84, 0x9d, 0x2f, 0xe3, 0x32, 0x11,
                0x7d, 0xf1, 0xe6, 0x87, 0xb9, 0x42, 0xd3, 0x8b, 0x9e, 0xaf, 0x92, 0x31, 0x0a, 0x53, 0xad, 0x8b,
                0xa7, 0x5c, 0x83, 0x39, 0x8c, 0x28, 0xac, 0xce, 0x6e, 0x9c, 0x18, 0xe3, 0x31, 0x16, 0x6e, 0xca,
                0x38, 0x31, 0xaf, 0xd9, 0x94, 0xf1, 0x84, 0xb1, 0xdf, 0x5a, 0xc2, 0x73, 0x22, 0xf6, 0xcb, 0xa2,
                0xe7, 0x8c, 0x77, 0x0c, 0x74, 0x2f, 0xc2, 0x13, 0xb0, 0x93, 0x51, 0xa9, 0x4f, 0xae, 0x0a, 0xda,
                0x45, 0xcc, 0xfd, 0x43, 0x99, 0x36, 0x9a, 0x0d, 0x21, 0xe0, 0xeb, 0x30, 0x65, 0xd4, 0xa0, 0x27,
                0x37, 0x3b, 0xe4, 0xc1, 0xc5, 0xa1, 0x2a, 0xd1, 0x76, 0xc4, 0x7e, 0x64, 0x0e, 0x5a, 0xa6, 0x50,
                0x24, 0xd5, 0x2c, 0xcc, 0x6d, 0xe5, 0x37, 0xea, 0xbd, 0x09, 0x34, 0xed, 0x24, 0x06, 0xa1, 0x22,
        };

        static const uint8_t dnskey_blob[] = {
                0x03, 0x01, 0x00, 0x01, 0xc3, 0x7f, 0x1d, 0xd1, 0x1c, 0x97, 0xb1, 0x13, 0x34, 0x3a, 0x9a, 0xea,
                0xee, 0xd9, 0x5a, 0x11, 0x1b, 0x17, 0xc7, 0xe3, 0xd4, 0xda, 0x20, 0xbc, 0x5d, 0xba, 0x74, 0xe3,
                0x37, 0x99, 0xec, 0x25, 0xce, 0x93, 0x7f, 0xbd, 0x22, 0x73, 0x7e, 0x14, 0x71, 0xe0, 0x60, 0x07,
                0xd4, 0x39, 0x8b, 0x5e, 0xe9, 0xba, 0x25, 0xe8, 0x49, 0xe9, 0x34, 0xef, 0xfe, 0x04, 0x5c, 0xa5,
                0x27, 0xcd, 0xa9, 0xda, 0x70, 0x05, 0x21, 0xab, 0x15, 0x82, 0x24, 0xc3, 0x94, 0xf5, 0xd7, 0xb7,
                0xc4, 0x66, 0xcb, 0x32, 0x6e, 0x60, 0x2b, 0x55, 0x59, 0x28, 0x89, 0x8a, 0x72, 0xde, 0x88, 0x56,
                0x27, 0x95, 0xd9, 0xac, 0x88, 0x4f, 0x65, 0x2b, 0x68, 0xfc, 0xe6, 0x41, 0xc1, 0x1b, 0xef, 0x4e,
                0xd6, 0xc2, 0x0f, 0x64, 0x88, 0x95, 0x5e, 0xdd, 0x3a, 0x02, 0x07, 0x50, 0xa9, 0xda, 0xa4, 0x49,
                0x74, 0x62, 0xfe, 0xd7,
        };

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *nsec = NULL, *rrsig = NULL, *dnskey = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_free_ char *x = NULL, *y = NULL, *z = NULL;
        DnssecResult result;

        nsec = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NSEC, "nasa.gov");
        assert_se(nsec);

        nsec->nsec.next_domain_name = strdup("3D-Printing.nasa.gov");
        assert_se(nsec->nsec.next_domain_name);

        nsec->nsec.types = bitmap_new();
        assert_se(nsec->nsec.types);
        assert_se(bitmap_set(nsec->nsec.types, DNS_TYPE_A) >= 0);
        assert_se(bitmap_set(nsec->nsec.types, DNS_TYPE_NS) >= 0);
        assert_se(bitmap_set(nsec->nsec.types, DNS_TYPE_SOA) >= 0);
        assert_se(bitmap_set(nsec->nsec.types, DNS_TYPE_MX) >= 0);
        assert_se(bitmap_set(nsec->nsec.types, DNS_TYPE_TXT) >= 0);
        assert_se(bitmap_set(nsec->nsec.types, DNS_TYPE_RRSIG) >= 0);
        assert_se(bitmap_set(nsec->nsec.types, DNS_TYPE_NSEC) >= 0);
        assert_se(bitmap_set(nsec->nsec.types, DNS_TYPE_DNSKEY) >= 0);
        assert_se(bitmap_set(nsec->nsec.types, 65534) >= 0);

        assert_se(dns_resource_record_to_string(nsec, &x) >= 0);
        log_info("NSEC: %s", x);

        rrsig = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "NaSa.GOV.");
        assert_se(rrsig);

        rrsig->rrsig.type_covered = DNS_TYPE_NSEC;
        rrsig->rrsig.algorithm = DNSSEC_ALGORITHM_RSASHA256;
        rrsig->rrsig.labels = 2;
        rrsig->rrsig.original_ttl = 300;
        rrsig->rrsig.expiration = 0x5689002f;
        rrsig->rrsig.inception = 0x56617230;
        rrsig->rrsig.key_tag = 30390;
        rrsig->rrsig.signer = strdup("Nasa.Gov.");
        assert_se(rrsig->rrsig.signer);
        rrsig->rrsig.signature_size = sizeof(signature_blob);
        rrsig->rrsig.signature = memdup(signature_blob, rrsig->rrsig.signature_size);
        assert_se(rrsig->rrsig.signature);

        assert_se(dns_resource_record_to_string(rrsig, &y) >= 0);
        log_info("RRSIG: %s", y);

        dnskey = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNSKEY, "nASA.gOV");
        assert_se(dnskey);

        dnskey->dnskey.flags = 256;
        dnskey->dnskey.protocol = 3;
        dnskey->dnskey.algorithm = DNSSEC_ALGORITHM_RSASHA256;
        dnskey->dnskey.key_size = sizeof(dnskey_blob);
        dnskey->dnskey.key = memdup(dnskey_blob, sizeof(dnskey_blob));
        assert_se(dnskey->dnskey.key);

        assert_se(dns_resource_record_to_string(dnskey, &z) >= 0);
        log_info("DNSKEY: %s", z);
        log_info("DNSKEY keytag: %u", dnssec_keytag(dnskey));

        assert_se(dnssec_key_match_rrsig(nsec->key, rrsig) > 0);
        assert_se(dnssec_rrsig_match_dnskey(rrsig, dnskey) > 0);

        answer = dns_answer_new(1);
        assert_se(answer);
        assert_se(dns_answer_add(answer, nsec, 0, DNS_ANSWER_AUTHENTICATED) >= 0);

        /* Validate the RR as it if was 2015-12-11 today */
        assert_se(dnssec_verify_rrset(answer, nsec->key, rrsig, dnskey, 1449849318*USEC_PER_SEC, &result) >= 0);
        assert_se(result == DNSSEC_VALIDATED);
}

static void test_dnssec_verify_rrset(void) {

        static const uint8_t signature_blob[] = {
                0x7f, 0x79, 0xdd, 0x5e, 0x89, 0x79, 0x18, 0xd0, 0x34, 0x86, 0x8c, 0x72, 0x77, 0x75, 0x48, 0x4d,
                0xc3, 0x7d, 0x38, 0x04, 0xab, 0xcd, 0x9e, 0x4c, 0x82, 0xb0, 0x92, 0xca, 0xe9, 0x66, 0xe9, 0x6e,
                0x47, 0xc7, 0x68, 0x8c, 0x94, 0xf6, 0x69, 0xcb, 0x75, 0x94, 0xe6, 0x30, 0xa6, 0xfb, 0x68, 0x64,
                0x96, 0x1a, 0x84, 0xe1, 0xdc, 0x16, 0x4c, 0x83, 0x6c, 0x44, 0xf2, 0x74, 0x4d, 0x74, 0x79, 0x8f,
                0xf3, 0xf4, 0x63, 0x0d, 0xef, 0x5a, 0xe7, 0xe2, 0xfd, 0xf2, 0x2b, 0x38, 0x7c, 0x28, 0x96, 0x9d,
                0xb6, 0xcd, 0x5c, 0x3b, 0x57, 0xe2, 0x24, 0x78, 0x65, 0xd0, 0x9e, 0x77, 0x83, 0x09, 0x6c, 0xff,
                0x3d, 0x52, 0x3f, 0x6e, 0xd1, 0xed, 0x2e, 0xf9, 0xee, 0x8e, 0xa6, 0xbe, 0x9a, 0xa8, 0x87, 0x76,
                0xd8, 0x77, 0xcc, 0x96, 0xa0, 0x98, 0xa1, 0xd1, 0x68, 0x09, 0x43, 0xcf, 0x56, 0xd9, 0xd1, 0x66,
        };

        static const uint8_t dnskey_blob[] = {
                0x03, 0x01, 0x00, 0x01, 0x9b, 0x49, 0x9b, 0xc1, 0xf9, 0x9a, 0xe0, 0x4e, 0xcf, 0xcb, 0x14, 0x45,
                0x2e, 0xc9, 0xf9, 0x74, 0xa7, 0x18, 0xb5, 0xf3, 0xde, 0x39, 0x49, 0xdf, 0x63, 0x33, 0x97, 0x52,
                0xe0, 0x8e, 0xac, 0x50, 0x30, 0x8e, 0x09, 0xd5, 0x24, 0x3d, 0x26, 0xa4, 0x49, 0x37, 0x2b, 0xb0,
                0x6b, 0x1b, 0xdf, 0xde, 0x85, 0x83, 0xcb, 0x22, 0x4e, 0x60, 0x0a, 0x91, 0x1a, 0x1f, 0xc5, 0x40,
                0xb1, 0xc3, 0x15, 0xc1, 0x54, 0x77, 0x86, 0x65, 0x53, 0xec, 0x10, 0x90, 0x0c, 0x91, 0x00, 0x5e,
                0x15, 0xdc, 0x08, 0x02, 0x4c, 0x8c, 0x0d, 0xc0, 0xac, 0x6e, 0xc4, 0x3e, 0x1b, 0x80, 0x19, 0xe4,
                0xf7, 0x5f, 0x77, 0x51, 0x06, 0x87, 0x61, 0xde, 0xa2, 0x18, 0x0f, 0x40, 0x8b, 0x79, 0x72, 0xfa,
                0x8d, 0x1a, 0x44, 0x47, 0x0d, 0x8e, 0x3a, 0x2d, 0xc7, 0x39, 0xbf, 0x56, 0x28, 0x97, 0xd9, 0x20,
                0x4f, 0x00, 0x51, 0x3b,
        };

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *a = NULL, *rrsig = NULL, *dnskey = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_free_ char *x = NULL, *y = NULL, *z = NULL;
        DnssecResult result;

        a = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "nAsA.gov");
        assert_se(a);

        a->a.in_addr.s_addr = inet_addr("52.0.14.116");

        assert_se(dns_resource_record_to_string(a, &x) >= 0);
        log_info("A: %s", x);

        rrsig = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "NaSa.GOV.");
        assert_se(rrsig);

        rrsig->rrsig.type_covered = DNS_TYPE_A;
        rrsig->rrsig.algorithm = DNSSEC_ALGORITHM_RSASHA256;
        rrsig->rrsig.labels = 2;
        rrsig->rrsig.original_ttl = 600;
        rrsig->rrsig.expiration = 0x5683135c;
        rrsig->rrsig.inception = 0x565b7da8;
        rrsig->rrsig.key_tag = 63876;
        rrsig->rrsig.signer = strdup("Nasa.Gov.");
        assert_se(rrsig->rrsig.signer);
        rrsig->rrsig.signature_size = sizeof(signature_blob);
        rrsig->rrsig.signature = memdup(signature_blob, rrsig->rrsig.signature_size);
        assert_se(rrsig->rrsig.signature);

        assert_se(dns_resource_record_to_string(rrsig, &y) >= 0);
        log_info("RRSIG: %s", y);

        dnskey = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNSKEY, "nASA.gOV");
        assert_se(dnskey);

        dnskey->dnskey.flags = 256;
        dnskey->dnskey.protocol = 3;
        dnskey->dnskey.algorithm = DNSSEC_ALGORITHM_RSASHA256;
        dnskey->dnskey.key_size = sizeof(dnskey_blob);
        dnskey->dnskey.key = memdup(dnskey_blob, sizeof(dnskey_blob));
        assert_se(dnskey->dnskey.key);

        assert_se(dns_resource_record_to_string(dnskey, &z) >= 0);
        log_info("DNSKEY: %s", z);
        log_info("DNSKEY keytag: %u", dnssec_keytag(dnskey));

        assert_se(dnssec_key_match_rrsig(a->key, rrsig) > 0);
        assert_se(dnssec_rrsig_match_dnskey(rrsig, dnskey) > 0);

        answer = dns_answer_new(1);
        assert_se(answer);
        assert_se(dns_answer_add(answer, a, 0, DNS_ANSWER_AUTHENTICATED) >= 0);

        /* Validate the RR as it if was 2015-12-2 today */
        assert_se(dnssec_verify_rrset(answer, a->key, rrsig, dnskey, 1449092754*USEC_PER_SEC, &result) >= 0);
        assert_se(result == DNSSEC_VALIDATED);
}

static void test_dnssec_verify_dns_key(void) {

        static const uint8_t ds1_fprint[] = {
                0x46, 0x8B, 0xC8, 0xDD, 0xC7, 0xE8, 0x27, 0x03, 0x40, 0xBB, 0x8A, 0x1F, 0x3B, 0x2E, 0x45, 0x9D,
                0x80, 0x67, 0x14, 0x01,
        };
        static const uint8_t ds2_fprint[] = {
                0x8A, 0xEE, 0x80, 0x47, 0x05, 0x5F, 0x83, 0xD1, 0x48, 0xBA, 0x8F, 0xF6, 0xDD, 0xA7, 0x60, 0xCE,
                0x94, 0xF7, 0xC7, 0x5E, 0x52, 0x4C, 0xF2, 0xE9, 0x50, 0xB9, 0x2E, 0xCB, 0xEF, 0x96, 0xB9, 0x98,
        };
        static const uint8_t dnskey_blob[] = {
                0x03, 0x01, 0x00, 0x01, 0xa8, 0x12, 0xda, 0x4f, 0xd2, 0x7d, 0x54, 0x14, 0x0e, 0xcc, 0x5b, 0x5e,
                0x45, 0x9c, 0x96, 0x98, 0xc0, 0xc0, 0x85, 0x81, 0xb1, 0x47, 0x8c, 0x7d, 0xe8, 0x39, 0x50, 0xcc,
                0xc5, 0xd0, 0xf2, 0x00, 0x81, 0x67, 0x79, 0xf6, 0xcc, 0x9d, 0xad, 0x6c, 0xbb, 0x7b, 0x6f, 0x48,
                0x97, 0x15, 0x1c, 0xfd, 0x0b, 0xfe, 0xd3, 0xd7, 0x7d, 0x9f, 0x81, 0x26, 0xd3, 0xc5, 0x65, 0x49,
                0xcf, 0x46, 0x62, 0xb0, 0x55, 0x6e, 0x47, 0xc7, 0x30, 0xef, 0x51, 0xfb, 0x3e, 0xc6, 0xef, 0xde,
                0x27, 0x3f, 0xfa, 0x57, 0x2d, 0xa7, 0x1d, 0x80, 0x46, 0x9a, 0x5f, 0x14, 0xb3, 0xb0, 0x2c, 0xbe,
                0x72, 0xca, 0xdf, 0xb2, 0xff, 0x36, 0x5b, 0x4f, 0xec, 0x58, 0x8e, 0x8d, 0x01, 0xe9, 0xa9, 0xdf,
                0xb5, 0x60, 0xad, 0x52, 0x4d, 0xfc, 0xa9, 0x3e, 0x8d, 0x35, 0x95, 0xb3, 0x4e, 0x0f, 0xca, 0x45,
                0x1b, 0xf7, 0xef, 0x3a, 0x88, 0x25, 0x08, 0xc7, 0x4e, 0x06, 0xc1, 0x62, 0x1a, 0xce, 0xd8, 0x77,
                0xbd, 0x02, 0x65, 0xf8, 0x49, 0xfb, 0xce, 0xf6, 0xa8, 0x09, 0xfc, 0xde, 0xb2, 0x09, 0x9d, 0x39,
                0xf8, 0x63, 0x9c, 0x32, 0x42, 0x7c, 0xa0, 0x30, 0x86, 0x72, 0x7a, 0x4a, 0xc6, 0xd4, 0xb3, 0x2d,
                0x24, 0xef, 0x96, 0x3f, 0xc2, 0xda, 0xd3, 0xf2, 0x15, 0x6f, 0xda, 0x65, 0x4b, 0x81, 0x28, 0x68,
                0xf4, 0xfe, 0x3e, 0x71, 0x4f, 0x50, 0x96, 0x72, 0x58, 0xa1, 0x89, 0xdd, 0x01, 0x61, 0x39, 0x39,
                0xc6, 0x76, 0xa4, 0xda, 0x02, 0x70, 0x3d, 0xc0, 0xdc, 0x8d, 0x70, 0x72, 0x04, 0x90, 0x79, 0xd4,
                0xec, 0x65, 0xcf, 0x49, 0x35, 0x25, 0x3a, 0x14, 0x1a, 0x45, 0x20, 0xeb, 0x31, 0xaf, 0x92, 0xba,
                0x20, 0xd3, 0xcd, 0xa7, 0x13, 0x44, 0xdc, 0xcf, 0xf0, 0x27, 0x34, 0xb9, 0xe7, 0x24, 0x6f, 0x73,
                0xe7, 0xea, 0x77, 0x03,
        };

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *dnskey = NULL, *ds1 = NULL, *ds2 = NULL;
        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL;

        /* The two DS RRs in effect for nasa.gov on 2015-12-01. */
        ds1 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DS, "nasa.gov");
        assert_se(ds1);

        ds1->ds.key_tag = 47857;
        ds1->ds.algorithm = DNSSEC_ALGORITHM_RSASHA256;
        ds1->ds.digest_type = DNSSEC_DIGEST_SHA1;
        ds1->ds.digest_size = sizeof(ds1_fprint);
        ds1->ds.digest = memdup(ds1_fprint, ds1->ds.digest_size);
        assert_se(ds1->ds.digest);

        assert_se(dns_resource_record_to_string(ds1, &a) >= 0);
        log_info("DS1: %s", a);

        ds2 = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DS, "NASA.GOV");
        assert_se(ds2);

        ds2->ds.key_tag = 47857;
        ds2->ds.algorithm = DNSSEC_ALGORITHM_RSASHA256;
        ds2->ds.digest_type = DNSSEC_DIGEST_SHA256;
        ds2->ds.digest_size = sizeof(ds2_fprint);
        ds2->ds.digest = memdup(ds2_fprint, ds2->ds.digest_size);
        assert_se(ds2->ds.digest);

        assert_se(dns_resource_record_to_string(ds2, &b) >= 0);
        log_info("DS2: %s", b);

        dnskey = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNSKEY, "nasa.GOV");
        assert_se(dnskey);

        dnskey->dnskey.flags = 257;
        dnskey->dnskey.protocol = 3;
        dnskey->dnskey.algorithm = DNSSEC_ALGORITHM_RSASHA256;
        dnskey->dnskey.key_size = sizeof(dnskey_blob);
        dnskey->dnskey.key = memdup(dnskey_blob, sizeof(dnskey_blob));
        assert_se(dnskey->dnskey.key);

        assert_se(dns_resource_record_to_string(dnskey, &c) >= 0);
        log_info("DNSKEY: %s", c);
        log_info("DNSKEY keytag: %u", dnssec_keytag(dnskey));

        assert_se(dnssec_verify_dnskey(dnskey, ds1) > 0);
        assert_se(dnssec_verify_dnskey(dnskey, ds2) > 0);
}

static void test_dnssec_canonicalize_one(const char *original, const char *canonical, int r) {
        char canonicalized[DNSSEC_CANONICAL_HOSTNAME_MAX];

        assert_se(dnssec_canonicalize(original, canonicalized, sizeof(canonicalized)) == r);
        if (r < 0)
                return;

        assert_se(streq(canonicalized, canonical));
}

static void test_dnssec_canonicalize(void) {
        test_dnssec_canonicalize_one("", ".", 1);
        test_dnssec_canonicalize_one(".", ".", 1);
        test_dnssec_canonicalize_one("foo", "foo.", 4);
        test_dnssec_canonicalize_one("foo.", "foo.", 4);
        test_dnssec_canonicalize_one("FOO.", "foo.", 4);
        test_dnssec_canonicalize_one("FOO.bar.", "foo.bar.", 8);
        test_dnssec_canonicalize_one("FOO..bar.", NULL, -EINVAL);
}

static void test_dnssec_nsec3_hash(void) {
        static const uint8_t salt[] = { 0xB0, 0x1D, 0xFA, 0xCE };
        static const uint8_t next_hashed_name[] = { 0x84, 0x10, 0x26, 0x53, 0xc9, 0xfa, 0x4d, 0x85, 0x6c, 0x97, 0x82, 0xe2, 0x8f, 0xdf, 0x2d, 0x5e, 0x87, 0x69, 0xc4, 0x52 };
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_free_ char *a = NULL, *b = NULL;
        uint8_t h[DNSSEC_HASH_SIZE_MAX];
        int k;

        /* The NSEC3 RR for eurid.eu on 2015-12-14. */
        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NSEC3, "PJ8S08RR45VIQDAQGE7EN3VHKNROTBMM.eurid.eu.");
        assert_se(rr);

        rr->nsec3.algorithm = DNSSEC_DIGEST_SHA1;
        rr->nsec3.flags = 1;
        rr->nsec3.iterations = 1;
        rr->nsec3.salt = memdup(salt, sizeof(salt));
        assert_se(rr->nsec3.salt);
        rr->nsec3.salt_size = sizeof(salt);
        rr->nsec3.next_hashed_name = memdup(next_hashed_name, sizeof(next_hashed_name));
        assert_se(rr->nsec3.next_hashed_name);
        rr->nsec3.next_hashed_name_size = sizeof(next_hashed_name);

        assert_se(dns_resource_record_to_string(rr, &a) >= 0);
        log_info("NSEC3: %s", a);

        k = dnssec_nsec3_hash(rr, "eurid.eu", &h);
        assert_se(k >= 0);

        b = base32hexmem(h, k, false);
        assert_se(b);
        assert_se(strcasecmp(b, "PJ8S08RR45VIQDAQGE7EN3VHKNROTBMM") == 0);
}

int main(int argc, char*argv[]) {

        test_dnssec_canonicalize();
        test_dnssec_verify_dns_key();
        test_dnssec_verify_rrset();
        test_dnssec_verify_rrset2();
        test_dnssec_nsec3_hash();

        return 0;
}
