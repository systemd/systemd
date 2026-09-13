/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "crypto-util.h"
#include "dns-answer.h"
#include "dns-rr.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "resolved-dns-dnssec.h"
#include "tests.h"
#include "time-util.h"

static void* load_base64_test_vector(const char *name, size_t *ret_size) {
        _cleanup_free_ char *encoded = NULL, *path = NULL;
        void *decoded = NULL;

        assert(name);
        assert(ret_size);

        assert_se(get_testdata_dir(name, &path) >= 0);
        assert_se(read_full_file(path, &encoded, /* ret_size= */ NULL) >= 0);
        assert_se(unbase64mem(encoded, &decoded, ret_size) >= 0);

        return decoded;
}

static void mldsa44_fixture_new(
                DnsResourceRecord **ret_mx,
                DnsResourceRecord **ret_rrsig,
                DnsResourceRecord **ret_dnskey,
                DnsAnswer **ret_answer) {

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *dnskey = NULL, *mx = NULL, *rrsig = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

        assert(ret_mx);
        assert(ret_rrsig);
        assert(ret_dnskey);
        assert(ret_answer);

        /* Deterministic example from Section 6 of draft-westerbaan-dnssec-mldsa-04. */
        assert_se(dnskey = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNSKEY, "example.com."));
        dnskey->dnskey.flags = 257;
        dnskey->dnskey.protocol = 3;
        dnskey->dnskey.algorithm = DNSSEC_ALGORITHM_MLDSA44;
        dnskey->dnskey.key = load_base64_test_vector(
                        "test-resolve/mldsa44-dnskey.b64", &dnskey->dnskey.key_size);
        assert_se(dnskey->dnskey.key_size == 1312);

        assert_se(mx = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_MX, "example.com."));
        mx->ttl = 3600;
        mx->mx.priority = 10;
        assert_se(mx->mx.exchange = strdup("mail.example.com."));

        assert_se(rrsig = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "example.com."));
        rrsig->ttl = 3600;
        rrsig->rrsig.type_covered = DNS_TYPE_MX;
        rrsig->rrsig.algorithm = DNSSEC_ALGORITHM_MLDSA44;
        rrsig->rrsig.labels = 2;
        rrsig->rrsig.original_ttl = 3600;
        rrsig->rrsig.expiration = 1440021600;
        rrsig->rrsig.inception = 1438207200;
        rrsig->rrsig.key_tag = 59829;
        assert_se(rrsig->rrsig.signer = strdup("example.com."));
        rrsig->rrsig.signature = load_base64_test_vector(
                        "test-resolve/mldsa44-rrsig.b64", &rrsig->rrsig.signature_size);
        assert_se(rrsig->rrsig.signature_size == 2420);

        assert_se(dnssec_keytag(dnskey, false) == rrsig->rrsig.key_tag);
        assert_se(dnssec_key_match_rrsig(mx->key, rrsig) > 0);
        assert_se(dnssec_rrsig_match_dnskey(rrsig, dnskey, false) > 0);

        assert_se(answer = dns_answer_new(1));
        assert_se(dns_answer_add(answer, mx, 0, DNS_ANSWER_AUTHENTICATED, /* rrsig= */ NULL) >= 0);

        *ret_mx = TAKE_PTR(mx);
        *ret_rrsig = TAKE_PTR(rrsig);
        *ret_dnskey = TAKE_PTR(dnskey);
        *ret_answer = TAKE_PTR(answer);
}

static bool mldsa44_available(void) {
        sym_ERR_clear_error();
        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new_from_name(
                        /* libctx= */ NULL, "ML-DSA-44", /* propquery= */ NULL);
        if (ctx)
                return true;

        ASSERT_ERROR(log_openssl_errors(LOG_DEBUG, "ML-DSA-44 capability check failed"), EOPNOTSUPP);
        return false;
}

TEST(dnssec_mldsa44_verify) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *dnskey = NULL, *mx = NULL, *rrsig = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_free_ char *algorithm = NULL;
        DnssecResult result;

        ASSERT_OK(dnssec_algorithm_to_string_alloc(DNSSEC_ALGORITHM_MLDSA44, &algorithm));
        ASSERT_STREQ(algorithm, "MLDSA44");
        mldsa44_fixture_new(&mx, &rrsig, &dnskey, &answer);

        bool available = mldsa44_available();
        ASSERT_OK(dnssec_verify_rrset(
                        answer, mx->key, rrsig, dnskey, rrsig->rrsig.inception * USEC_PER_SEC, &result));
        if (!available) {
                ASSERT_EQ(result, DNSSEC_UNSUPPORTED_ALGORITHM);
                return (void) log_tests_skipped("OpenSSL does not provide ML-DSA-44");
        }
        ASSERT_EQ(result, DNSSEC_VALIDATED);

        mx->mx.priority++;
        dns_resource_record_clear_wire_format(mx);
        ASSERT_OK(dnssec_verify_rrset(
                        answer, mx->key, rrsig, dnskey, rrsig->rrsig.inception * USEC_PER_SEC, &result));
        ASSERT_EQ(result, DNSSEC_INVALID);
        mx->mx.priority--;
        dns_resource_record_clear_wire_format(mx);

        ((uint8_t*) rrsig->rrsig.signature)[0] ^= 1;
        ASSERT_OK(dnssec_verify_rrset(
                        answer, mx->key, rrsig, dnskey, rrsig->rrsig.inception * USEC_PER_SEC, &result));
        ASSERT_EQ(result, DNSSEC_INVALID);
}

TEST(dnssec_mldsa44_corrupted_key) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *dnskey = NULL, *mx = NULL, *rrsig = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnssecResult result;

        mldsa44_fixture_new(&mx, &rrsig, &dnskey, &answer);

        if (!mldsa44_available())
                return (void) log_tests_skipped("OpenSSL does not provide ML-DSA-44");

        ASSERT_OK(dnssec_verify_rrset(
                        answer, mx->key, rrsig, dnskey, rrsig->rrsig.inception * USEC_PER_SEC, &result));
        ASSERT_EQ(result, DNSSEC_VALIDATED);

        ((uint8_t*) dnskey->dnskey.key)[0] ^= 1;
        ASSERT_EQ(dnskey->dnskey.key_size, (size_t) 1312);

        ASSERT_OK(dnssec_verify_rrset(
                        answer, mx->key, rrsig, dnskey, rrsig->rrsig.inception * USEC_PER_SEC, &result));
        ASSERT_EQ(result, DNSSEC_INVALID);
}

TEST(dnssec_mldsa44_sizes) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *dnskey = NULL, *mx = NULL, *rrsig = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnssecResult result;

        mldsa44_fixture_new(&mx, &rrsig, &dnskey, &answer);

        dnskey->dnskey.key_size--;
        ASSERT_ERROR(dnssec_verify_rrset(
                        answer, mx->key, rrsig, dnskey,
                        rrsig->rrsig.inception * USEC_PER_SEC, &result), EINVAL);
        dnskey->dnskey.key_size++;

        rrsig->rrsig.signature_size--;
        ASSERT_ERROR(dnssec_verify_rrset(
                        answer, mx->key, rrsig, dnskey,
                        rrsig->rrsig.inception * USEC_PER_SEC, &result), EINVAL);
}

static int fail_key_import(EVP_PKEY_CTX *ctx, EVP_PKEY **pkey, int selection, OSSL_PARAM params[]) {
        /* Generate a real unsupported-algorithm error after capability detection has succeeded. */
        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *unsupported = sym_EVP_PKEY_CTX_new_from_name(
                        /* libctx= */ NULL, "systemd-test-nonexistent-algorithm", /* propquery= */ NULL);
        ASSERT_NULL(unsupported);
        return 0;
}

TEST(dnssec_mldsa44_import_failure) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *dnskey = NULL, *mx = NULL, *rrsig = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnssecResult result;
        int r;

        if (!mldsa44_available())
                return (void) log_tests_skipped("OpenSSL does not provide ML-DSA-44");

        mldsa44_fixture_new(&mx, &rrsig, &dnskey, &answer);
        typeof(sym_EVP_PKEY_fromdata) saved_import = sym_EVP_PKEY_fromdata;
        sym_EVP_PKEY_fromdata = fail_key_import;
        r = dnssec_verify_rrset(
                        answer, mx->key, rrsig, dnskey, rrsig->rrsig.inception * USEC_PER_SEC, &result);
        sym_EVP_PKEY_fromdata = saved_import;
        ASSERT_ERROR(r, EIO);
}

TEST(dnssec_mldsa44_stale_errors) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *dnskey = NULL, *mx = NULL, *rrsig = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnssecResult result;

        mldsa44_fixture_new(&mx, &rrsig, &dnskey, &answer);
        bool available = mldsa44_available();

        /* Leave an unrelated key-import error in OpenSSL's queue. */
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *bad = sym_EVP_PKEY_new_raw_public_key(
                        EVP_PKEY_ED25519, /* engine= */ NULL, dnskey->dnskey.key, 1);
        ASSERT_NULL(bad);

        ASSERT_OK(dnssec_verify_rrset(
                        answer, mx->key, rrsig, dnskey, rrsig->rrsig.inception * USEC_PER_SEC, &result));
        ASSERT_EQ(result, available ? DNSSEC_VALIDATED : DNSSEC_UNSUPPORTED_ALGORITHM);
        ASSERT_EQ(sym_ERR_get_error(), 0UL);
}

static int intro(void) {
        if (dlopen_libcrypto(LOG_DEBUG) < 0)
                return EXIT_TEST_SKIP;

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
