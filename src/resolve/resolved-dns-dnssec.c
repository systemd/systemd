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

#include <gcrypt.h>

#include "alloc-util.h"
#include "dns-domain.h"
#include "hexdecoct.h"
#include "resolved-dns-dnssec.h"
#include "resolved-dns-packet.h"
#include "string-table.h"

/* Open question:
 *
 * How does the DNSSEC canonical form of a hostname with a label
 * containing a dot look like, the way DNS-SD does it?
 *
 * TODO:
 *
 *   - wildcard zones compatibility (NSEC/NSEC3 wildcard check is missing)
 *   - multi-label zone compatibility
 *   - cname/dname compatibility
 *   - nxdomain on qname
 *   - bus calls to override DNSEC setting per interface
 *   - log all DNSSEC downgrades
 *   - enable by default
 *
 *   - RFC 4035, Section 5.3.4 (When receiving a positive wildcard reply, use NSEC to ensure it actually really applies)
 *   - RFC 6840, Section 4.1 (ensure we don't get fed a glue NSEC from the parent zone)
 *   - RFC 6840, Section 4.3 (check for CNAME on NSEC too)
 * */

#define VERIFY_RRS_MAX 256
#define MAX_KEY_SIZE (32*1024)

/* Permit a maximum clock skew of 1h 10min. This should be enough to deal with DST confusion */
#define SKEW_MAX (1*USEC_PER_HOUR + 10*USEC_PER_MINUTE)

/* Maximum number of NSEC3 iterations we'll do. RFC5155 says 2500 shall be the maximum useful value */
#define NSEC3_ITERATIONS_MAX 2500

/*
 * The DNSSEC Chain of trust:
 *
 *            Normal RRs are protected via RRSIG RRs in combination with DNSKEY RRs, all in the same zone
 *            DNSKEY RRs are either protected like normal RRs, or via a DS from a zone "higher" up the tree
 *            DS RRs are protected like normal RRs
 *
 * Example chain:
 *            Normal RR → RRSIG/DNSKEY+ → DS → RRSIG/DNSKEY+ → DS → ... → DS → RRSIG/DNSKEY+ → DS
 */

static void initialize_libgcrypt(void) {
        const char *p;

        if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
                return;

        p = gcry_check_version("1.4.5");
        assert(p);

        gcry_control(GCRYCTL_DISABLE_SECMEM);
        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

uint16_t dnssec_keytag(DnsResourceRecord *dnskey, bool mask_revoke) {
        const uint8_t *p;
        uint32_t sum, f;
        size_t i;

        /* The algorithm from RFC 4034, Appendix B. */

        assert(dnskey);
        assert(dnskey->key->type == DNS_TYPE_DNSKEY);

        f = (uint32_t) dnskey->dnskey.flags;

        if (mask_revoke)
                f &= ~DNSKEY_FLAG_REVOKE;

        sum = f + ((((uint32_t) dnskey->dnskey.protocol) << 8) + (uint32_t) dnskey->dnskey.algorithm);

        p = dnskey->dnskey.key;

        for (i = 0; i < dnskey->dnskey.key_size; i++)
                sum += (i & 1) == 0 ? (uint32_t) p[i] << 8 : (uint32_t) p[i];

        sum += (sum >> 16) & UINT32_C(0xFFFF);

        return sum & UINT32_C(0xFFFF);
}

static int rr_compare(const void *a, const void *b) {
        DnsResourceRecord **x = (DnsResourceRecord**) a, **y = (DnsResourceRecord**) b;
        size_t m;
        int r;

        /* Let's order the RRs according to RFC 4034, Section 6.3 */

        assert(x);
        assert(*x);
        assert((*x)->wire_format);
        assert(y);
        assert(*y);
        assert((*y)->wire_format);

        m = MIN(DNS_RESOURCE_RECORD_RDATA_SIZE(*x), DNS_RESOURCE_RECORD_RDATA_SIZE(*y));

        r = memcmp(DNS_RESOURCE_RECORD_RDATA(*x), DNS_RESOURCE_RECORD_RDATA(*y), m);
        if (r != 0)
                return r;

        if (DNS_RESOURCE_RECORD_RDATA_SIZE(*x) < DNS_RESOURCE_RECORD_RDATA_SIZE(*y))
                return -1;
        else if (DNS_RESOURCE_RECORD_RDATA_SIZE(*x) > DNS_RESOURCE_RECORD_RDATA_SIZE(*y))
                return 1;

        return 0;
}

static int dnssec_rsa_verify_raw(
                const char *hash_algorithm,
                const void *signature, size_t signature_size,
                const void *data, size_t data_size,
                const void *exponent, size_t exponent_size,
                const void *modulus, size_t modulus_size) {

        gcry_sexp_t public_key_sexp = NULL, data_sexp = NULL, signature_sexp = NULL;
        gcry_mpi_t n = NULL, e = NULL, s = NULL;
        gcry_error_t ge;
        int r;

        assert(hash_algorithm);

        ge = gcry_mpi_scan(&s, GCRYMPI_FMT_USG, signature, signature_size, NULL);
        if (ge != 0) {
                r = -EIO;
                goto finish;
        }

        ge = gcry_mpi_scan(&e, GCRYMPI_FMT_USG, exponent, exponent_size, NULL);
        if (ge != 0) {
                r = -EIO;
                goto finish;
        }

        ge = gcry_mpi_scan(&n, GCRYMPI_FMT_USG, modulus, modulus_size, NULL);
        if (ge != 0) {
                r = -EIO;
                goto finish;
        }

        ge = gcry_sexp_build(&signature_sexp,
                             NULL,
                             "(sig-val (rsa (s %m)))",
                             s);

        if (ge != 0) {
                r = -EIO;
                goto finish;
        }

        ge = gcry_sexp_build(&data_sexp,
                             NULL,
                             "(data (flags pkcs1) (hash %s %b))",
                             hash_algorithm,
                             (int) data_size,
                             data);
        if (ge != 0) {
                r = -EIO;
                goto finish;
        }

        ge = gcry_sexp_build(&public_key_sexp,
                             NULL,
                             "(public-key (rsa (n %m) (e %m)))",
                             n,
                             e);
        if (ge != 0) {
                r = -EIO;
                goto finish;
        }

        ge = gcry_pk_verify(signature_sexp, data_sexp, public_key_sexp);
        if (gpg_err_code(ge) == GPG_ERR_BAD_SIGNATURE)
                r = 0;
        else if (ge != 0) {
                log_debug("RSA signature check failed: %s", gpg_strerror(ge));
                r = -EIO;
        } else
                r = 1;

finish:
        if (e)
                gcry_mpi_release(e);
        if (n)
                gcry_mpi_release(n);
        if (s)
                gcry_mpi_release(s);

        if (public_key_sexp)
                gcry_sexp_release(public_key_sexp);
        if (signature_sexp)
                gcry_sexp_release(signature_sexp);
        if (data_sexp)
                gcry_sexp_release(data_sexp);

        return r;
}

static int dnssec_rsa_verify(
                const char *hash_algorithm,
                const void *hash, size_t hash_size,
                DnsResourceRecord *rrsig,
                DnsResourceRecord *dnskey) {

        size_t exponent_size, modulus_size;
        void *exponent, *modulus;

        assert(hash_algorithm);
        assert(hash);
        assert(hash_size > 0);
        assert(rrsig);
        assert(dnskey);

        if (*(uint8_t*) dnskey->dnskey.key == 0) {
                /* exponent is > 255 bytes long */

                exponent = (uint8_t*) dnskey->dnskey.key + 3;
                exponent_size =
                        ((size_t) (((uint8_t*) dnskey->dnskey.key)[1]) << 8) |
                        ((size_t) ((uint8_t*) dnskey->dnskey.key)[2]);

                if (exponent_size < 256)
                        return -EINVAL;

                if (3 + exponent_size >= dnskey->dnskey.key_size)
                        return -EINVAL;

                modulus = (uint8_t*) dnskey->dnskey.key + 3 + exponent_size;
                modulus_size = dnskey->dnskey.key_size - 3 - exponent_size;

        } else {
                /* exponent is <= 255 bytes long */

                exponent = (uint8_t*) dnskey->dnskey.key + 1;
                exponent_size = (size_t) ((uint8_t*) dnskey->dnskey.key)[0];

                if (exponent_size <= 0)
                        return -EINVAL;

                if (1 + exponent_size >= dnskey->dnskey.key_size)
                        return -EINVAL;

                modulus = (uint8_t*) dnskey->dnskey.key + 1 + exponent_size;
                modulus_size = dnskey->dnskey.key_size - 1 - exponent_size;
        }

        return dnssec_rsa_verify_raw(
                        hash_algorithm,
                        rrsig->rrsig.signature, rrsig->rrsig.signature_size,
                        hash, hash_size,
                        exponent, exponent_size,
                        modulus, modulus_size);
}

static int dnssec_ecdsa_verify_raw(
                const char *hash_algorithm,
                const char *curve,
                const void *signature_r, size_t signature_r_size,
                const void *signature_s, size_t signature_s_size,
                const void *data, size_t data_size,
                const void *key, size_t key_size) {

        gcry_sexp_t public_key_sexp = NULL, data_sexp = NULL, signature_sexp = NULL;
        gcry_mpi_t q = NULL, r = NULL, s = NULL;
        gcry_error_t ge;
        int k;

        assert(hash_algorithm);

        ge = gcry_mpi_scan(&r, GCRYMPI_FMT_USG, signature_r, signature_r_size, NULL);
        if (ge != 0) {
                k = -EIO;
                goto finish;
        }

        ge = gcry_mpi_scan(&s, GCRYMPI_FMT_USG, signature_s, signature_s_size, NULL);
        if (ge != 0) {
                k = -EIO;
                goto finish;
        }

        ge = gcry_mpi_scan(&q, GCRYMPI_FMT_USG, key, key_size, NULL);
        if (ge != 0) {
                k = -EIO;
                goto finish;
        }

        ge = gcry_sexp_build(&signature_sexp,
                             NULL,
                             "(sig-val (ecdsa (r %m) (s %m)))",
                             r,
                             s);
        if (ge != 0) {
                k = -EIO;
                goto finish;
        }

        ge = gcry_sexp_build(&data_sexp,
                             NULL,
                             "(data (flags rfc6979) (hash %s %b))",
                             hash_algorithm,
                             (int) data_size,
                             data);
        if (ge != 0) {
                k = -EIO;
                goto finish;
        }

        ge = gcry_sexp_build(&public_key_sexp,
                             NULL,
                             "(public-key (ecc (curve %s) (q %m)))",
                             curve,
                             q);
        if (ge != 0) {
                k = -EIO;
                goto finish;
        }

        ge = gcry_pk_verify(signature_sexp, data_sexp, public_key_sexp);
        if (gpg_err_code(ge) == GPG_ERR_BAD_SIGNATURE)
                k = 0;
        else if (ge != 0) {
                log_debug("ECDSA signature check failed: %s", gpg_strerror(ge));
                k = -EIO;
        } else
                k = 1;
finish:
        if (r)
                gcry_mpi_release(r);
        if (s)
                gcry_mpi_release(s);
        if (q)
                gcry_mpi_release(q);

        if (public_key_sexp)
                gcry_sexp_release(public_key_sexp);
        if (signature_sexp)
                gcry_sexp_release(signature_sexp);
        if (data_sexp)
                gcry_sexp_release(data_sexp);

        return k;
}

static int dnssec_ecdsa_verify(
                const char *hash_algorithm,
                int algorithm,
                const void *hash, size_t hash_size,
                DnsResourceRecord *rrsig,
                DnsResourceRecord *dnskey) {

        const char *curve;
        size_t key_size;
        uint8_t *q;

        assert(hash);
        assert(hash_size);
        assert(rrsig);
        assert(dnskey);

        if (algorithm == DNSSEC_ALGORITHM_ECDSAP256SHA256) {
                key_size = 32;
                curve = "NIST P-256";
        } else if (algorithm == DNSSEC_ALGORITHM_ECDSAP384SHA384) {
                key_size = 48;
                curve = "NIST P-384";
        } else
                return -EOPNOTSUPP;

        if (dnskey->dnskey.key_size != key_size * 2)
                return -EINVAL;

        if (rrsig->rrsig.signature_size != key_size * 2)
                return -EINVAL;

        q = alloca(key_size*2 + 1);
        q[0] = 0x04; /* Prepend 0x04 to indicate an uncompressed key */
        memcpy(q+1, dnskey->dnskey.key, key_size*2);

        return dnssec_ecdsa_verify_raw(
                        hash_algorithm,
                        curve,
                        rrsig->rrsig.signature, key_size,
                        (uint8_t*) rrsig->rrsig.signature + key_size, key_size,
                        hash, hash_size,
                        q, key_size*2+1);
}

static void md_add_uint8(gcry_md_hd_t md, uint8_t v) {
        gcry_md_write(md, &v, sizeof(v));
}

static void md_add_uint16(gcry_md_hd_t md, uint16_t v) {
        v = htobe16(v);
        gcry_md_write(md, &v, sizeof(v));
}

static void md_add_uint32(gcry_md_hd_t md, uint32_t v) {
        v = htobe32(v);
        gcry_md_write(md, &v, sizeof(v));
}

static int dnssec_rrsig_expired(DnsResourceRecord *rrsig, usec_t realtime) {
        usec_t expiration, inception, skew;

        assert(rrsig);
        assert(rrsig->key->type == DNS_TYPE_RRSIG);

        if (realtime == USEC_INFINITY)
                realtime = now(CLOCK_REALTIME);

        expiration = rrsig->rrsig.expiration * USEC_PER_SEC;
        inception = rrsig->rrsig.inception * USEC_PER_SEC;

        /* Consider inverted validity intervals as expired */
        if (inception > expiration)
                return true;

        /* Permit a certain amount of clock skew of 10% of the valid
         * time range. This takes inspiration from unbound's
         * resolver. */
        skew = (expiration - inception) / 10;
        if (skew > SKEW_MAX)
                skew = SKEW_MAX;

        if (inception < skew)
                inception = 0;
        else
                inception -= skew;

        if (expiration + skew < expiration)
                expiration = USEC_INFINITY;
        else
                expiration += skew;

        return realtime < inception || realtime > expiration;
}

static int algorithm_to_gcrypt_md(uint8_t algorithm) {

        /* Translates a DNSSEC signature algorithm into a gcrypt
         * digest identifier.
         *
         * Note that we implement all algorithms listed as "Must
         * implement" and "Recommended to Implement" in RFC6944. We
         * don't implement any algorithms that are listed as
         * "Optional" or "Must Not Implement". Specifically, we do not
         * implement RSAMD5, DSASHA1, DH, DSA-NSEC3-SHA1, and
         * GOST-ECC. */

        switch (algorithm) {

        case DNSSEC_ALGORITHM_RSASHA1:
        case DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1:
                return GCRY_MD_SHA1;

        case DNSSEC_ALGORITHM_RSASHA256:
        case DNSSEC_ALGORITHM_ECDSAP256SHA256:
                return GCRY_MD_SHA256;

        case DNSSEC_ALGORITHM_ECDSAP384SHA384:
                return GCRY_MD_SHA384;

        case DNSSEC_ALGORITHM_RSASHA512:
                return GCRY_MD_SHA512;

        default:
                return -EOPNOTSUPP;
        }
}

int dnssec_verify_rrset(
                DnsAnswer *a,
                const DnsResourceKey *key,
                DnsResourceRecord *rrsig,
                DnsResourceRecord *dnskey,
                usec_t realtime,
                DnssecResult *result) {

        uint8_t wire_format_name[DNS_WIRE_FOMAT_HOSTNAME_MAX];
        size_t hash_size;
        void *hash;
        DnsResourceRecord **list, *rr;
        gcry_md_hd_t md = NULL;
        int r, md_algorithm;
        bool wildcard = false;
        size_t k, n = 0;

        assert(key);
        assert(rrsig);
        assert(dnskey);
        assert(result);
        assert(rrsig->key->type == DNS_TYPE_RRSIG);
        assert(dnskey->key->type == DNS_TYPE_DNSKEY);

        /* Verifies the the RRSet matching the specified "key" in "a",
         * using the signature "rrsig" and the key "dnskey". It's
         * assumed the RRSIG and DNSKEY match. */

        md_algorithm = algorithm_to_gcrypt_md(rrsig->rrsig.algorithm);
        if (md_algorithm == -EOPNOTSUPP) {
                *result = DNSSEC_UNSUPPORTED_ALGORITHM;
                return 0;
        }
        if (md_algorithm < 0)
                return md_algorithm;

        r = dnssec_rrsig_expired(rrsig, realtime);
        if (r < 0)
                return r;
        if (r > 0) {
                *result = DNSSEC_SIGNATURE_EXPIRED;
                return 0;
        }

        /* Collect all relevant RRs in a single array, so that we can look at the RRset */
        list = newa(DnsResourceRecord *, dns_answer_size(a));

        DNS_ANSWER_FOREACH(rr, a) {
                r = dns_resource_key_equal(key, rr->key);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                /* We need the wire format for ordering, and digest calculation */
                r = dns_resource_record_to_wire_format(rr, true);
                if (r < 0)
                        return r;

                list[n++] = rr;

                if (n > VERIFY_RRS_MAX)
                        return -E2BIG;
        }

        if (n <= 0)
                return -ENODATA;

        /* Bring the RRs into canonical order */
        qsort_safe(list, n, sizeof(DnsResourceRecord*), rr_compare);

        /* OK, the RRs are now in canonical order. Let's calculate the digest */
        initialize_libgcrypt();

        hash_size = gcry_md_get_algo_dlen(md_algorithm);
        assert(hash_size > 0);

        gcry_md_open(&md, md_algorithm, 0);
        if (!md)
                return -EIO;

        md_add_uint16(md, rrsig->rrsig.type_covered);
        md_add_uint8(md, rrsig->rrsig.algorithm);
        md_add_uint8(md, rrsig->rrsig.labels);
        md_add_uint32(md, rrsig->rrsig.original_ttl);
        md_add_uint32(md, rrsig->rrsig.expiration);
        md_add_uint32(md, rrsig->rrsig.inception);
        md_add_uint16(md, rrsig->rrsig.key_tag);

        r = dns_name_to_wire_format(rrsig->rrsig.signer, wire_format_name, sizeof(wire_format_name), true);
        if (r < 0)
                goto finish;
        gcry_md_write(md, wire_format_name, r);

        for (k = 0; k < n; k++) {
                const char *suffix;
                size_t l;
                rr = list[k];

                r = dns_name_suffix(DNS_RESOURCE_KEY_NAME(rr->key), rrsig->rrsig.labels, &suffix);
                if (r < 0)
                        goto finish;
                if (r > 0) /* This is a wildcard! */ {
                        gcry_md_write(md, (uint8_t[]) { 1, '*'}, 2);
                        wildcard = true;
                }

                r = dns_name_to_wire_format(suffix, wire_format_name, sizeof(wire_format_name), true);
                if (r < 0)
                        goto finish;
                gcry_md_write(md, wire_format_name, r);

                md_add_uint16(md, rr->key->type);
                md_add_uint16(md, rr->key->class);
                md_add_uint32(md, rrsig->rrsig.original_ttl);

                l = DNS_RESOURCE_RECORD_RDATA_SIZE(rr);
                assert(l <= 0xFFFF);

                md_add_uint16(md, (uint16_t) l);
                gcry_md_write(md, DNS_RESOURCE_RECORD_RDATA(rr), l);
        }

        hash = gcry_md_read(md, 0);
        if (!hash) {
                r = -EIO;
                goto finish;
        }

        switch (rrsig->rrsig.algorithm) {

        case DNSSEC_ALGORITHM_RSASHA1:
        case DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1:
        case DNSSEC_ALGORITHM_RSASHA256:
        case DNSSEC_ALGORITHM_RSASHA512:
                r = dnssec_rsa_verify(
                                gcry_md_algo_name(md_algorithm),
                                hash, hash_size,
                                rrsig,
                                dnskey);
                break;

        case DNSSEC_ALGORITHM_ECDSAP256SHA256:
        case DNSSEC_ALGORITHM_ECDSAP384SHA384:
                r = dnssec_ecdsa_verify(
                                gcry_md_algo_name(md_algorithm),
                                rrsig->rrsig.algorithm,
                                hash, hash_size,
                                rrsig,
                                dnskey);
                break;
        }

        if (r < 0)
                goto finish;

        if (!r)
                *result = DNSSEC_INVALID;
        else if (wildcard)
                *result = DNSSEC_VALIDATED_WILDCARD;
        else
                *result = DNSSEC_VALIDATED;
        r = 0;

finish:
        gcry_md_close(md);
        return r;
}

int dnssec_rrsig_match_dnskey(DnsResourceRecord *rrsig, DnsResourceRecord *dnskey, bool revoked_ok) {

        assert(rrsig);
        assert(dnskey);

        /* Checks if the specified DNSKEY RR matches the key used for
         * the signature in the specified RRSIG RR */

        if (rrsig->key->type != DNS_TYPE_RRSIG)
                return -EINVAL;

        if (dnskey->key->type != DNS_TYPE_DNSKEY)
                return 0;
        if (dnskey->key->class != rrsig->key->class)
                return 0;
        if ((dnskey->dnskey.flags & DNSKEY_FLAG_ZONE_KEY) == 0)
                return 0;
        if (!revoked_ok && (dnskey->dnskey.flags & DNSKEY_FLAG_REVOKE))
                return 0;
        if (dnskey->dnskey.protocol != 3)
                return 0;
        if (dnskey->dnskey.algorithm != rrsig->rrsig.algorithm)
                return 0;

        if (dnssec_keytag(dnskey, false) != rrsig->rrsig.key_tag)
                return 0;

        return dns_name_equal(DNS_RESOURCE_KEY_NAME(dnskey->key), rrsig->rrsig.signer);
}

int dnssec_key_match_rrsig(const DnsResourceKey *key, DnsResourceRecord *rrsig) {
        int r;

        assert(key);
        assert(rrsig);

        /* Checks if the specified RRSIG RR protects the RRSet of the specified RR key. */

        if (rrsig->key->type != DNS_TYPE_RRSIG)
                return 0;
        if (rrsig->key->class != key->class)
                return 0;
        if (rrsig->rrsig.type_covered != key->type)
                return 0;

        /* Make sure signer is a parent of the RRset */
        r = dns_name_endswith(DNS_RESOURCE_KEY_NAME(rrsig->key), rrsig->rrsig.signer);
        if (r <= 0)
                return r;

        /* Make sure the owner name has at least as many labels as the "label" fields indicates. */
        r = dns_name_count_labels(DNS_RESOURCE_KEY_NAME(rrsig->key));
        if (r < 0)
                return r;
        if (r < rrsig->rrsig.labels)
                return 0;

        return dns_name_equal(DNS_RESOURCE_KEY_NAME(rrsig->key), DNS_RESOURCE_KEY_NAME(key));
}

static int dnssec_fix_rrset_ttl(DnsAnswer *a, const DnsResourceKey *key, DnsResourceRecord *rrsig, usec_t realtime) {
        DnsResourceRecord *rr;
        int r;

        assert(key);
        assert(rrsig);

        DNS_ANSWER_FOREACH(rr, a) {
                r = dns_resource_key_equal(key, rr->key);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                /* Pick the TTL as the minimum of the RR's TTL, the
                 * RR's original TTL according to the RRSIG and the
                 * RRSIG's own TTL, see RFC 4035, Section 5.3.3 */
                rr->ttl = MIN3(rr->ttl, rrsig->rrsig.original_ttl, rrsig->ttl);
                rr->expiry = rrsig->rrsig.expiration * USEC_PER_SEC;
        }

        return 0;
}

int dnssec_verify_rrset_search(
                DnsAnswer *a,
                const DnsResourceKey *key,
                DnsAnswer *validated_dnskeys,
                usec_t realtime,
                DnssecResult *result,
                DnsResourceRecord **ret_rrsig) {

        bool found_rrsig = false, found_invalid = false, found_expired_rrsig = false, found_unsupported_algorithm = false;
        DnsResourceRecord *rrsig;
        int r;

        assert(key);
        assert(result);

        /* Verifies all RRs from "a" that match the key "key" against DNSKEYs in "validated_dnskeys" */

        if (!a || a->n_rrs <= 0)
                return -ENODATA;

        /* Iterate through each RRSIG RR. */
        DNS_ANSWER_FOREACH(rrsig, a) {
                DnsResourceRecord *dnskey;
                DnsAnswerFlags flags;

                /* Is this an RRSIG RR that applies to RRs matching our key? */
                r = dnssec_key_match_rrsig(key, rrsig);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                found_rrsig = true;

                /* Look for a matching key */
                DNS_ANSWER_FOREACH_FLAGS(dnskey, flags, validated_dnskeys) {
                        DnssecResult one_result;

                        if ((flags & DNS_ANSWER_AUTHENTICATED) == 0)
                                continue;

                        /* Is this a DNSKEY RR that matches they key of our RRSIG? */
                        r = dnssec_rrsig_match_dnskey(rrsig, dnskey, false);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        /* Take the time here, if it isn't set yet, so
                         * that we do all validations with the same
                         * time. */
                        if (realtime == USEC_INFINITY)
                                realtime = now(CLOCK_REALTIME);

                        /* Yay, we found a matching RRSIG with a matching
                         * DNSKEY, awesome. Now let's verify all entries of
                         * the RRSet against the RRSIG and DNSKEY
                         * combination. */

                        r = dnssec_verify_rrset(a, key, rrsig, dnskey, realtime, &one_result);
                        if (r < 0)
                                return r;

                        switch (one_result) {

                        case DNSSEC_VALIDATED:
                        case DNSSEC_VALIDATED_WILDCARD:
                                /* Yay, the RR has been validated,
                                 * return immediately, but fix up the expiry */
                                r = dnssec_fix_rrset_ttl(a, key, rrsig, realtime);
                                if (r < 0)
                                        return r;

                                if (ret_rrsig)
                                        *ret_rrsig = rrsig;

                                *result = one_result;
                                return 0;

                        case DNSSEC_INVALID:
                                /* If the signature is invalid, let's try another
                                   key and/or signature. After all they
                                   key_tags and stuff are not unique, and
                                   might be shared by multiple keys. */
                                found_invalid = true;
                                continue;

                        case DNSSEC_UNSUPPORTED_ALGORITHM:
                                /* If the key algorithm is
                                   unsupported, try another
                                   RRSIG/DNSKEY pair, but remember we
                                   encountered this, so that we can
                                   return a proper error when we
                                   encounter nothing better. */
                                found_unsupported_algorithm = true;
                                continue;

                        case DNSSEC_SIGNATURE_EXPIRED:
                                /* If the signature is expired, try
                                   another one, but remember it, so
                                   that we can return this */
                                found_expired_rrsig = true;
                                continue;

                        default:
                                assert_not_reached("Unexpected DNSSEC validation result");
                        }
                }
        }

        if (found_expired_rrsig)
                *result = DNSSEC_SIGNATURE_EXPIRED;
        else if (found_unsupported_algorithm)
                *result = DNSSEC_UNSUPPORTED_ALGORITHM;
        else if (found_invalid)
                *result = DNSSEC_INVALID;
        else if (found_rrsig)
                *result = DNSSEC_MISSING_KEY;
        else
                *result = DNSSEC_NO_SIGNATURE;

        if (ret_rrsig)
                *ret_rrsig = NULL;

        return 0;
}

int dnssec_has_rrsig(DnsAnswer *a, const DnsResourceKey *key) {
        DnsResourceRecord *rr;
        int r;

        /* Checks whether there's at least one RRSIG in 'a' that proctects RRs of the specified key */

        DNS_ANSWER_FOREACH(rr, a) {
                r = dnssec_key_match_rrsig(key, rr);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 1;
        }

        return 0;
}

int dnssec_canonicalize(const char *n, char *buffer, size_t buffer_max) {
        size_t c = 0;
        int r;

        /* Converts the specified hostname into DNSSEC canonicalized
         * form. */

        if (buffer_max < 2)
                return -ENOBUFS;

        for (;;) {
                r = dns_label_unescape(&n, buffer, buffer_max);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
                if (r > 0) {
                        int k;

                        /* DNSSEC validation is always done on the ASCII version of the label */
                        k = dns_label_apply_idna(buffer, r, buffer, buffer_max);
                        if (k < 0)
                                return k;
                        if (k > 0)
                                r = k;
                }

                if (buffer_max < (size_t) r + 2)
                        return -ENOBUFS;

                /* The DNSSEC canonical form is not clear on what to
                 * do with dots appearing in labels, the way DNS-SD
                 * does it. Refuse it for now. */

                if (memchr(buffer, '.', r))
                        return -EINVAL;

                ascii_strlower_n(buffer, (size_t) r);
                buffer[r] = '.';

                buffer += r + 1;
                c += r + 1;

                buffer_max -= r + 1;
        }

        if (c <= 0) {
                /* Not even a single label: this is the root domain name */

                assert(buffer_max > 2);
                buffer[0] = '.';
                buffer[1] = 0;

                return 1;
        }

        return (int) c;
}

static int digest_to_gcrypt_md(uint8_t algorithm) {

        /* Translates a DNSSEC digest algorithm into a gcrypt digest identifier */

        switch (algorithm) {

        case DNSSEC_DIGEST_SHA1:
                return GCRY_MD_SHA1;

        case DNSSEC_DIGEST_SHA256:
                return GCRY_MD_SHA256;

        case DNSSEC_DIGEST_SHA384:
                return GCRY_MD_SHA384;

        default:
                return -EOPNOTSUPP;
        }
}

int dnssec_verify_dnskey(DnsResourceRecord *dnskey, DnsResourceRecord *ds, bool mask_revoke) {
        char owner_name[DNSSEC_CANONICAL_HOSTNAME_MAX];
        gcry_md_hd_t md = NULL;
        size_t hash_size;
        int md_algorithm, r;
        void *result;

        assert(dnskey);
        assert(ds);

        /* Implements DNSKEY verification by a DS, according to RFC 4035, section 5.2 */

        if (dnskey->key->type != DNS_TYPE_DNSKEY)
                return -EINVAL;
        if (ds->key->type != DNS_TYPE_DS)
                return -EINVAL;
        if ((dnskey->dnskey.flags & DNSKEY_FLAG_ZONE_KEY) == 0)
                return -EKEYREJECTED;
        if (!mask_revoke && (dnskey->dnskey.flags & DNSKEY_FLAG_REVOKE))
                return -EKEYREJECTED;
        if (dnskey->dnskey.protocol != 3)
                return -EKEYREJECTED;

        if (dnskey->dnskey.algorithm != ds->ds.algorithm)
                return 0;
        if (dnssec_keytag(dnskey, mask_revoke) != ds->ds.key_tag)
                return 0;

        initialize_libgcrypt();

        md_algorithm = digest_to_gcrypt_md(ds->ds.digest_type);
        if (md_algorithm < 0)
                return md_algorithm;

        hash_size = gcry_md_get_algo_dlen(md_algorithm);
        assert(hash_size > 0);

        if (ds->ds.digest_size != hash_size)
                return 0;

        r = dnssec_canonicalize(DNS_RESOURCE_KEY_NAME(dnskey->key), owner_name, sizeof(owner_name));
        if (r < 0)
                return r;

        gcry_md_open(&md, md_algorithm, 0);
        if (!md)
                return -EIO;

        gcry_md_write(md, owner_name, r);
        if (mask_revoke)
                md_add_uint16(md, dnskey->dnskey.flags & ~DNSKEY_FLAG_REVOKE);
        else
                md_add_uint16(md, dnskey->dnskey.flags);
        md_add_uint8(md, dnskey->dnskey.protocol);
        md_add_uint8(md, dnskey->dnskey.algorithm);
        gcry_md_write(md, dnskey->dnskey.key, dnskey->dnskey.key_size);

        result = gcry_md_read(md, 0);
        if (!result) {
                r = -EIO;
                goto finish;
        }

        r = memcmp(result, ds->ds.digest, ds->ds.digest_size) != 0;

finish:
        gcry_md_close(md);
        return r;
}

int dnssec_verify_dnskey_search(DnsResourceRecord *dnskey, DnsAnswer *validated_ds) {
        DnsResourceRecord *ds;
        DnsAnswerFlags flags;
        int r;

        assert(dnskey);

        if (dnskey->key->type != DNS_TYPE_DNSKEY)
                return 0;

        DNS_ANSWER_FOREACH_FLAGS(ds, flags, validated_ds) {

                if ((flags & DNS_ANSWER_AUTHENTICATED) == 0)
                        continue;

                if (ds->key->type != DNS_TYPE_DS)
                        continue;

                if (ds->key->class != dnskey->key->class)
                        continue;

                r = dns_name_equal(DNS_RESOURCE_KEY_NAME(dnskey->key), DNS_RESOURCE_KEY_NAME(ds->key));
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = dnssec_verify_dnskey(dnskey, ds, false);
                if (r == -EKEYREJECTED)
                        return 0; /* The DNSKEY is revoked or otherwise invalid, we won't bless it */
                if (r < 0)
                        return r;
                if (r > 0)
                        return 1;
        }

        return 0;
}

static int nsec3_hash_to_gcrypt_md(uint8_t algorithm) {

        /* Translates a DNSSEC NSEC3 hash algorithm into a gcrypt digest identifier */

        switch (algorithm) {

        case NSEC3_ALGORITHM_SHA1:
                return GCRY_MD_SHA1;

        default:
                return -EOPNOTSUPP;
        }
}

int dnssec_nsec3_hash(DnsResourceRecord *nsec3, const char *name, void *ret) {
        uint8_t wire_format[DNS_WIRE_FOMAT_HOSTNAME_MAX];
        gcry_md_hd_t md = NULL;
        size_t hash_size;
        int algorithm;
        void *result;
        unsigned k;
        int r;

        assert(nsec3);
        assert(name);
        assert(ret);

        if (nsec3->key->type != DNS_TYPE_NSEC3)
                return -EINVAL;

        if (nsec3->nsec3.iterations > NSEC3_ITERATIONS_MAX) {
                log_debug("Ignoring NSEC3 RR %s with excessive number of iterations.", dns_resource_record_to_string(nsec3));
                return -EOPNOTSUPP;
        }

        algorithm = nsec3_hash_to_gcrypt_md(nsec3->nsec3.algorithm);
        if (algorithm < 0)
                return algorithm;

        initialize_libgcrypt();

        hash_size = gcry_md_get_algo_dlen(algorithm);
        assert(hash_size > 0);

        if (nsec3->nsec3.next_hashed_name_size != hash_size)
                return -EINVAL;

        r = dns_name_to_wire_format(name, wire_format, sizeof(wire_format), true);
        if (r < 0)
                return r;

        gcry_md_open(&md, algorithm, 0);
        if (!md)
                return -EIO;

        gcry_md_write(md, wire_format, r);
        gcry_md_write(md, nsec3->nsec3.salt, nsec3->nsec3.salt_size);

        result = gcry_md_read(md, 0);
        if (!result) {
                r = -EIO;
                goto finish;
        }

        for (k = 0; k < nsec3->nsec3.iterations; k++) {
                uint8_t tmp[hash_size];
                memcpy(tmp, result, hash_size);

                gcry_md_reset(md);
                gcry_md_write(md, tmp, hash_size);
                gcry_md_write(md, nsec3->nsec3.salt, nsec3->nsec3.salt_size);

                result = gcry_md_read(md, 0);
                if (!result) {
                        r = -EIO;
                        goto finish;
                }
        }

        memcpy(ret, result, hash_size);
        r = (int) hash_size;

finish:
        gcry_md_close(md);
        return r;
}

static int nsec3_is_good(DnsResourceRecord *rr, DnsResourceRecord *nsec3) {
        const char *a, *b;
        int r;

        assert(rr);

        if (rr->key->type != DNS_TYPE_NSEC3)
                return 0;

        /* RFC  5155, Section 8.2 says we MUST ignore NSEC3 RRs with flags != 0 or 1 */
        if (!IN_SET(rr->nsec3.flags, 0, 1))
                return 0;

        /* Ignore NSEC3 RRs whose algorithm we don't know */
        if (nsec3_hash_to_gcrypt_md(rr->nsec3.algorithm) < 0)
                return 0;
        /* Ignore NSEC3 RRs with an excessive number of required iterations */
        if (rr->nsec3.iterations > NSEC3_ITERATIONS_MAX)
                return 0;

        if (!nsec3)
                return 1;

        /* If a second NSEC3 RR is specified, also check if they are from the same zone. */

        if (nsec3 == rr) /* Shortcut */
                return 1;

        if (rr->key->class != nsec3->key->class)
                return 0;
        if (rr->nsec3.algorithm != nsec3->nsec3.algorithm)
                return 0;
        if (rr->nsec3.iterations != nsec3->nsec3.iterations)
                return 0;
        if (rr->nsec3.salt_size != nsec3->nsec3.salt_size)
                return 0;
        if (memcmp(rr->nsec3.salt, nsec3->nsec3.salt, rr->nsec3.salt_size) != 0)
                return 0;

        a = DNS_RESOURCE_KEY_NAME(rr->key);
        r = dns_name_parent(&a); /* strip off hash */
        if (r < 0)
                return r;
        if (r == 0)
                return 0;

        b = DNS_RESOURCE_KEY_NAME(nsec3->key);
        r = dns_name_parent(&b); /* strip off hash */
        if (r < 0)
                return r;
        if (r == 0)
                return 0;

        return dns_name_equal(a, b);
}

static int nsec3_hashed_domain_format(const uint8_t *hashed, size_t hashed_size, const char *zone, char **ret) {
        _cleanup_free_ char *l = NULL;
        char *j;

        assert(hashed);
        assert(hashed_size > 0);
        assert(zone);
        assert(ret);

        l = base32hexmem(hashed, hashed_size, false);
        if (!l)
                return -ENOMEM;

        j = strjoin(l, ".", zone, NULL);
        if (!j)
                return -ENOMEM;

        *ret = j;
        return (int) hashed_size;
}

static int nsec3_hashed_domain_make(DnsResourceRecord *nsec3, const char *domain, const char *zone, char **ret) {
        uint8_t hashed[DNSSEC_HASH_SIZE_MAX];
        int hashed_size;

        assert(nsec3);
        assert(domain);
        assert(zone);
        assert(ret);

        hashed_size = dnssec_nsec3_hash(nsec3, domain, hashed);
        if (hashed_size < 0)
                return hashed_size;

        return nsec3_hashed_domain_format(hashed, (size_t) hashed_size, zone, ret);
}

/* See RFC 5155, Section 8
 * First try to find a NSEC3 record that matches our query precisely, if that fails, find the closest
 * enclosure. Secondly, find a proof that there is no closer enclosure and either a proof that there
 * is no wildcard domain as a direct descendant of the closest enclosure, or find an NSEC3 record that
 * matches the wildcard domain.
 *
 * Based on this we can prove either the existence of the record in @key, or NXDOMAIN or NODATA, or
 * that there is no proof either way. The latter is the case if a the proof of non-existence of a given
 * name uses an NSEC3 record with the opt-out bit set. Lastly, if we are given insufficient NSEC3 records
 * to conclude anything we indicate this by returning NO_RR. */
static int dnssec_test_nsec3(DnsAnswer *answer, DnsResourceKey *key, DnssecNsecResult *result, bool *authenticated, uint32_t *ttl) {
        _cleanup_free_ char *next_closer_domain = NULL, *wildcard = NULL, *wildcard_domain = NULL;
        const char *zone, *p, *pp = NULL;
        DnsResourceRecord *rr, *enclosure_rr, *zone_rr, *wildcard_rr = NULL;
        DnsAnswerFlags flags;
        int hashed_size, r;
        bool a, no_closer = false, no_wildcard = false, optout = false;

        assert(key);
        assert(result);

        /* First step, find the zone name and the NSEC3 parameters of the zone.
         * it is sufficient to look for the longest common suffix we find with
         * any NSEC3 RR in the response. Any NSEC3 record will do as all NSEC3
         * records from a given zone in a response must use the same
         * parameters. */
        zone = DNS_RESOURCE_KEY_NAME(key);
        for (;;) {
                DNS_ANSWER_FOREACH_FLAGS(zone_rr, flags, answer) {
                        r = nsec3_is_good(zone_rr, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        r = dns_name_equal_skip(DNS_RESOURCE_KEY_NAME(zone_rr->key), 1, zone);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                goto found_zone;
                }

                /* Strip one label from the front */
                r = dns_name_parent(&zone);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
        }

        *result = DNSSEC_NSEC_NO_RR;
        return 0;

found_zone:
        /* Second step, find the closest encloser NSEC3 RR in 'answer' that matches 'key' */
        p = DNS_RESOURCE_KEY_NAME(key);
        for (;;) {
                _cleanup_free_ char *hashed_domain = NULL;

                hashed_size = nsec3_hashed_domain_make(zone_rr, p, zone, &hashed_domain);
                if (hashed_size == -EOPNOTSUPP) {
                        *result = DNSSEC_NSEC_UNSUPPORTED_ALGORITHM;
                        return 0;
                }
                if (hashed_size < 0)
                        return hashed_size;

                DNS_ANSWER_FOREACH_FLAGS(enclosure_rr, flags, answer) {

                        r = nsec3_is_good(enclosure_rr, zone_rr);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        if (enclosure_rr->nsec3.next_hashed_name_size != (size_t) hashed_size)
                                continue;

                        r = dns_name_equal(DNS_RESOURCE_KEY_NAME(enclosure_rr->key), hashed_domain);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                a = flags & DNS_ANSWER_AUTHENTICATED;
                                goto found_closest_encloser;
                        }
                }

                /* We didn't find the closest encloser with this name,
                 * but let's remember this domain name, it might be
                 * the next closer name */

                pp = p;

                /* Strip one label from the front */
                r = dns_name_parent(&p);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
        }

        *result = DNSSEC_NSEC_NO_RR;
        return 0;

found_closest_encloser:
        /* We found a closest encloser in 'p'; next closer is 'pp' */

        /* Ensure this is not a DNAME domain, see RFC5155, section 8.3. */
        if (bitmap_isset(enclosure_rr->nsec3.types, DNS_TYPE_DNAME))
                return -EBADMSG;

        /* Ensure that this data is from the delegated domain
         * (i.e. originates from the "lower" DNS server), and isn't
         * just glue records (i.e. doesn't originate from the "upper"
         * DNS server). */
        if (bitmap_isset(enclosure_rr->nsec3.types, DNS_TYPE_NS) &&
            !bitmap_isset(enclosure_rr->nsec3.types, DNS_TYPE_SOA))
                return -EBADMSG;

        if (!pp) {
                /* No next closer NSEC3 RR. That means there's a direct NSEC3 RR for our key. */
                if (bitmap_isset(enclosure_rr->nsec3.types, key->type))
                        *result = DNSSEC_NSEC_FOUND;
                else if (bitmap_isset(enclosure_rr->nsec3.types, DNS_TYPE_CNAME))
                        *result = DNSSEC_NSEC_CNAME;
                else
                        *result = DNSSEC_NSEC_NODATA;

                if (authenticated)
                        *authenticated = a;
                if (ttl)
                        *ttl = enclosure_rr->ttl;

                return 0;
        }

        /* Prove that there is no next closer and whether or not there is a wildcard domain. */

        wildcard = strappend("*.", p);
        if (!wildcard)
                return -ENOMEM;

        r = nsec3_hashed_domain_make(enclosure_rr, wildcard, zone, &wildcard_domain);
        if (r < 0)
                return r;
        if (r != hashed_size)
                return -EBADMSG;

        r = nsec3_hashed_domain_make(enclosure_rr, pp, zone, &next_closer_domain);
        if (r < 0)
                return r;
        if (r != hashed_size)
                return -EBADMSG;

        DNS_ANSWER_FOREACH_FLAGS(rr, flags, answer) {
                _cleanup_free_ char *next_hashed_domain = NULL;

                r = nsec3_is_good(rr, zone_rr);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = nsec3_hashed_domain_format(rr->nsec3.next_hashed_name, rr->nsec3.next_hashed_name_size, zone, &next_hashed_domain);
                if (r < 0)
                        return r;

                r = dns_name_between(DNS_RESOURCE_KEY_NAME(rr->key), next_closer_domain, next_hashed_domain);
                if (r < 0)
                        return r;
                if (r > 0) {
                        if (rr->nsec3.flags & 1)
                                optout = true;

                        a = a && (flags & DNS_ANSWER_AUTHENTICATED);

                        no_closer = true;
                }

                r = dns_name_equal(DNS_RESOURCE_KEY_NAME(rr->key), wildcard_domain);
                if (r < 0)
                        return r;
                if (r > 0) {
                        a = a && (flags & DNS_ANSWER_AUTHENTICATED);

                        wildcard_rr = rr;
                }

                r = dns_name_between(DNS_RESOURCE_KEY_NAME(rr->key), wildcard_domain, next_hashed_domain);
                if (r < 0)
                        return r;
                if (r > 0) {
                        if (rr->nsec3.flags & 1)
                                /* This only makes sense if we have a wildcard delegation, which is
                                 * very unlikely, see RFC 4592, Section 4.2, but we cannot rely on
                                 * this not happening, so hence cannot simply conclude NXDOMAIN as
                                 * we would wish */
                                optout = true;

                        a = a && (flags & DNS_ANSWER_AUTHENTICATED);

                        no_wildcard = true;
                }
        }

        if (wildcard_rr && no_wildcard)
                return -EBADMSG;

        if (!no_closer) {
                *result = DNSSEC_NSEC_NO_RR;
                return 0;
        }

        if (wildcard_rr) {
                /* A wildcard exists that matches our query. */
                if (optout)
                        /* This is not specified in any RFC to the best of my knowledge, but
                         * if the next closer enclosure is covered by an opt-out NSEC3 RR
                         * it means that we cannot prove that the source of synthesis is
                         * correct, as there may be a closer match. */
                        *result = DNSSEC_NSEC_OPTOUT;
                else if (bitmap_isset(wildcard_rr->nsec3.types, key->type))
                        *result = DNSSEC_NSEC_FOUND;
                else if (bitmap_isset(wildcard_rr->nsec3.types, DNS_TYPE_CNAME))
                        *result = DNSSEC_NSEC_CNAME;
                else
                        *result = DNSSEC_NSEC_NODATA;
        } else {
                if (optout)
                        /* The RFC only specifies that we have to care for optout for NODATA for
                         * DS records. However, children of an insecure opt-out delegation should
                         * also be considered opt-out, rather than verified NXDOMAIN.
                         * Note that we do not require a proof of wildcard non-existence if the
                         * next closer domain is covered by an opt-out, as that would not provide
                         * any additional information. */
                        *result = DNSSEC_NSEC_OPTOUT;
                else if (no_wildcard)
                        *result = DNSSEC_NSEC_NXDOMAIN;
                else {
                        *result = DNSSEC_NSEC_NO_RR;

                        return 0;
                }
        }

        if (authenticated)
                *authenticated = a;

        if (ttl)
                *ttl = enclosure_rr->ttl;

        return 0;
}

int dnssec_nsec_test(DnsAnswer *answer, DnsResourceKey *key, DnssecNsecResult *result, bool *authenticated, uint32_t *ttl) {
        DnsResourceRecord *rr;
        bool have_nsec3 = false;
        DnsAnswerFlags flags;
        int r;

        assert(key);
        assert(result);

        /* Look for any NSEC/NSEC3 RRs that say something about the specified key. */

        DNS_ANSWER_FOREACH_FLAGS(rr, flags, answer) {

                if (rr->key->class != key->class)
                        continue;

                switch (rr->key->type) {

                case DNS_TYPE_NSEC:

                        r = dns_name_equal(DNS_RESOURCE_KEY_NAME(rr->key), DNS_RESOURCE_KEY_NAME(key));
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                if (bitmap_isset(rr->nsec.types, key->type))
                                        *result = DNSSEC_NSEC_FOUND;
                                else if (bitmap_isset(rr->nsec.types, DNS_TYPE_CNAME))
                                        *result = DNSSEC_NSEC_CNAME;
                                else
                                        *result = DNSSEC_NSEC_NODATA;

                                if (authenticated)
                                        *authenticated = flags & DNS_ANSWER_AUTHENTICATED;
                                if (ttl)
                                        *ttl = rr->ttl;

                                return 0;
                        }

                        r = dns_name_between(DNS_RESOURCE_KEY_NAME(rr->key), DNS_RESOURCE_KEY_NAME(key), rr->nsec.next_domain_name);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                *result = DNSSEC_NSEC_NXDOMAIN;

                                if (authenticated)
                                        *authenticated = flags & DNS_ANSWER_AUTHENTICATED;
                                if (ttl)
                                        *ttl = rr->ttl;

                                return 0;
                        }
                        break;

                case DNS_TYPE_NSEC3:
                        have_nsec3 = true;
                        break;
                }
        }

        /* OK, this was not sufficient. Let's see if NSEC3 can help. */
        if (have_nsec3)
                return dnssec_test_nsec3(answer, key, result, authenticated, ttl);

        /* No approproate NSEC RR found, report this. */
        *result = DNSSEC_NSEC_NO_RR;
        return 0;
}

int dnssec_nsec_test_between(DnsAnswer *answer, const char *name, const char *zone, bool *authenticated) {
        DnsResourceRecord *rr;
        DnsAnswerFlags flags;
        int r;

        assert(name);
        assert(zone);

        /* Checks whether there's an NSEC/NSEC3 that proves that the specified 'name' is non-existing in the specified
         * 'zone'. The 'zone' must be a suffix of the 'name'. */

        DNS_ANSWER_FOREACH_FLAGS(rr, flags, answer) {
                bool found = false;

                r = dns_name_endswith(DNS_RESOURCE_KEY_NAME(rr->key), zone);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                switch (rr->key->type) {

                case DNS_TYPE_NSEC:
                        r = dns_name_between(DNS_RESOURCE_KEY_NAME(rr->key), name, rr->nsec.next_domain_name);
                        if (r < 0)
                                return r;

                        found = r > 0;
                        break;

                case DNS_TYPE_NSEC3: {
                        _cleanup_free_ char *hashed_domain = NULL, *next_hashed_domain = NULL;

                        r = nsec3_is_good(rr, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        /* Format the domain we are testing with the NSEC3 RR's hash function */
                        r = nsec3_hashed_domain_make(
                                        rr,
                                        name,
                                        zone,
                                        &hashed_domain);
                        if (r < 0)
                                return r;
                        if ((size_t) r != rr->nsec3.next_hashed_name_size)
                                break;

                        /* Format the NSEC3's next hashed name as proper domain name */
                        r = nsec3_hashed_domain_format(
                                        rr->nsec3.next_hashed_name,
                                        rr->nsec3.next_hashed_name_size,
                                        zone,
                                        &next_hashed_domain);
                        if (r < 0)
                                return r;

                        r = dns_name_between(DNS_RESOURCE_KEY_NAME(rr->key), hashed_domain, next_hashed_domain);
                        if (r < 0)
                                return r;

                        found = r > 0;
                        break;
                }

                default:
                        continue;
                }

                if (found) {
                        if (authenticated)
                                *authenticated = flags & DNS_ANSWER_AUTHENTICATED;
                        return 1;
                }
        }

        return 0;
}

static const char* const dnssec_result_table[_DNSSEC_RESULT_MAX] = {
        [DNSSEC_VALIDATED] = "validated",
        [DNSSEC_VALIDATED_WILDCARD] = "validated-wildcard",
        [DNSSEC_INVALID] = "invalid",
        [DNSSEC_SIGNATURE_EXPIRED] = "signature-expired",
        [DNSSEC_UNSUPPORTED_ALGORITHM] = "unsupported-algorithm",
        [DNSSEC_NO_SIGNATURE] = "no-signature",
        [DNSSEC_MISSING_KEY] = "missing-key",
        [DNSSEC_UNSIGNED] = "unsigned",
        [DNSSEC_FAILED_AUXILIARY] = "failed-auxiliary",
        [DNSSEC_NSEC_MISMATCH] = "nsec-mismatch",
        [DNSSEC_INCOMPATIBLE_SERVER] = "incompatible-server",
};
DEFINE_STRING_TABLE_LOOKUP(dnssec_result, DnssecResult);
