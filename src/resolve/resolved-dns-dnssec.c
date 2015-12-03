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
#include "resolved-dns-dnssec.h"
#include "resolved-dns-packet.h"

/* Open question:
 *
 * How does the DNSSEC canonical form of a hostname with a label
 * containing a dot look like, the way DNS-SD does it?
 *
 * */

#define VERIFY_RRS_MAX 256
#define MAX_KEY_SIZE (32*1024)

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

static bool dnssec_algorithm_supported(int algorithm) {
        return IN_SET(algorithm,
                      DNSSEC_ALGORITHM_RSASHA1,
                      DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1,
                      DNSSEC_ALGORITHM_RSASHA256,
                      DNSSEC_ALGORITHM_RSASHA512);
}

static bool dnssec_digest_supported(int digest) {
        return IN_SET(digest,
                      DNSSEC_DIGEST_SHA1,
                      DNSSEC_DIGEST_SHA256);
}

uint16_t dnssec_keytag(DnsResourceRecord *dnskey) {
        const uint8_t *p;
        uint32_t sum;
        size_t i;

        /* The algorithm from RFC 4034, Appendix B. */

        assert(dnskey);
        assert(dnskey->key->type == DNS_TYPE_DNSKEY);

        sum = (uint32_t) dnskey->dnskey.flags +
                ((((uint32_t) dnskey->dnskey.protocol) << 8) + (uint32_t) dnskey->dnskey.algorithm);

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

        m = MIN((*x)->wire_format_size, (*y)->wire_format_size);

        r = memcmp((*x)->wire_format, (*y)->wire_format, m);
        if (r != 0)
                return r;

        if ((*x)->wire_format_size < (*y)->wire_format_size)
                return -1;
        else if ((*x)->wire_format_size > (*y)->wire_format_size)
                return 1;

        return 0;
}

static int dnssec_rsa_verify(
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
        if (ge == GPG_ERR_BAD_SIGNATURE)
                r = 0;
        else if (ge != 0)
                r = -EIO;
        else
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

        if (inception > expiration)
                return -EKEYREJECTED;

        /* Permit a certain amount of clock skew of 10% of the valid time range */
        skew = (expiration - inception) / 10;

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

int dnssec_verify_rrset(
                DnsAnswer *a,
                DnsResourceKey *key,
                DnsResourceRecord *rrsig,
                DnsResourceRecord *dnskey,
                usec_t realtime) {

        uint8_t wire_format_name[DNS_WIRE_FOMAT_HOSTNAME_MAX];
        size_t exponent_size, modulus_size, hash_size;
        void *exponent, *modulus, *hash;
        DnsResourceRecord **list, *rr;
        gcry_md_hd_t md = NULL;
        size_t k, n = 0;
        int r;

        assert(key);
        assert(rrsig);
        assert(dnskey);
        assert(rrsig->key->type == DNS_TYPE_RRSIG);
        assert(dnskey->key->type == DNS_TYPE_DNSKEY);

        /* Verifies the the RRSet matching the specified "key" in "a",
         * using the signature "rrsig" and the key "dnskey". It's
         * assumed the RRSIG and DNSKEY match. */

        if (!dnssec_algorithm_supported(rrsig->rrsig.algorithm))
                return -EOPNOTSUPP;

        if (a->n_rrs > VERIFY_RRS_MAX)
                return -E2BIG;

        r = dnssec_rrsig_expired(rrsig, realtime);
        if (r < 0)
                return r;
        if (r > 0)
                return DNSSEC_SIGNATURE_EXPIRED;

        /* Collect all relevant RRs in a single array, so that we can look at the RRset */
        list = newa(DnsResourceRecord *, a->n_rrs);

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
        }

        if (n <= 0)
                return -ENODATA;

        /* Bring the RRs into canonical order */
        qsort_safe(list, n, sizeof(DnsResourceRecord), rr_compare);

        /* OK, the RRs are now in canonical order. Let's calculate the digest */
        switch (rrsig->rrsig.algorithm) {

        case DNSSEC_ALGORITHM_RSASHA1:
        case DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1:
                gcry_md_open(&md, GCRY_MD_SHA1, 0);
                hash_size = 20;
                break;

        case DNSSEC_ALGORITHM_RSASHA256:
                gcry_md_open(&md, GCRY_MD_SHA256, 0);
                hash_size = 32;
                break;

        case DNSSEC_ALGORITHM_RSASHA512:
                gcry_md_open(&md, GCRY_MD_SHA512, 0);
                hash_size = 64;
                break;

        default:
                assert_not_reached("Unknown digest");
        }

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
                size_t l;
                rr = list[k];

                r = dns_name_to_wire_format(DNS_RESOURCE_KEY_NAME(rr->key), wire_format_name, sizeof(wire_format_name), true);
                if (r < 0)
                        goto finish;
                gcry_md_write(md, wire_format_name, r);

                md_add_uint16(md, rr->key->type);
                md_add_uint16(md, rr->key->class);
                md_add_uint32(md, rrsig->rrsig.original_ttl);

                assert(rr->wire_format_rdata_offset <= rr->wire_format_size);
                l = rr->wire_format_size - rr->wire_format_rdata_offset;
                assert(l <= 0xFFFF);

                md_add_uint16(md, (uint16_t) l);
                gcry_md_write(md, (uint8_t*) rr->wire_format + rr->wire_format_rdata_offset, l);
        }

        hash = gcry_md_read(md, 0);
        if (!hash) {
                r = -EIO;
                goto finish;
        }

        if (*(uint8_t*) dnskey->dnskey.key == 0) {
                /* exponent is > 255 bytes long */

                exponent = (uint8_t*) dnskey->dnskey.key + 3;
                exponent_size =
                        ((size_t) (((uint8_t*) dnskey->dnskey.key)[0]) << 8) |
                        ((size_t) ((uint8_t*) dnskey->dnskey.key)[1]);

                if (exponent_size < 256) {
                        r = -EINVAL;
                        goto finish;
                }

                if (3 + exponent_size >= dnskey->dnskey.key_size) {
                        r = -EINVAL;
                        goto finish;
                }

                modulus = (uint8_t*) dnskey->dnskey.key + 3 + exponent_size;
                modulus_size = dnskey->dnskey.key_size - 3 - exponent_size;

        } else {
                /* exponent is <= 255 bytes long */

                exponent = (uint8_t*) dnskey->dnskey.key + 1;
                exponent_size = (size_t) ((uint8_t*) dnskey->dnskey.key)[0];

                if (exponent_size <= 0) {
                        r = -EINVAL;
                        goto finish;
                }

                if (1 + exponent_size >= dnskey->dnskey.key_size) {
                        r = -EINVAL;
                        goto finish;
                }

                modulus = (uint8_t*) dnskey->dnskey.key + 1 + exponent_size;
                modulus_size = dnskey->dnskey.key_size - 1 - exponent_size;
        }

        r = dnssec_rsa_verify(
                        gcry_md_algo_name(gcry_md_get_algo(md)),
                        rrsig->rrsig.signature, rrsig->rrsig.signature_size,
                        hash, hash_size,
                        exponent, exponent_size,
                        modulus, modulus_size);
        if (r < 0)
                goto finish;

        r = r ? DNSSEC_VERIFIED : DNSSEC_INVALID;

finish:
        gcry_md_close(md);
        return r;
}

int dnssec_rrsig_match_dnskey(DnsResourceRecord *rrsig, DnsResourceRecord *dnskey) {

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
        if (dnskey->dnskey.protocol != 3)
                return 0;
        if (dnskey->dnskey.algorithm != rrsig->rrsig.algorithm)
                return 0;

        if (dnssec_keytag(dnskey) != rrsig->rrsig.key_tag)
                return 0;

        return dns_name_equal(DNS_RESOURCE_KEY_NAME(dnskey->key), DNS_RESOURCE_KEY_NAME(rrsig->key));
}

int dnssec_key_match_rrsig(DnsResourceKey *key, DnsResourceRecord *rrsig) {
        assert(key);
        assert(rrsig);

        /* Checks if the specified RRSIG RR protects the RRSet of the specified RR key. */

        if (rrsig->key->type != DNS_TYPE_RRSIG)
                return 0;
        if (rrsig->key->class != key->class)
                return 0;
        if (rrsig->rrsig.type_covered != key->type)
                return 0;

        return dns_name_equal(DNS_RESOURCE_KEY_NAME(rrsig->key), DNS_RESOURCE_KEY_NAME(key));
}

int dnssec_verify_rrset_search(
                DnsAnswer *a,
                DnsResourceKey *key,
                DnsAnswer *validated_dnskeys,
                usec_t realtime) {

        bool found_rrsig = false, found_dnskey = false;
        DnsResourceRecord *rrsig;
        int r;

        assert(key);

        /* Verifies all RRs from "a" that match the key "key", against DNSKEY RRs in "validated_dnskeys" */

        if (!a || a->n_rrs <= 0)
                return -ENODATA;

        /* Iterate through each RRSIG RR. */
        DNS_ANSWER_FOREACH(rrsig, a) {
                DnsResourceRecord *dnskey;

                r = dnssec_key_match_rrsig(key, rrsig);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                found_rrsig = true;

                DNS_ANSWER_FOREACH(dnskey, validated_dnskeys) {

                        r = dnssec_rrsig_match_dnskey(rrsig, dnskey);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        found_dnskey = true;

                        /* Take the time here, if it isn't set yet, so
                         * that we do all validations with the same
                         * time. */
                        if (realtime == USEC_INFINITY)
                                realtime = now(CLOCK_REALTIME);

                        /* Yay, we found a matching RRSIG with a matching
                         * DNSKEY, awesome. Now let's verify all entries of
                         * the RRSet against the RRSIG and DNSKEY
                         * combination. */

                        r = dnssec_verify_rrset(a, key, rrsig, dnskey, realtime);
                        if (r < 0 && r != EOPNOTSUPP)
                                return r;
                        if (r == DNSSEC_VERIFIED)
                                return DNSSEC_VERIFIED;

                        /* If the signature is invalid, or done using
                           an unsupported algorithm, let's try another
                           key and/or signature. After all they
                           key_tags and stuff are not unique, and
                           might be shared by multiple keys. */
                }
        }

        if (found_dnskey)
                return DNSSEC_INVALID;

        if (found_rrsig)
                return DNSSEC_MISSING_KEY;

        return DNSSEC_NO_SIGNATURE;
}

int dnssec_canonicalize(const char *n, char *buffer, size_t buffer_max) {
        _cleanup_free_ char *s = NULL;
        size_t c = 0;
        int r;

        /* Converts the specified hostname into DNSSEC canonicalized
         * form. */

        if (buffer_max < 2)
                return -ENOBUFS;

        for (;;) {
                size_t i;

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

                for (i = 0; i < (size_t) r; i ++) {
                        if (buffer[i] >= 'A' && buffer[i] <= 'Z')
                                buffer[i] = buffer[i] - 'A' + 'a';
                }

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

int dnssec_verify_dnskey(DnsResourceRecord *dnskey, DnsResourceRecord *ds) {
        gcry_md_hd_t md = NULL;
        char owner_name[DNSSEC_CANONICAL_HOSTNAME_MAX];
        void *result;
        int r;

        assert(dnskey);
        assert(ds);

        /* Implements DNSKEY verification by a DS, according to RFC 4035, section 5.2 */

        if (dnskey->key->type != DNS_TYPE_DNSKEY)
                return -EINVAL;
        if (ds->key->type != DNS_TYPE_DS)
                return -EINVAL;
        if ((dnskey->dnskey.flags & DNSKEY_FLAG_ZONE_KEY) == 0)
                return -EKEYREJECTED;
        if (dnskey->dnskey.protocol != 3)
                return -EKEYREJECTED;

        if (!dnssec_algorithm_supported(dnskey->dnskey.algorithm))
                return -EOPNOTSUPP;
        if (!dnssec_digest_supported(ds->ds.digest_type))
                return -EOPNOTSUPP;

        if (dnskey->dnskey.algorithm != ds->ds.algorithm)
                return 0;
        if (dnssec_keytag(dnskey) != ds->ds.key_tag)
                return 0;

        switch (ds->ds.digest_type) {

        case DNSSEC_DIGEST_SHA1:

                if (ds->ds.digest_size != 20)
                        return 0;

                gcry_md_open(&md, GCRY_MD_SHA1, 0);
                break;

        case DNSSEC_DIGEST_SHA256:

                if (ds->ds.digest_size != 32)
                        return 0;

                gcry_md_open(&md, GCRY_MD_SHA256, 0);
                break;

        default:
                assert_not_reached("Unknown digest");
        }

        if (!md)
                return -EIO;

        r = dnssec_canonicalize(DNS_RESOURCE_KEY_NAME(dnskey->key), owner_name, sizeof(owner_name));
        if (r < 0)
                goto finish;

        gcry_md_write(md, owner_name, r);
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
