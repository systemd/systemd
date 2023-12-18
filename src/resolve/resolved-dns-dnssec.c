/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "fileio.h"
#include "gcrypt-util.h"
#include "hexdecoct.h"
#include "memory-util.h"
#include "memstream-util.h"
#include "openssl-util.h"
#include "resolved-dns-dnssec.h"
#include "resolved-dns-packet.h"
#include "sort-util.h"
#include "string-table.h"

#if PREFER_OPENSSL && OPENSSL_VERSION_MAJOR >= 3
#  pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wdeprecated-declarations"
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(RSA*, RSA_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EC_KEY*, EC_KEY_free, NULL);
#  pragma GCC diagnostic pop
#endif

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

uint16_t dnssec_keytag(DnsResourceRecord *dnskey, bool mask_revoke) {
        const uint8_t *p;
        uint32_t sum, f;

        /* The algorithm from RFC 4034, Appendix B. */

        assert(dnskey);
        assert(dnskey->key->type == DNS_TYPE_DNSKEY);

        f = (uint32_t) dnskey->dnskey.flags;

        if (mask_revoke)
                f &= ~DNSKEY_FLAG_REVOKE;

        sum = f + ((((uint32_t) dnskey->dnskey.protocol) << 8) + (uint32_t) dnskey->dnskey.algorithm);

        p = dnskey->dnskey.key;

        for (size_t i = 0; i < dnskey->dnskey.key_size; i++)
                sum += (i & 1) == 0 ? (uint32_t) p[i] << 8 : (uint32_t) p[i];

        sum += (sum >> 16) & UINT32_C(0xFFFF);

        return sum & UINT32_C(0xFFFF);
}

#if HAVE_OPENSSL_OR_GCRYPT

static int rr_compare(DnsResourceRecord * const *a, DnsResourceRecord * const *b) {
        const DnsResourceRecord *x = *a, *y = *b;
        size_t m;
        int r;

        /* Let's order the RRs according to RFC 4034, Section 6.3 */

        assert(x);
        assert(x->wire_format);
        assert(y);
        assert(y->wire_format);

        m = MIN(DNS_RESOURCE_RECORD_RDATA_SIZE(x), DNS_RESOURCE_RECORD_RDATA_SIZE(y));

        r = memcmp(DNS_RESOURCE_RECORD_RDATA(x), DNS_RESOURCE_RECORD_RDATA(y), m);
        if (r != 0)
                return r;

        return CMP(DNS_RESOURCE_RECORD_RDATA_SIZE(x), DNS_RESOURCE_RECORD_RDATA_SIZE(y));
}

static int dnssec_rsa_verify_raw(
                hash_algorithm_t hash_algorithm,
                const void *signature, size_t signature_size,
                const void *data, size_t data_size,
                const void *exponent, size_t exponent_size,
                const void *modulus, size_t modulus_size) {
        int r;

#if PREFER_OPENSSL
#  pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        _cleanup_(RSA_freep) RSA *rpubkey = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *epubkey = NULL;
        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = NULL;
        _cleanup_(BN_freep) BIGNUM *e = NULL, *m = NULL;

        assert(hash_algorithm);

        e = BN_bin2bn(exponent, exponent_size, NULL);
        if (!e)
                return -EIO;

        m = BN_bin2bn(modulus, modulus_size, NULL);
        if (!m)
                return -EIO;

        rpubkey = RSA_new();
        if (!rpubkey)
                return -ENOMEM;

        if (RSA_set0_key(rpubkey, m, e, NULL) <= 0)
                return -EIO;
        e = m = NULL;

        assert((size_t) RSA_size(rpubkey) == signature_size);

        epubkey = EVP_PKEY_new();
        if (!epubkey)
                return -ENOMEM;

        if (EVP_PKEY_assign_RSA(epubkey, RSAPublicKey_dup(rpubkey)) <= 0)
                return -EIO;

        ctx = EVP_PKEY_CTX_new(epubkey, NULL);
        if (!ctx)
                return -ENOMEM;

        if (EVP_PKEY_verify_init(ctx) <= 0)
                return -EIO;

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
                return -EIO;

        if (EVP_PKEY_CTX_set_signature_md(ctx, hash_algorithm) <= 0)
                return -EIO;

        r = EVP_PKEY_verify(ctx, signature, signature_size, data, data_size);
        if (r < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                       "Signature verification failed: 0x%lx", ERR_get_error());

#  pragma GCC diagnostic pop
#else
        gcry_sexp_t public_key_sexp = NULL, data_sexp = NULL, signature_sexp = NULL;
        gcry_mpi_t n = NULL, e = NULL, s = NULL;
        gcry_error_t ge;

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
        else if (ge != 0)
                r = log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                    "RSA signature check failed: %s", gpg_strerror(ge));
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
#endif
        return r;
}

static int dnssec_rsa_verify(
                hash_algorithm_t hash_algorithm,
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
                hash_algorithm_t hash_algorithm,
                elliptic_curve_t curve,
                const void *signature_r, size_t signature_r_size,
                const void *signature_s, size_t signature_s_size,
                const void *data, size_t data_size,
                const void *key, size_t key_size) {
        int k;

#if PREFER_OPENSSL
#  pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        _cleanup_(EC_GROUP_freep) EC_GROUP *ec_group = NULL;
        _cleanup_(EC_POINT_freep) EC_POINT *p = NULL;
        _cleanup_(EC_KEY_freep) EC_KEY *eckey = NULL;
        _cleanup_(BN_CTX_freep) BN_CTX *bctx = NULL;
        _cleanup_(BN_freep) BIGNUM *r = NULL, *s = NULL;
        _cleanup_(ECDSA_SIG_freep) ECDSA_SIG *sig = NULL;

        assert(hash_algorithm);

        ec_group = EC_GROUP_new_by_curve_name(curve);
        if (!ec_group)
                return -ENOMEM;

        p = EC_POINT_new(ec_group);
        if (!p)
                return -ENOMEM;

        bctx = BN_CTX_new();
        if (!bctx)
                return -ENOMEM;

        if (EC_POINT_oct2point(ec_group, p, key, key_size, bctx) <= 0)
                return -EIO;

        eckey = EC_KEY_new();
        if (!eckey)
                return -ENOMEM;

        if (EC_KEY_set_group(eckey, ec_group) <= 0)
                return -EIO;

        if (EC_KEY_set_public_key(eckey, p) <= 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                       "EC_POINT_bn2point failed: 0x%lx", ERR_get_error());

        assert(EC_KEY_check_key(eckey) == 1);

        r = BN_bin2bn(signature_r, signature_r_size, NULL);
        if (!r)
                return -EIO;

        s = BN_bin2bn(signature_s, signature_s_size, NULL);
        if (!s)
                return -EIO;

        /* TODO: We should eventually use the EVP API once it supports ECDSA signature verification */

        sig = ECDSA_SIG_new();
        if (!sig)
                return -ENOMEM;

        if (ECDSA_SIG_set0(sig, r, s) <= 0)
                return -EIO;
        r = s = NULL;

        k = ECDSA_do_verify(data, data_size, sig, eckey);
        if (k < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                       "Signature verification failed: 0x%lx", ERR_get_error());

#  pragma GCC diagnostic pop
#else
        gcry_sexp_t public_key_sexp = NULL, data_sexp = NULL, signature_sexp = NULL;
        gcry_mpi_t q = NULL, r = NULL, s = NULL;
        gcry_error_t ge;

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
#endif
        return k;
}

static int dnssec_ecdsa_verify(
                hash_algorithm_t hash_algorithm,
                int algorithm,
                const void *hash, size_t hash_size,
                DnsResourceRecord *rrsig,
                DnsResourceRecord *dnskey) {

        elliptic_curve_t curve;
        size_t key_size;
        uint8_t *q;

        assert(hash);
        assert(hash_size);
        assert(rrsig);
        assert(dnskey);

        if (algorithm == DNSSEC_ALGORITHM_ECDSAP256SHA256) {
                curve = OPENSSL_OR_GCRYPT(NID_X9_62_prime256v1, "NIST P-256");  /* NIST P-256 */
                key_size = 32;
        } else if (algorithm == DNSSEC_ALGORITHM_ECDSAP384SHA384) {
                curve = OPENSSL_OR_GCRYPT(NID_secp384r1, "NIST P-384");         /* NIST P-384 */
                key_size = 48;
        } else
                return -EOPNOTSUPP;

        if (dnskey->dnskey.key_size != key_size * 2)
                return -EINVAL;

        if (rrsig->rrsig.signature_size != key_size * 2)
                return -EINVAL;

        q = newa(uint8_t, key_size*2 + 1);
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

static int dnssec_eddsa_verify_raw(
                elliptic_curve_t curve,
                const uint8_t *signature, size_t signature_size,
                const uint8_t *data, size_t data_size,
                const uint8_t *key, size_t key_size) {

#if PREFER_OPENSSL
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *evkey = NULL;
        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *pctx = NULL;
        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *ctx = NULL;
        int r;

        assert(curve == NID_ED25519);
        assert(signature_size == key_size * 2);

        uint8_t *q = newa(uint8_t, signature_size + 1);
        q[0] = 0x04; /* Prepend 0x04 to indicate an uncompressed key */
        memcpy(q+1, signature, signature_size);

        evkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key, key_size);
        if (!evkey)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                       "EVP_PKEY_new_raw_public_key failed: 0x%lx", ERR_get_error());

        pctx = EVP_PKEY_CTX_new(evkey, NULL);
        if (!pctx)
                return -ENOMEM;

        ctx = EVP_MD_CTX_new();
        if (!ctx)
                return -ENOMEM;

        /* This prevents EVP_DigestVerifyInit from managing pctx and complicating our free logic. */
        EVP_MD_CTX_set_pkey_ctx(ctx, pctx);

        /* One might be tempted to use EVP_PKEY_verify_init, but see Ed25519(7ssl). */
        if (EVP_DigestVerifyInit(ctx, &pctx, NULL, NULL, evkey) <= 0)
                return -EIO;

        r = EVP_DigestVerify(ctx, signature, signature_size, data, data_size);
        if (r < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                       "Signature verification failed: 0x%lx", ERR_get_error());

        return r;

#elif GCRYPT_VERSION_NUMBER >= 0x010600
        gcry_sexp_t public_key_sexp = NULL, data_sexp = NULL, signature_sexp = NULL;
        gcry_error_t ge;
        int k;

        assert(signature_size == key_size * 2);

        ge = gcry_sexp_build(&signature_sexp,
                             NULL,
                             "(sig-val (eddsa (r %b) (s %b)))",
                             (int) key_size,
                             signature,
                             (int) key_size,
                             signature + key_size);
        if (ge != 0) {
                k = -EIO;
                goto finish;
        }

        ge = gcry_sexp_build(&data_sexp,
                             NULL,
                             "(data (flags eddsa) (hash-algo sha512) (value %b))",
                             (int) data_size,
                             data);
        if (ge != 0) {
                k = -EIO;
                goto finish;
        }

        ge = gcry_sexp_build(&public_key_sexp,
                             NULL,
                             "(public-key (ecc (curve %s) (flags eddsa) (q %b)))",
                             curve,
                             (int) key_size,
                             key);
        if (ge != 0) {
                k = -EIO;
                goto finish;
        }

        ge = gcry_pk_verify(signature_sexp, data_sexp, public_key_sexp);
        if (gpg_err_code(ge) == GPG_ERR_BAD_SIGNATURE)
                k = 0;
        else if (ge != 0)
                k = log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                    "EdDSA signature check failed: %s", gpg_strerror(ge));
        else
                k = 1;
finish:
        if (public_key_sexp)
                gcry_sexp_release(public_key_sexp);
        if (signature_sexp)
                gcry_sexp_release(signature_sexp);
        if (data_sexp)
                gcry_sexp_release(data_sexp);

        return k;
#else
        return -EOPNOTSUPP;
#endif
}

static int dnssec_eddsa_verify(
                int algorithm,
                const void *data, size_t data_size,
                DnsResourceRecord *rrsig,
                DnsResourceRecord *dnskey) {
        elliptic_curve_t curve;
        size_t key_size;

        if (algorithm == DNSSEC_ALGORITHM_ED25519) {
                curve = OPENSSL_OR_GCRYPT(NID_ED25519, "Ed25519");
                key_size = 32;
        } else
                return -EOPNOTSUPP;

        if (dnskey->dnskey.key_size != key_size)
                return -EINVAL;

        if (rrsig->rrsig.signature_size != key_size * 2)
                return -EINVAL;

        return dnssec_eddsa_verify_raw(
                        curve,
                        rrsig->rrsig.signature, rrsig->rrsig.signature_size,
                        data, data_size,
                        dnskey->dnskey.key, key_size);
}

static int md_add_uint8(hash_context_t ctx, uint8_t v) {
#if PREFER_OPENSSL
        return EVP_DigestUpdate(ctx, &v, sizeof(v));
#else
        gcry_md_write(ctx, &v, sizeof(v));
        return 0;
#endif
}

static int md_add_uint16(hash_context_t ctx, uint16_t v) {
        v = htobe16(v);
#if PREFER_OPENSSL
        return EVP_DigestUpdate(ctx, &v, sizeof(v));
#else
        gcry_md_write(ctx, &v, sizeof(v));
        return 0;
#endif
}

static void fwrite_uint8(FILE *fp, uint8_t v) {
        fwrite(&v, sizeof(v), 1, fp);
}

static void fwrite_uint16(FILE *fp, uint16_t v) {
        v = htobe16(v);
        fwrite(&v, sizeof(v), 1, fp);
}

static void fwrite_uint32(FILE *fp, uint32_t v) {
        v = htobe32(v);
        fwrite(&v, sizeof(v), 1, fp);
}

static int dnssec_rrsig_prepare(DnsResourceRecord *rrsig) {
        int n_key_labels, n_signer_labels;
        const char *name;
        int r;

        /* Checks whether the specified RRSIG RR is somewhat valid, and initializes the .n_skip_labels_source
         * and .n_skip_labels_signer fields so that we can use them later on. */

        assert(rrsig);
        assert(rrsig->key->type == DNS_TYPE_RRSIG);

        /* Check if this RRSIG RR is already prepared */
        if (rrsig->n_skip_labels_source != UINT8_MAX)
                return 0;

        if (rrsig->rrsig.inception > rrsig->rrsig.expiration)
                return -EINVAL;

        name = dns_resource_key_name(rrsig->key);

        n_key_labels = dns_name_count_labels(name);
        if (n_key_labels < 0)
                return n_key_labels;
        if (rrsig->rrsig.labels > n_key_labels)
                return -EINVAL;

        n_signer_labels = dns_name_count_labels(rrsig->rrsig.signer);
        if (n_signer_labels < 0)
                return n_signer_labels;
        if (n_signer_labels > rrsig->rrsig.labels)
                return -EINVAL;

        r = dns_name_skip(name, n_key_labels - n_signer_labels, &name);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        /* Check if the signer is really a suffix of us */
        r = dns_name_equal(name, rrsig->rrsig.signer);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        assert(n_key_labels < UINT8_MAX); /* UINT8_MAX/-1 means unsigned. */
        rrsig->n_skip_labels_source = n_key_labels - rrsig->rrsig.labels;
        rrsig->n_skip_labels_signer = n_key_labels - n_signer_labels;

        return 0;
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

static hash_md_t algorithm_to_implementation_id(uint8_t algorithm) {

        /* Translates a DNSSEC signature algorithm into an openssl/gcrypt digest identifier.
         *
         * Note that we implement all algorithms listed as "Must implement" and "Recommended to Implement" in
         * RFC6944. We don't implement any algorithms that are listed as "Optional" or "Must Not Implement".
         * Specifically, we do not implement RSAMD5, DSASHA1, DH, DSA-NSEC3-SHA1, and GOST-ECC. */

        switch (algorithm) {

        case DNSSEC_ALGORITHM_RSASHA1:
        case DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1:
                return OPENSSL_OR_GCRYPT(EVP_sha1(), GCRY_MD_SHA1);

        case DNSSEC_ALGORITHM_RSASHA256:
        case DNSSEC_ALGORITHM_ECDSAP256SHA256:
                return OPENSSL_OR_GCRYPT(EVP_sha256(), GCRY_MD_SHA256);

        case DNSSEC_ALGORITHM_ECDSAP384SHA384:
                return OPENSSL_OR_GCRYPT(EVP_sha384(), GCRY_MD_SHA384);

        case DNSSEC_ALGORITHM_RSASHA512:
                return OPENSSL_OR_GCRYPT(EVP_sha512(), GCRY_MD_SHA512);

        default:
                return OPENSSL_OR_GCRYPT(NULL, -EOPNOTSUPP);
        }
}

static void dnssec_fix_rrset_ttl(
                DnsResourceRecord *list[],
                unsigned n,
                DnsResourceRecord *rrsig) {

        assert(list);
        assert(n > 0);
        assert(rrsig);

        for (unsigned k = 0; k < n; k++) {
                DnsResourceRecord *rr = list[k];

                /* Pick the TTL as the minimum of the RR's TTL, the
                 * RR's original TTL according to the RRSIG and the
                 * RRSIG's own TTL, see RFC 4035, Section 5.3.3 */
                rr->ttl = MIN3(rr->ttl, rrsig->rrsig.original_ttl, rrsig->ttl);
                rr->expiry = rrsig->rrsig.expiration * USEC_PER_SEC;

                /* Copy over information about the signer and wildcard source of synthesis */
                rr->n_skip_labels_source = rrsig->n_skip_labels_source;
                rr->n_skip_labels_signer = rrsig->n_skip_labels_signer;
        }

        rrsig->expiry = rrsig->rrsig.expiration * USEC_PER_SEC;
}

static int dnssec_rrset_serialize_sig(
                DnsResourceRecord *rrsig,
                const char *source,
                DnsResourceRecord **list,
                size_t list_len,
                bool wildcard,
                char **ret_sig_data,
                size_t *ret_sig_size) {

        _cleanup_(memstream_done) MemStream m = {};
        uint8_t wire_format_name[DNS_WIRE_FORMAT_HOSTNAME_MAX];
        DnsResourceRecord *rr;
        FILE *f;
        int r;

        assert(rrsig);
        assert(source);
        assert(list || list_len == 0);
        assert(ret_sig_data);
        assert(ret_sig_size);

        f = memstream_init(&m);
        if (!f)
                return -ENOMEM;

        fwrite_uint16(f, rrsig->rrsig.type_covered);
        fwrite_uint8(f, rrsig->rrsig.algorithm);
        fwrite_uint8(f, rrsig->rrsig.labels);
        fwrite_uint32(f, rrsig->rrsig.original_ttl);
        fwrite_uint32(f, rrsig->rrsig.expiration);
        fwrite_uint32(f, rrsig->rrsig.inception);
        fwrite_uint16(f, rrsig->rrsig.key_tag);

        r = dns_name_to_wire_format(rrsig->rrsig.signer, wire_format_name, sizeof(wire_format_name), true);
        if (r < 0)
                return r;
        fwrite(wire_format_name, 1, r, f);

        /* Convert the source of synthesis into wire format */
        r = dns_name_to_wire_format(source, wire_format_name, sizeof(wire_format_name), true);
        if (r < 0)
                return r;

        for (size_t k = 0; k < list_len; k++) {
                size_t l;

                rr = list[k];

                /* Hash the source of synthesis. If this is a wildcard, then prefix it with the *. label */
                if (wildcard)
                        fwrite((uint8_t[]) { 1, '*'}, sizeof(uint8_t), 2, f);
                fwrite(wire_format_name, 1, r, f);

                fwrite_uint16(f, rr->key->type);
                fwrite_uint16(f, rr->key->class);
                fwrite_uint32(f, rrsig->rrsig.original_ttl);

                l = DNS_RESOURCE_RECORD_RDATA_SIZE(rr);
                assert(l <= 0xFFFF);

                fwrite_uint16(f, (uint16_t) l);
                fwrite(DNS_RESOURCE_RECORD_RDATA(rr), 1, l, f);
        }

        return memstream_finalize(&m, ret_sig_data, ret_sig_size);
}

static int dnssec_rrset_verify_sig(
                DnsResourceRecord *rrsig,
                DnsResourceRecord *dnskey,
                const char *sig_data,
                size_t sig_size) {

        assert(rrsig);
        assert(dnskey);
        assert(sig_data);
        assert(sig_size > 0);

        hash_md_t md_algorithm;

#if PREFER_OPENSSL
        uint8_t hash[EVP_MAX_MD_SIZE];
        unsigned hash_size;
#else
        _cleanup_(gcry_md_closep) gcry_md_hd_t md = NULL;
        void *hash;
        size_t hash_size;

        initialize_libgcrypt(false);
#endif

        switch (rrsig->rrsig.algorithm) {
        case DNSSEC_ALGORITHM_ED25519:
#if PREFER_OPENSSL || GCRYPT_VERSION_NUMBER >= 0x010600
                return dnssec_eddsa_verify(
                                rrsig->rrsig.algorithm,
                                sig_data, sig_size,
                                rrsig,
                                dnskey);
#endif
        case DNSSEC_ALGORITHM_ED448:
                return -EOPNOTSUPP;
        default:
                /* OK, the RRs are now in canonical order. Let's calculate the digest */
                md_algorithm = algorithm_to_implementation_id(rrsig->rrsig.algorithm);
#if PREFER_OPENSSL
                if (!md_algorithm)
                        return -EOPNOTSUPP;

                _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *ctx = EVP_MD_CTX_new();
                if (!ctx)
                        return -ENOMEM;

                if (EVP_DigestInit_ex(ctx, md_algorithm, NULL) <= 0)
                        return -EIO;

                if (EVP_DigestUpdate(ctx, sig_data, sig_size) <= 0)
                        return -EIO;

                if (EVP_DigestFinal_ex(ctx, hash, &hash_size) <= 0)
                        return -EIO;

                assert(hash_size > 0);

#else
                if (md_algorithm < 0)
                        return md_algorithm;

                gcry_error_t err = gcry_md_open(&md, md_algorithm, 0);
                if (gcry_err_code(err) != GPG_ERR_NO_ERROR || !md)
                        return -EIO;

                hash_size = gcry_md_get_algo_dlen(md_algorithm);
                assert(hash_size > 0);

                gcry_md_write(md, sig_data, sig_size);

                hash = gcry_md_read(md, 0);
                if (!hash)
                        return -EIO;
#endif
        }

        switch (rrsig->rrsig.algorithm) {

        case DNSSEC_ALGORITHM_RSASHA1:
        case DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1:
        case DNSSEC_ALGORITHM_RSASHA256:
        case DNSSEC_ALGORITHM_RSASHA512:
                return dnssec_rsa_verify(
                                OPENSSL_OR_GCRYPT(md_algorithm, gcry_md_algo_name(md_algorithm)),
                                hash, hash_size,
                                rrsig,
                                dnskey);

        case DNSSEC_ALGORITHM_ECDSAP256SHA256:
        case DNSSEC_ALGORITHM_ECDSAP384SHA384:
                return dnssec_ecdsa_verify(
                                OPENSSL_OR_GCRYPT(md_algorithm, gcry_md_algo_name(md_algorithm)),
                                rrsig->rrsig.algorithm,
                                hash, hash_size,
                                rrsig,
                                dnskey);

        default:
                assert_not_reached();
        }
}

int dnssec_verify_rrset(
                DnsAnswer *a,
                const DnsResourceKey *key,
                DnsResourceRecord *rrsig,
                DnsResourceRecord *dnskey,
                usec_t realtime,
                DnssecResult *result) {

        DnsResourceRecord **list, *rr;
        const char *source, *name;
        _cleanup_free_ char *sig_data = NULL;
        size_t sig_size = 0; /* avoid false maybe-uninitialized warning */
        size_t n = 0;
        bool wildcard;
        int r;

        assert(key);
        assert(rrsig);
        assert(dnskey);
        assert(result);
        assert(rrsig->key->type == DNS_TYPE_RRSIG);
        assert(dnskey->key->type == DNS_TYPE_DNSKEY);

        /* Verifies that the RRSet matches the specified "key" in "a",
         * using the signature "rrsig" and the key "dnskey". It's
         * assumed that RRSIG and DNSKEY match. */

        r = dnssec_rrsig_prepare(rrsig);
        if (r == -EINVAL) {
                *result = DNSSEC_INVALID;
                return r;
        }
        if (r < 0)
                return r;

        r = dnssec_rrsig_expired(rrsig, realtime);
        if (r < 0)
                return r;
        if (r > 0) {
                *result = DNSSEC_SIGNATURE_EXPIRED;
                return 0;
        }

        name = dns_resource_key_name(key);

        /* Some keys may only appear signed in the zone apex, and are invalid anywhere else. (SOA, NS...) */
        if (dns_type_apex_only(rrsig->rrsig.type_covered)) {
                r = dns_name_equal(rrsig->rrsig.signer, name);
                if (r < 0)
                        return r;
                if (r == 0) {
                        *result = DNSSEC_INVALID;
                        return 0;
                }
        }

        /* OTOH DS RRs may not appear in the zone apex, but are valid everywhere else. */
        if (rrsig->rrsig.type_covered == DNS_TYPE_DS) {
                r = dns_name_equal(rrsig->rrsig.signer, name);
                if (r < 0)
                        return r;
                if (r > 0) {
                        *result = DNSSEC_INVALID;
                        return 0;
                }
        }

        /* Determine the "Source of Synthesis" and whether this is a wildcard RRSIG */
        r = dns_name_suffix(name, rrsig->rrsig.labels, &source);
        if (r < 0)
                return r;
        if (r > 0 && !dns_type_may_wildcard(rrsig->rrsig.type_covered)) {
                /* We refuse to validate NSEC3 or SOA RRs that are synthesized from wildcards */
                *result = DNSSEC_INVALID;
                return 0;
        }
        if (r == 1) {
                /* If we stripped a single label, then let's see if that maybe was "*". If so, we are not really
                 * synthesized from a wildcard, we are the wildcard itself. Treat that like a normal name. */
                r = dns_name_startswith(name, "*");
                if (r < 0)
                        return r;
                if (r > 0)
                        source = name;

                wildcard = r == 0;
        } else
                wildcard = r > 0;

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
        typesafe_qsort(list, n, rr_compare);

        r = dnssec_rrset_serialize_sig(rrsig, source, list, n, wildcard,
                                       &sig_data, &sig_size);
        if (r < 0)
                return r;

        r = dnssec_rrset_verify_sig(rrsig, dnskey, sig_data, sig_size);
        if (r == -EOPNOTSUPP) {
                *result = DNSSEC_UNSUPPORTED_ALGORITHM;
                return 0;
        }
        if (r < 0)
                return r;

        /* Now, fix the ttl, expiry, and remember the synthesizing source and the signer */
        if (r > 0)
                dnssec_fix_rrset_ttl(list, n, rrsig);

        if (r == 0)
                *result = DNSSEC_INVALID;
        else if (wildcard)
                *result = DNSSEC_VALIDATED_WILDCARD;
        else
                *result = DNSSEC_VALIDATED;

        return 0;
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

        return dns_name_equal(dns_resource_key_name(dnskey->key), rrsig->rrsig.signer);
}

int dnssec_key_match_rrsig(const DnsResourceKey *key, DnsResourceRecord *rrsig) {
        assert(key);
        assert(rrsig);

        /* Checks if the specified RRSIG RR protects the RRSet of the specified RR key. */

        if (rrsig->key->type != DNS_TYPE_RRSIG)
                return 0;
        if (rrsig->key->class != key->class)
                return 0;
        if (rrsig->rrsig.type_covered != key->type)
                return 0;

        return dns_name_equal(dns_resource_key_name(rrsig->key), dns_resource_key_name(key));
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

        if (dns_answer_isempty(a))
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
                                assert_not_reached();
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

        /* Checks whether there's at least one RRSIG in 'a' that protects RRs of the specified key */

        DNS_ANSWER_FOREACH(rr, a) {
                r = dnssec_key_match_rrsig(key, rr);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 1;
        }

        return 0;
}

static hash_md_t digest_to_hash_md(uint8_t algorithm) {

        /* Translates a DNSSEC digest algorithm into an openssl/gcrypt digest identifier */

        switch (algorithm) {

        case DNSSEC_DIGEST_SHA1:
                return OPENSSL_OR_GCRYPT(EVP_sha1(), GCRY_MD_SHA1);

        case DNSSEC_DIGEST_SHA256:
                return OPENSSL_OR_GCRYPT(EVP_sha256(), GCRY_MD_SHA256);

        case DNSSEC_DIGEST_SHA384:
                return OPENSSL_OR_GCRYPT(EVP_sha384(), GCRY_MD_SHA384);

        default:
                return OPENSSL_OR_GCRYPT(NULL, -EOPNOTSUPP);
        }
}

int dnssec_verify_dnskey_by_ds(DnsResourceRecord *dnskey, DnsResourceRecord *ds, bool mask_revoke) {
        uint8_t wire_format[DNS_WIRE_FORMAT_HOSTNAME_MAX];
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
        if (!mask_revoke && (dnskey->dnskey.flags & DNSKEY_FLAG_REVOKE))
                return -EKEYREJECTED;
        if (dnskey->dnskey.protocol != 3)
                return -EKEYREJECTED;

        if (dnskey->dnskey.algorithm != ds->ds.algorithm)
                return 0;
        if (dnssec_keytag(dnskey, mask_revoke) != ds->ds.key_tag)
                return 0;

        r = dns_name_to_wire_format(dns_resource_key_name(dnskey->key), wire_format, sizeof wire_format, true);
        if (r < 0)
                return r;

        hash_md_t md_algorithm = digest_to_hash_md(ds->ds.digest_type);

#if PREFER_OPENSSL
        if (!md_algorithm)
                return -EOPNOTSUPP;

        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *ctx = NULL;
        uint8_t result[EVP_MAX_MD_SIZE];

        unsigned hash_size = EVP_MD_size(md_algorithm);
        assert(hash_size > 0);

        if (ds->ds.digest_size != hash_size)
                return 0;

        ctx = EVP_MD_CTX_new();
        if (!ctx)
                return -ENOMEM;

        if (EVP_DigestInit_ex(ctx, md_algorithm, NULL) <= 0)
                return -EIO;

        if (EVP_DigestUpdate(ctx, wire_format, r) <= 0)
                return -EIO;

        if (mask_revoke)
                md_add_uint16(ctx, dnskey->dnskey.flags & ~DNSKEY_FLAG_REVOKE);
        else
                md_add_uint16(ctx, dnskey->dnskey.flags);

        r = md_add_uint8(ctx, dnskey->dnskey.protocol);
        if (r <= 0)
                return r;
        r = md_add_uint8(ctx, dnskey->dnskey.algorithm);
        if (r <= 0)
                return r;
        if (EVP_DigestUpdate(ctx, dnskey->dnskey.key, dnskey->dnskey.key_size) <= 0)
                return -EIO;

        if (EVP_DigestFinal_ex(ctx, result, NULL) <= 0)
                return -EIO;

#else
        if (md_algorithm < 0)
                return -EOPNOTSUPP;

        initialize_libgcrypt(false);

        _cleanup_(gcry_md_closep) gcry_md_hd_t md = NULL;

        size_t hash_size = gcry_md_get_algo_dlen(md_algorithm);
        assert(hash_size > 0);

        if (ds->ds.digest_size != hash_size)
                return 0;

        gcry_error_t err = gcry_md_open(&md, md_algorithm, 0);
        if (gcry_err_code(err) != GPG_ERR_NO_ERROR || !md)
                return -EIO;

        gcry_md_write(md, wire_format, r);
        if (mask_revoke)
                md_add_uint16(md, dnskey->dnskey.flags & ~DNSKEY_FLAG_REVOKE);
        else
                md_add_uint16(md, dnskey->dnskey.flags);
        md_add_uint8(md, dnskey->dnskey.protocol);
        md_add_uint8(md, dnskey->dnskey.algorithm);
        gcry_md_write(md, dnskey->dnskey.key, dnskey->dnskey.key_size);

        void *result = gcry_md_read(md, 0);
        if (!result)
                return -EIO;
#endif

        return memcmp(result, ds->ds.digest, ds->ds.digest_size) == 0;
}

int dnssec_verify_dnskey_by_ds_search(DnsResourceRecord *dnskey, DnsAnswer *validated_ds) {
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

                r = dns_name_equal(dns_resource_key_name(dnskey->key), dns_resource_key_name(ds->key));
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = dnssec_verify_dnskey_by_ds(dnskey, ds, false);
                if (IN_SET(r, -EKEYREJECTED, -EOPNOTSUPP))
                        return 0; /* The DNSKEY is revoked or otherwise invalid, or we don't support the digest algorithm */
                if (r < 0)
                        return r;
                if (r > 0)
                        return 1;
        }

        return 0;
}

static hash_md_t nsec3_hash_to_hash_md(uint8_t algorithm) {

        /* Translates a DNSSEC NSEC3 hash algorithm into an openssl/gcrypt digest identifier */

        switch (algorithm) {

        case NSEC3_ALGORITHM_SHA1:
                return OPENSSL_OR_GCRYPT(EVP_sha1(), GCRY_MD_SHA1);

        default:
                return OPENSSL_OR_GCRYPT(NULL, -EOPNOTSUPP);
        }
}

int dnssec_nsec3_hash(DnsResourceRecord *nsec3, const char *name, void *ret) {
        uint8_t wire_format[DNS_WIRE_FORMAT_HOSTNAME_MAX];
        int r;

        assert(nsec3);
        assert(name);
        assert(ret);

        if (nsec3->key->type != DNS_TYPE_NSEC3)
                return -EINVAL;

        if (nsec3->nsec3.iterations > NSEC3_ITERATIONS_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Ignoring NSEC3 RR %s with excessive number of iterations.",
                                       dns_resource_record_to_string(nsec3));

        hash_md_t algorithm = nsec3_hash_to_hash_md(nsec3->nsec3.algorithm);
#if PREFER_OPENSSL
        if (!algorithm)
                return -EOPNOTSUPP;

        size_t hash_size = EVP_MD_size(algorithm);
        assert(hash_size > 0);

        if (nsec3->nsec3.next_hashed_name_size != hash_size)
                return -EINVAL;

        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
                return -ENOMEM;

        if (EVP_DigestInit_ex(ctx, algorithm, NULL) <= 0)
                return -EIO;

        r = dns_name_to_wire_format(name, wire_format, sizeof(wire_format), true);
        if (r < 0)
                return r;

        if (EVP_DigestUpdate(ctx, wire_format, r) <= 0)
                return -EIO;
        if (EVP_DigestUpdate(ctx, nsec3->nsec3.salt, nsec3->nsec3.salt_size) <= 0)
                return -EIO;

        uint8_t result[EVP_MAX_MD_SIZE];
        if (EVP_DigestFinal_ex(ctx, result, NULL) <= 0)
                return -EIO;

        for (unsigned k = 0; k < nsec3->nsec3.iterations; k++) {
                if (EVP_DigestInit_ex(ctx, algorithm, NULL) <= 0)
                        return -EIO;
                if (EVP_DigestUpdate(ctx, result, hash_size) <= 0)
                        return -EIO;
                if (EVP_DigestUpdate(ctx, nsec3->nsec3.salt, nsec3->nsec3.salt_size) <= 0)
                        return -EIO;

                if (EVP_DigestFinal_ex(ctx, result, NULL) <= 0)
                        return -EIO;
        }
#else
        if (algorithm < 0)
                return algorithm;

        initialize_libgcrypt(false);

        unsigned hash_size = gcry_md_get_algo_dlen(algorithm);
        assert(hash_size > 0);

        if (nsec3->nsec3.next_hashed_name_size != hash_size)
                return -EINVAL;

        r = dns_name_to_wire_format(name, wire_format, sizeof(wire_format), true);
        if (r < 0)
                return r;

        _cleanup_(gcry_md_closep) gcry_md_hd_t md = NULL;
        gcry_error_t err = gcry_md_open(&md, algorithm, 0);
        if (gcry_err_code(err) != GPG_ERR_NO_ERROR || !md)
                return -EIO;

        gcry_md_write(md, wire_format, r);
        gcry_md_write(md, nsec3->nsec3.salt, nsec3->nsec3.salt_size);

        void *result = gcry_md_read(md, 0);
        if (!result)
                return -EIO;

        for (unsigned k = 0; k < nsec3->nsec3.iterations; k++) {
                uint8_t tmp[hash_size];
                memcpy(tmp, result, hash_size);

                gcry_md_reset(md);
                gcry_md_write(md, tmp, hash_size);
                gcry_md_write(md, nsec3->nsec3.salt, nsec3->nsec3.salt_size);

                result = gcry_md_read(md, 0);
                if (!result)
                        return -EIO;
        }
#endif

        memcpy(ret, result, hash_size);
        return (int) hash_size;
}

static int nsec3_is_good(DnsResourceRecord *rr, DnsResourceRecord *nsec3) {
        const char *a, *b;
        int r;

        assert(rr);

        if (rr->key->type != DNS_TYPE_NSEC3)
                return 0;

        /* RFC 5155, Section 8.2 says we MUST ignore NSEC3 RRs with flags != 0 or 1 */
        if (!IN_SET(rr->nsec3.flags, 0, 1))
                return 0;

        /* Ignore NSEC3 RRs whose algorithm we don't know */
#if PREFER_OPENSSL
        if (!nsec3_hash_to_hash_md(rr->nsec3.algorithm))
                return 0;
#else
        if (nsec3_hash_to_hash_md(rr->nsec3.algorithm) < 0)
                return 0;
#endif

        /* Ignore NSEC3 RRs with an excessive number of required iterations */
        if (rr->nsec3.iterations > NSEC3_ITERATIONS_MAX)
                return 0;

        /* Ignore NSEC3 RRs generated from wildcards. If these NSEC3 RRs weren't correctly signed we can't make this
         * check (since rr->n_skip_labels_source is -1), but that's OK, as we won't trust them anyway in that case. */
        if (!IN_SET(rr->n_skip_labels_source, 0, UINT8_MAX))
                return 0;
        /* Ignore NSEC3 RRs that are located anywhere else than one label below the zone */
        if (!IN_SET(rr->n_skip_labels_signer, 1, UINT8_MAX))
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
        if (memcmp_safe(rr->nsec3.salt, nsec3->nsec3.salt, rr->nsec3.salt_size) != 0)
                return 0;

        a = dns_resource_key_name(rr->key);
        r = dns_name_parent(&a); /* strip off hash */
        if (r <= 0)
                return r;

        b = dns_resource_key_name(nsec3->key);
        r = dns_name_parent(&b); /* strip off hash */
        if (r <= 0)
                return r;

        /* Make sure both have the same parent */
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

        j = strjoin(l, ".", zone);
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
 * that there is no proof either way. The latter is the case if a proof of non-existence of a given
 * name uses an NSEC3 record with the opt-out bit set. Lastly, if we are given insufficient NSEC3 records
 * to conclude anything we indicate this by returning NO_RR. */
static int dnssec_test_nsec3(DnsAnswer *answer, DnsResourceKey *key, DnssecNsecResult *result, bool *authenticated, uint32_t *ttl) {
        _cleanup_free_ char *next_closer_domain = NULL, *wildcard_domain = NULL;
        const char *zone, *p, *pp = NULL, *wildcard;
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
        zone = dns_resource_key_name(key);
        for (;;) {
                DNS_ANSWER_FOREACH_FLAGS(zone_rr, flags, answer) {
                        r = nsec3_is_good(zone_rr, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        r = dns_name_equal_skip(dns_resource_key_name(zone_rr->key), 1, zone);
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
        p = dns_resource_key_name(key);
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

                        r = dns_name_equal(dns_resource_key_name(enclosure_rr->key), hashed_domain);
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

        if (!pp) {
                /* We have an exact match! If we area looking for a DS RR, then we must insist that we got the NSEC3 RR
                 * from the parent. Otherwise the one from the child. Do so, by checking whether SOA and NS are
                 * appropriately set. */

                if (key->type == DNS_TYPE_DS) {
                        if (bitmap_isset(enclosure_rr->nsec3.types, DNS_TYPE_SOA))
                                return -EBADMSG;
                } else {
                        if (bitmap_isset(enclosure_rr->nsec3.types, DNS_TYPE_NS) &&
                            !bitmap_isset(enclosure_rr->nsec3.types, DNS_TYPE_SOA))
                                return -EBADMSG;
                }

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

        /* Prove that there is no next closer and whether or not there is a wildcard domain. */

        wildcard = strjoina("*.", p);
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

                r = dns_name_between(dns_resource_key_name(rr->key), next_closer_domain, next_hashed_domain);
                if (r < 0)
                        return r;
                if (r > 0) {
                        if (rr->nsec3.flags & 1)
                                optout = true;

                        a = a && (flags & DNS_ANSWER_AUTHENTICATED);

                        no_closer = true;
                }

                r = dns_name_equal(dns_resource_key_name(rr->key), wildcard_domain);
                if (r < 0)
                        return r;
                if (r > 0) {
                        a = a && (flags & DNS_ANSWER_AUTHENTICATED);

                        wildcard_rr = rr;
                }

                r = dns_name_between(dns_resource_key_name(rr->key), wildcard_domain, next_hashed_domain);
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

static int dnssec_nsec_wildcard_equal(DnsResourceRecord *rr, const char *name) {
        char label[DNS_LABEL_MAX+1];
        const char *n;
        int r;

        assert(rr);
        assert(rr->key->type == DNS_TYPE_NSEC);

        /* Checks whether the specified RR has a name beginning in "*.", and if the rest is a suffix of our name */

        if (rr->n_skip_labels_source != 1)
                return 0;

        n = dns_resource_key_name(rr->key);
        r = dns_label_unescape(&n, label, sizeof label, 0);
        if (r <= 0)
                return r;
        if (r != 1 || label[0] != '*')
                return 0;

        return dns_name_endswith(name, n);
}

static int dnssec_nsec_in_path(DnsResourceRecord *rr, const char *name) {
        const char *nn, *common_suffix;
        int r;

        assert(rr);
        assert(rr->key->type == DNS_TYPE_NSEC);

        /* Checks whether the specified nsec RR indicates that name is an empty non-terminal (ENT)
         *
         * A couple of examples:
         *
         *      NSEC             bar →   waldo.foo.bar: indicates that foo.bar exists and is an ENT
         *      NSEC   waldo.foo.bar → yyy.zzz.xoo.bar: indicates that xoo.bar and zzz.xoo.bar exist and are ENTs
         *      NSEC yyy.zzz.xoo.bar →             bar: indicates pretty much nothing about ENTs
         */

        /* First, determine parent of next domain. */
        nn = rr->nsec.next_domain_name;
        r = dns_name_parent(&nn);
        if (r <= 0)
                return r;

        /* If the name we just determined is not equal or child of the name we are interested in, then we can't say
         * anything at all. */
        r = dns_name_endswith(nn, name);
        if (r <= 0)
                return r;

        /* If the name we are interested in is not a prefix of the common suffix of the NSEC RR's owner and next domain names, then we can't say anything either. */
        r = dns_name_common_suffix(dns_resource_key_name(rr->key), rr->nsec.next_domain_name, &common_suffix);
        if (r < 0)
                return r;

        return dns_name_endswith(name, common_suffix);
}

static int dnssec_nsec_from_parent_zone(DnsResourceRecord *rr, const char *name) {
        int r;

        assert(rr);
        assert(rr->key->type == DNS_TYPE_NSEC);

        /* Checks whether this NSEC originates to the parent zone or the child zone. */

        r = dns_name_parent(&name);
        if (r <= 0)
                return r;

        r = dns_name_equal(name, dns_resource_key_name(rr->key));
        if (r <= 0)
                return r;

        /* DNAME, and NS without SOA is an indication for a delegation. */
        if (bitmap_isset(rr->nsec.types, DNS_TYPE_DNAME))
                return 1;

        if (bitmap_isset(rr->nsec.types, DNS_TYPE_NS) && !bitmap_isset(rr->nsec.types, DNS_TYPE_SOA))
                return 1;

        return 0;
}

static int dnssec_nsec_covers(DnsResourceRecord *rr, const char *name) {
        const char *signer;
        int r;

        assert(rr);
        assert(rr->key->type == DNS_TYPE_NSEC);

        /* Checks whether the name is covered by this NSEC RR. This means, that the name is somewhere below the NSEC's
         * signer name, and between the NSEC's two names. */

        r = dns_resource_record_signer(rr, &signer);
        if (r < 0)
                return r;

        r = dns_name_endswith(name, signer); /* this NSEC isn't suitable the name is not in the signer's domain */
        if (r <= 0)
                return r;

        return dns_name_between(dns_resource_key_name(rr->key), name, rr->nsec.next_domain_name);
}

static int dnssec_nsec_generate_wildcard(DnsResourceRecord *rr, const char *name, char **wc) {
        const char *common_suffix1, *common_suffix2, *signer;
        int r, labels1, labels2;

        assert(rr);
        assert(rr->key->type == DNS_TYPE_NSEC);

        /* Generates "Wildcard at the Closest Encloser" for the given name and NSEC RR. */

        r = dns_resource_record_signer(rr, &signer);
        if (r < 0)
                return r;

        r = dns_name_endswith(name, signer); /* this NSEC isn't suitable the name is not in the signer's domain */
        if (r <= 0)
                return r;

        r = dns_name_common_suffix(name, dns_resource_key_name(rr->key), &common_suffix1);
        if (r < 0)
                return r;

        r = dns_name_common_suffix(name, rr->nsec.next_domain_name, &common_suffix2);
        if (r < 0)
                return r;

        labels1 = dns_name_count_labels(common_suffix1);
        if (labels1 < 0)
            return labels1;

        labels2 = dns_name_count_labels(common_suffix2);
        if (labels2 < 0)
            return labels2;

        if (labels1 > labels2)
                r = dns_name_concat("*", common_suffix1, 0, wc);
        else
                r = dns_name_concat("*", common_suffix2, 0, wc);

        if (r < 0)
                return r;

        return 0;
}

int dnssec_nsec_test(DnsAnswer *answer, DnsResourceKey *key, DnssecNsecResult *result, bool *authenticated, uint32_t *ttl) {
        bool have_nsec3 = false, covering_rr_authenticated = false, wildcard_rr_authenticated = false;
        DnsResourceRecord *rr, *covering_rr = NULL, *wildcard_rr = NULL;
        DnsAnswerFlags flags;
        const char *name;
        int r;

        assert(key);
        assert(result);

        /* Look for any NSEC/NSEC3 RRs that say something about the specified key. */

        name = dns_resource_key_name(key);

        DNS_ANSWER_FOREACH_FLAGS(rr, flags, answer) {

                if (rr->key->class != key->class)
                        continue;

                have_nsec3 = have_nsec3 || (rr->key->type == DNS_TYPE_NSEC3);

                if (rr->key->type != DNS_TYPE_NSEC)
                        continue;

                /* The following checks only make sense for NSEC RRs that are not expanded from a wildcard */
                r = dns_resource_record_is_synthetic(rr);
                if (r == -ENODATA) /* No signing RR known. */
                        continue;
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                /* Check if this is a direct match. If so, we have encountered a NODATA case */
                r = dns_name_equal(dns_resource_key_name(rr->key), name);
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* If it's not a direct match, maybe it's a wild card match? */
                        r = dnssec_nsec_wildcard_equal(rr, name);
                        if (r < 0)
                                return r;
                }
                if (r > 0) {
                        if (key->type == DNS_TYPE_DS) {
                                /* If we look for a DS RR and the server sent us the NSEC RR of the child zone
                                 * we have a problem. For DS RRs we want the NSEC RR from the parent */
                                if (bitmap_isset(rr->nsec.types, DNS_TYPE_SOA))
                                        continue;
                        } else {
                                /* For all RR types, ensure that if NS is set SOA is set too, so that we know
                                 * we got the child's NSEC. */
                                if (bitmap_isset(rr->nsec.types, DNS_TYPE_NS) &&
                                    !bitmap_isset(rr->nsec.types, DNS_TYPE_SOA))
                                        continue;
                        }

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

                /* Check if the name we are looking for is an empty non-terminal within the owner or next name
                 * of the NSEC RR. */
                r = dnssec_nsec_in_path(rr, name);
                if (r < 0)
                        return r;
                if (r > 0) {
                        *result = DNSSEC_NSEC_NODATA;

                        if (authenticated)
                                *authenticated = flags & DNS_ANSWER_AUTHENTICATED;
                        if (ttl)
                                *ttl = rr->ttl;

                        return 0;
                }

                /* The following two "covering" checks, are not useful if the NSEC is from the parent */
                r = dnssec_nsec_from_parent_zone(rr, name);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                /* Check if this NSEC RR proves the absence of an explicit RR under this name */
                r = dnssec_nsec_covers(rr, name);
                if (r < 0)
                        return r;
                if (r > 0 && (!covering_rr || !covering_rr_authenticated)) {
                        covering_rr = rr;
                        covering_rr_authenticated = flags & DNS_ANSWER_AUTHENTICATED;
                }
        }

        if (covering_rr) {
                _cleanup_free_ char *wc = NULL;
                r = dnssec_nsec_generate_wildcard(covering_rr, name, &wc);
                if (r < 0)
                        return r;

                DNS_ANSWER_FOREACH_FLAGS(rr, flags, answer) {

                        if (rr->key->class != key->class)
                                continue;

                        if (rr->key->type != DNS_TYPE_NSEC)
                                continue;

                        /* Check if this NSEC RR proves the nonexistence of the wildcard */
                        r = dnssec_nsec_covers(rr, wc);
                        if (r < 0)
                                return r;
                        if (r > 0 && (!wildcard_rr || !wildcard_rr_authenticated)) {
                                wildcard_rr = rr;
                                wildcard_rr_authenticated = flags & DNS_ANSWER_AUTHENTICATED;
                        }
                }
        }

        if (covering_rr && wildcard_rr) {
                /* If we could prove that neither the name itself, nor the wildcard at the closest encloser exists, we
                 * proved the NXDOMAIN case. */
                *result = DNSSEC_NSEC_NXDOMAIN;

                if (authenticated)
                        *authenticated = covering_rr_authenticated && wildcard_rr_authenticated;
                if (ttl)
                        *ttl = MIN(covering_rr->ttl, wildcard_rr->ttl);

                return 0;
        }

        /* OK, this was not sufficient. Let's see if NSEC3 can help. */
        if (have_nsec3)
                return dnssec_test_nsec3(answer, key, result, authenticated, ttl);

        /* No appropriate NSEC RR found, report this. */
        *result = DNSSEC_NSEC_NO_RR;
        return 0;
}

static int dnssec_nsec_test_enclosed(DnsAnswer *answer, uint16_t type, const char *name, const char *zone, bool *authenticated) {
        DnsResourceRecord *rr;
        DnsAnswerFlags flags;
        int r;

        assert(name);
        assert(zone);

        /* Checks whether there's an NSEC/NSEC3 that proves that the specified 'name' is non-existing in the specified
         * 'zone'. The 'zone' must be a suffix of the 'name'. */

        DNS_ANSWER_FOREACH_FLAGS(rr, flags, answer) {
                bool found = false;

                if (rr->key->type != type && type != DNS_TYPE_ANY)
                        continue;

                switch (rr->key->type) {

                case DNS_TYPE_NSEC:

                        /* We only care for NSEC RRs from the indicated zone */
                        r = dns_resource_record_is_signer(rr, zone);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        r = dns_name_between(dns_resource_key_name(rr->key), name, rr->nsec.next_domain_name);
                        if (r < 0)
                                return r;

                        found = r > 0;
                        break;

                case DNS_TYPE_NSEC3: {
                        _cleanup_free_ char *hashed_domain = NULL, *next_hashed_domain = NULL;

                        /* We only care for NSEC3 RRs from the indicated zone */
                        r = dns_resource_record_is_signer(rr, zone);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

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

                        r = dns_name_between(dns_resource_key_name(rr->key), hashed_domain, next_hashed_domain);
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

static int dnssec_test_positive_wildcard_nsec3(
                DnsAnswer *answer,
                const char *name,
                const char *source,
                const char *zone,
                bool *authenticated) {

        const char *next_closer = NULL;
        int r;

        /* Run a positive NSEC3 wildcard proof. Specifically:
         *
         * A proof that the "next closer" of the generating wildcard does not exist.
         *
         * Note a key difference between the NSEC3 and NSEC versions of the proof. NSEC RRs don't have to exist for
         * empty non-transients. NSEC3 RRs however have to. This means it's sufficient to check if the next closer name
         * exists for the NSEC3 RR and we are done.
         *
         * To prove that a.b.c.d.e.f is rightfully synthesized from a wildcard *.d.e.f all we have to check is that
         * c.d.e.f does not exist. */

        for (;;) {
                next_closer = name;
                r = dns_name_parent(&name);
                if (r <= 0)
                        return r;

                r = dns_name_equal(name, source);
                if (r < 0)
                        return r;
                if (r > 0)
                        break;
        }

        return dnssec_nsec_test_enclosed(answer, DNS_TYPE_NSEC3, next_closer, zone, authenticated);
}

static int dnssec_test_positive_wildcard_nsec(
                DnsAnswer *answer,
                const char *name,
                const char *source,
                const char *zone,
                bool *_authenticated) {

        bool authenticated = true;
        int r;

        /* Run a positive NSEC wildcard proof. Specifically:
         *
         * A proof that there's neither a wildcard name nor a non-wildcard name that is a suffix of the name "name" and
         * a prefix of the synthesizing source "source" in the zone "zone".
         *
         * See RFC 5155, Section 8.8 and RFC 4035, Section 5.3.4
         *
         * Note that if we want to prove that a.b.c.d.e.f is rightfully synthesized from a wildcard *.d.e.f, then we
         * have to prove that none of the following exist:
         *
         *      1) a.b.c.d.e.f
         *      2) *.b.c.d.e.f
         *      3)   b.c.d.e.f
         *      4)   *.c.d.e.f
         *      5)     c.d.e.f
         */

        for (;;) {
                _cleanup_free_ char *wc = NULL;
                bool a = false;

                /* Check if there's an NSEC or NSEC3 RR that proves that the mame we determined is really non-existing,
                 * i.e between the owner name and the next name of an NSEC RR. */
                r = dnssec_nsec_test_enclosed(answer, DNS_TYPE_NSEC, name, zone, &a);
                if (r <= 0)
                        return r;

                authenticated = authenticated && a;

                /* Strip one label off */
                r = dns_name_parent(&name);
                if (r <= 0)
                        return r;

                /* Did we reach the source of synthesis? */
                r = dns_name_equal(name, source);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* Successful exit */
                        *_authenticated = authenticated;
                        return 1;
                }

                /* Safety check, that the source of synthesis is still our suffix */
                r = dns_name_endswith(name, source);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EBADMSG;

                /* Replace the label we stripped off with an asterisk */
                wc = strjoin("*.", name);
                if (!wc)
                        return -ENOMEM;

                /* And check if the proof holds for the asterisk name, too */
                r = dnssec_nsec_test_enclosed(answer, DNS_TYPE_NSEC, wc, zone, &a);
                if (r <= 0)
                        return r;

                authenticated = authenticated && a;
                /* In the next iteration we'll check the non-asterisk-prefixed version */
        }
}

int dnssec_test_positive_wildcard(
                DnsAnswer *answer,
                const char *name,
                const char *source,
                const char *zone,
                bool *authenticated) {

        int r;

        assert(name);
        assert(source);
        assert(zone);
        assert(authenticated);

        r = dns_answer_contains_zone_nsec3(answer, zone);
        if (r < 0)
                return r;
        if (r > 0)
                return dnssec_test_positive_wildcard_nsec3(answer, name, source, zone, authenticated);
        else
                return dnssec_test_positive_wildcard_nsec(answer, name, source, zone, authenticated);
}

#else

int dnssec_verify_rrset(
                DnsAnswer *a,
                const DnsResourceKey *key,
                DnsResourceRecord *rrsig,
                DnsResourceRecord *dnskey,
                usec_t realtime,
                DnssecResult *result) {

        return -EOPNOTSUPP;
}

int dnssec_rrsig_match_dnskey(DnsResourceRecord *rrsig, DnsResourceRecord *dnskey, bool revoked_ok) {

        return -EOPNOTSUPP;
}

int dnssec_key_match_rrsig(const DnsResourceKey *key, DnsResourceRecord *rrsig) {

        return -EOPNOTSUPP;
}

int dnssec_verify_rrset_search(
                DnsAnswer *a,
                const DnsResourceKey *key,
                DnsAnswer *validated_dnskeys,
                usec_t realtime,
                DnssecResult *result,
                DnsResourceRecord **ret_rrsig) {

        return -EOPNOTSUPP;
}

int dnssec_has_rrsig(DnsAnswer *a, const DnsResourceKey *key) {

        return -EOPNOTSUPP;
}

int dnssec_verify_dnskey_by_ds(DnsResourceRecord *dnskey, DnsResourceRecord *ds, bool mask_revoke) {

        return -EOPNOTSUPP;
}

int dnssec_verify_dnskey_by_ds_search(DnsResourceRecord *dnskey, DnsAnswer *validated_ds) {

        return -EOPNOTSUPP;
}

int dnssec_nsec3_hash(DnsResourceRecord *nsec3, const char *name, void *ret) {

        return -EOPNOTSUPP;
}

int dnssec_nsec_test(DnsAnswer *answer, DnsResourceKey *key, DnssecNsecResult *result, bool *authenticated, uint32_t *ttl) {

        return -EOPNOTSUPP;
}

int dnssec_test_positive_wildcard(
                DnsAnswer *answer,
                const char *name,
                const char *source,
                const char *zone,
                bool *authenticated) {

        return -EOPNOTSUPP;
}

#endif

static const char* const dnssec_result_table[_DNSSEC_RESULT_MAX] = {
        [DNSSEC_VALIDATED]             = "validated",
        [DNSSEC_VALIDATED_WILDCARD]    = "validated-wildcard",
        [DNSSEC_INVALID]               = "invalid",
        [DNSSEC_SIGNATURE_EXPIRED]     = "signature-expired",
        [DNSSEC_UNSUPPORTED_ALGORITHM] = "unsupported-algorithm",
        [DNSSEC_NO_SIGNATURE]          = "no-signature",
        [DNSSEC_MISSING_KEY]           = "missing-key",
        [DNSSEC_UNSIGNED]              = "unsigned",
        [DNSSEC_FAILED_AUXILIARY]      = "failed-auxiliary",
        [DNSSEC_NSEC_MISMATCH]         = "nsec-mismatch",
        [DNSSEC_INCOMPATIBLE_SERVER]   = "incompatible-server",
};
DEFINE_STRING_TABLE_LOOKUP(dnssec_result, DnssecResult);

static const char* const dnssec_verdict_table[_DNSSEC_VERDICT_MAX] = {
        [DNSSEC_SECURE]        = "secure",
        [DNSSEC_INSECURE]      = "insecure",
        [DNSSEC_BOGUS]         = "bogus",
        [DNSSEC_INDETERMINATE] = "indeterminate",
};
DEFINE_STRING_TABLE_LOOKUP(dnssec_verdict, DnssecVerdict);
