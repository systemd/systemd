/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * This is based on
 *   fsprg v0.1  -  (seekable) forward-secure pseudorandom generator
 *   Copyright © 2012 B. Poettering
 *   Contact: fsprg@point-at-infinity.org
 *
 * OpenSSL port of the original libgcrypt-based implementation.
 *
 * See "Practical Secure Logging: Seekable Sequential Key Generators"
 * by G. A. Marson, B. Poettering for details:
 *
 * http://eprint.iacr.org/2013/397
 */

#include <syslog.h>

#include "alloc-util.h"         /* IWYU pragma: keep */
#include "crypto-util.h"
#include "fsprg-openssl.h"
#include "iovec-util.h"
#include "logarithm.h"
#include "sparse-endian.h"
#include "unaligned.h"

#define RND_GEN_P 0x01
#define RND_GEN_Q 0x02
#define RND_GEN_X 0x03

/* Suppress a false positive from GCC's -Wstringop-overflow warning. Keep a local helper so the compiler can
 * propagate the range check within this translation unit. */
static bool secpar_is_valid(uint16_t secpar) {
        return
                secpar % 16 == 0 &&
                secpar >= 16 &&
                secpar <= 16384;
}

bool fsprg_secpar_is_valid(uint16_t secpar) {
        return secpar_is_valid(secpar);
}

size_t fsprg_state_size(uint16_t secpar) {
        assert(secpar_is_valid(secpar));

        /* See comment in parse_state(). */
        return sizeof(uint16_t) + 2 * secpar / 8 + sizeof(uint64_t);
}

#if HAVE_OPENSSL
static int mpi_export(struct iovec *iov, const BIGNUM *x) {
        assert(iovec_is_set(iov));
        assert(x);

        if (sym_BN_is_negative(x))
                return -EINVAL;

        if (sym_BN_num_bytes(x) > (int) iov->iov_len)
                return -ENOSPC;

        if (sym_BN_bn2binpad(x, iov->iov_base, iov->iov_len) != (int) iov->iov_len)
                return -EIO;

        return 0;
}

static int mpi_import(const struct iovec *iov, BIGNUM **ret) {
        assert(iovec_is_set(iov));
        assert(ret);

        /* Allocate a new BIGNUM. */
        _cleanup_(BN_clear_freep) BIGNUM *x = sym_BN_secure_new();
        if (!x)
                return -ENOMEM;

        if (!sym_BN_bin2bn(iov->iov_base, iov->iov_len, x))
                return -EIO;

        *ret = TAKE_PTR(x);
        return 0;
}

static int det_randomize(const struct iovec *seed, uint32_t idx, struct iovec *iov) {
        assert(iovec_is_set(seed));
        assert(iovec_is_valid(iov));

        /* Expand (seed, idx) into a deterministic pseudorandom byte stream. */

        if (!iovec_is_set(iov))
                return 0;

        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *ctx = sym_EVP_MD_CTX_new();
        if (!ctx)
                return -ENOMEM;

        if (sym_EVP_DigestInit_ex(ctx, sym_EVP_sha256(), NULL) <= 0)
                return -EIO;

        if (sym_EVP_DigestUpdate(ctx, seed->iov_base, seed->iov_len) <= 0)
                return -EIO;

        if (sym_EVP_DigestUpdate(ctx, (be32_t[]) { htobe32(idx) }, sizeof(be32_t)) <= 0)
                return -EIO;

        struct iovec v = *iov;
        for (uint32_t ctr = 0; iovec_is_set(&v); ctr++) {
                _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *tmp = sym_EVP_MD_CTX_new();
                if (!tmp)
                        return -ENOMEM;

                if (sym_EVP_MD_CTX_copy_ex(tmp, ctx) <= 0)
                        return -EIO;

                if (sym_EVP_DigestUpdate(tmp, (be32_t[]) { htobe32(ctr) }, sizeof(be32_t)) <= 0)
                        return -EIO;

                unsigned dlen;
                uint8_t digest[EVP_MAX_MD_SIZE];
                CLEANUP_ERASE(digest);

                if (sym_EVP_DigestFinal_ex(tmp, digest, &dlen) <= 0)
                        return -EIO;

                size_t n = MIN(v.iov_len, dlen);
                memcpy(v.iov_base, digest, n);
                iovec_inc(&v, n);
        }

        return 0;
}

/* deterministically generate from seed/idx a prime of length (secpar / 2) bits that is 3 mod 4 */
static int generate_prime3mod4(
                uint16_t secpar,
                const struct iovec *seed,
                uint32_t idx,
                BN_CTX *bn_ctx,
                BIGNUM **ret) {

        int r;

        assert(iovec_is_set(seed));
        assert(bn_ctx);
        assert(ret);

        if (!secpar_is_valid(secpar))
                return -EINVAL;

        _cleanup_(iovec_erase) struct iovec iov = IOVEC_ALLOCA(secpar / 2 / 8);
        r = det_randomize(seed, idx, &iov);
        if (r < 0)
                return r;

        uint8_t *buf = iov.iov_base;

        /* Set the upper two bits so that n = pq has the maximum size. */
        buf[0] |= 0xc0;

        /* Make the candidate congruent to 3 (mod 4). */
        buf[iov.iov_len - 1] |= 0x03;

        _cleanup_(BN_clear_freep) BIGNUM *p = NULL;
        r = mpi_import(&iov, &p);
        if (r < 0)
                return r;

        for (;;) {
                /* negative: error, 0: composite, 1: prime */
                r = sym_BN_check_prime(p, bn_ctx, /* cb= */ NULL);
                if (r < 0)
                        return -EIO;
                if (r > 0)
                        break;

                /* Increment p by 4. */
                if (sym_BN_add_word(p, 4) <= 0)
                        return -EIO;

                /* Check if p is still (secpar / 2) bits. */
                if (sym_BN_num_bits(p) != secpar / 2)
                        return -EOVERFLOW;
        }

        *ret = TAKE_PTR(p);
        return 0;
}

static int generate_keys(
                uint16_t secpar,
                const struct iovec *seed,
                BN_CTX *bn_ctx,
                BIGNUM **ret_p,   /* prime */
                BIGNUM **ret_q,   /* prime */
                BIGNUM **ret_n) { /* n = p * q */

        int r;

        assert(iovec_is_set(seed));
        assert(bn_ctx);
        assert(ret_p);
        assert(ret_q);
        assert(ret_n);

        if (!secpar_is_valid(secpar))
                return -EINVAL;

        _cleanup_(BN_clear_freep) BIGNUM *p = NULL;
        r = generate_prime3mod4(secpar, seed, RND_GEN_P, bn_ctx, &p);
        if (r < 0)
                return r;

        _cleanup_(BN_clear_freep) BIGNUM *q = NULL;
        r = generate_prime3mod4(secpar, seed, RND_GEN_Q, bn_ctx, &q);
        if (r < 0)
                return r;

        _cleanup_(BN_clear_freep) BIGNUM *n = sym_BN_secure_new();
        if (!n)
                return -ENOMEM;

        if (sym_BN_mul(n, p, q, bn_ctx) <= 0)
                return -EIO;

        if (sym_BN_num_bits(n) != secpar)
                return -EIO;

        if (ret_p)
                *ret_p = TAKE_PTR(p);
        if (ret_q)
                *ret_q = TAKE_PTR(q);
        if (ret_n)
                *ret_n = TAKE_PTR(n);
        return 0;
}

/* deterministically generate from seed/idx a quadratic residue (mod n) */
static int generate_square(
                uint16_t secpar,
                const struct iovec *seed,
                uint32_t idx,
                const BIGNUM *n,
                BN_CTX *bn_ctx,
                BIGNUM **ret) {

        int r;

        assert(iovec_is_set(seed));
        assert(n);
        assert(bn_ctx);
        assert(ret);

        _cleanup_(iovec_erase) struct iovec iov = IOVEC_ALLOCA(secpar / 8);
        r = det_randomize(seed, idx, &iov);
        if (r < 0)
                return r;

        *(uint8_t*) iov.iov_base &= 0x7f; /* Clear the upper bit so that we are likely to have x < n. */

        _cleanup_(BN_clear_freep) BIGNUM *x = NULL;
        r = mpi_import(&iov, &x);
        if (r < 0)
                return r;

        /* x < n should always hold for a valid modulus generated by generate_keys(). */
        if (sym_BN_cmp(x, n) >= 0)
                return -EINVAL;

        /* x := x^2 mod n */
        if (sym_BN_mod_sqr(x, x, n, bn_ctx) <= 0)
                return -EIO;

        *ret = TAKE_PTR(x);
        return 0;
}

/* Compute 2^m mod phi(p), where p is prime and phi(p) = p - 1. */
static int compute_two_pow_mod_phi(
                uint64_t m,
                const BIGNUM *p,
                BN_CTX *bn_ctx,
                BIGNUM **ret) {

        assert(p);
        assert(bn_ctx);
        assert(ret);

        _cleanup_(BN_clear_freep) BIGNUM *phi = sym_BN_secure_new();
        if (!phi)
                return -ENOMEM;

        /* phi := p */
        if (!sym_BN_copy(phi, p))
                return -EIO;

        /* phi := p - 1 */
        if (sym_BN_sub_word(phi, 1) <= 0)
                return -EIO;

        _cleanup_(BN_clear_freep) BIGNUM *x = sym_BN_secure_new();
        if (!x)
                return -ENOMEM;

        /* x := 1 */
        if (!sym_BN_one(x))
                return -EIO;

        if (m == 0) {
                /* 2^0 mod phi = 1. */
                *ret = TAKE_PTR(x);
                return 0;
        }

        /* Square-and-multiply. Iterate over the bits of m from MSB to LSB. */
        for (int n = LOG2ULL(m); n >= 0; n--) {
                if (sym_BN_mod_sqr(x, x, phi, bn_ctx) <= 0) /* x := x^2 mod phi */
                        return -EIO;

                if (m & (UINT64_C(1) << n) &&
                    sym_BN_mod_lshift1_quick(x, x, phi) <= 0) /* x := 2x mod phi */
                        return -EIO;
        }

        *ret = TAKE_PTR(x);
        return 0;
}

/* Decompose x ∈ Z_n into (xp, xq) ∈ Z_p × Z_q using the Chinese Remainder Theorem. */
static int crt_decompose(
                const BIGNUM *x,
                const BIGNUM *p,
                const BIGNUM *q,
                BN_CTX *bn_ctx,
                BIGNUM **ret_xp,
                BIGNUM **ret_xq) {

        assert(x);
        assert(p);
        assert(q);
        assert(bn_ctx);
        assert(ret_xp);
        assert(ret_xq);

        _cleanup_(BN_clear_freep) BIGNUM *xp = sym_BN_secure_new();
        if (!xp)
                return -ENOMEM;

        _cleanup_(BN_clear_freep) BIGNUM *xq = sym_BN_secure_new();
        if (!xq)
                return -ENOMEM;

        if (sym_BN_nnmod(xp, x, p, bn_ctx) <= 0)
                return -EIO;

        if (sym_BN_nnmod(xq, x, q, bn_ctx) <= 0)
                return -EIO;

        *ret_xp = TAKE_PTR(xp);
        *ret_xq = TAKE_PTR(xq);
        return 0;
}

/* Compose (xp, xq) ∈ Z_p × Z_q into x ∈ Z_n using the Chinese Remainder Theorem. */
static int crt_compose(
                const BIGNUM *xp,
                const BIGNUM *xq,
                const BIGNUM *p,
                const BIGNUM *q,
                BN_CTX *bn_ctx,
                BIGNUM **ret) {

        assert(xp);
        assert(xq);
        assert(p);
        assert(q);
        assert(bn_ctx);
        assert(ret);

        _cleanup_(BN_clear_freep) BIGNUM *x = sym_BN_secure_new();
        if (!x)
                return -ENOMEM;

        /* x := xq - xp mod q */
        if (sym_BN_mod_sub(x, xq, xp, q, bn_ctx) <= 0)
                return -EIO;

        /* Compute p^-1 mod q. */
        _cleanup_(BN_clear_freep) BIGNUM *p_inv = sym_BN_secure_new();
        if (!p_inv)
                return -ENOMEM;

        if (!sym_BN_mod_inverse(p_inv, p, q, bn_ctx))
                return -EIO;

        /* x := (xq - xp) * p^-1 mod q */
        if (sym_BN_mod_mul(x, x, p_inv, q, bn_ctx) <= 0)
                return -EIO;

        /* x := p * ((xq - xp) * p^-1 mod q) */
        if (sym_BN_mul(x, x, p, bn_ctx) <= 0)
                return -EIO;

        /* x := p * ((xq - xp) * p^-1 mod q) + xp */
        if (sym_BN_add(x, x, xp) <= 0)
                return -EIO;

        *ret = TAKE_PTR(x);
        return 0;
}

static int save_state(
                uint16_t secpar,
                const BIGNUM *modulus,
                const BIGNUM *current,
                uint64_t epoch,
                struct iovec *state) {

        int r;

        assert(modulus);
        assert(current);
        assert(iovec_is_set(state));

        if (!secpar_is_valid(secpar))
                return -EINVAL;

        if (state->iov_len != fsprg_state_size(secpar))
                return -EINVAL;

        uint8_t *s = state->iov_base;

        /* header */
        unaligned_write_be16(s, secpar / 16 - 1);
        s += sizeof(uint16_t);

        /* modulus */
        r = mpi_export(&IOVEC_MAKE(s, secpar / 8), modulus);
        if (r < 0)
                return r;
        s += secpar / 8;

        /* current */
        r = mpi_export(&IOVEC_MAKE(s, secpar / 8), current);
        if (r < 0)
                return r;
        s += secpar / 8;

        /* epoch */
        unaligned_write_be64(s, epoch);
        return 0;
}

static int parse_state(
                const struct iovec *state,
                uint16_t *ret_secpar,
                BIGNUM **ret_modulus,
                BIGNUM **ret_current,
                uint64_t *ret_epoch) {

        int r;

        assert(iovec_is_set(state));

        /* The serialized state consists of:
         * - header: 2 bytes. Encodes secpar / 16 - 1, where 16 <= secpar <= 16384.
         * - modulus (a.k.a. n): secpar / 8 bytes.
         * - current (a.k.a. x): secpar / 8 bytes.
         * - epoch: 8 bytes. */

        if (state->iov_len < sizeof(uint16_t))
                return -EBADMSG;

        uint16_t header = unaligned_read_be16(state->iov_base);
        if (header >= 1024)
                return -EBADMSG;

        uint16_t secpar = 16 * (header + 1);
        if (state->iov_len != fsprg_state_size(secpar))
                return -EBADMSG;

        _cleanup_(BN_clear_freep) BIGNUM *modulus = NULL;
        if (ret_modulus) {
                r = mpi_import(&IOVEC_MAKE((uint8_t*) state->iov_base + sizeof(uint16_t), secpar / 8), &modulus);
                if (r < 0)
                        return r;
        }

        _cleanup_(BN_clear_freep) BIGNUM *current = NULL;
        if (ret_current) {
                r = mpi_import(&IOVEC_MAKE((uint8_t*) state->iov_base + sizeof(uint16_t) + secpar / 8, secpar / 8), &current);
                if (r < 0)
                        return r;
        }

        if (ret_secpar)
                *ret_secpar = secpar;
        if (ret_modulus)
                *ret_modulus = TAKE_PTR(modulus);
        if (ret_current)
                *ret_current = TAKE_PTR(current);
        if (ret_epoch)
                *ret_epoch = unaligned_read_be64((uint8_t*) state->iov_base + sizeof(uint16_t) + 2 * secpar / 8);
        return 0;
}
#endif

int fsprg_generate_state(
                uint16_t secpar,
                uint64_t epoch,
                const struct iovec *seed,
                struct iovec *state) {

#if HAVE_OPENSSL
        int r;

        assert(iovec_is_set(seed));
        assert(iovec_is_set(state));

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        if (!secpar_is_valid(secpar))
                return -EINVAL;

        _cleanup_(BN_CTX_freep) BN_CTX *bn_ctx = sym_BN_CTX_secure_new();
        if (!bn_ctx)
                return -ENOMEM;

        _cleanup_(BN_clear_freep) BIGNUM *p = NULL, *q = NULL, *n = NULL;
        r = generate_keys(secpar, seed, bn_ctx, &p, &q, &n);
        if (r < 0)
                return r;

        _cleanup_(BN_clear_freep) BIGNUM *x = NULL;
        r = generate_square(secpar, seed, RND_GEN_X, n, bn_ctx, &x);
        if (r < 0)
                return r;

        if (epoch != 0) {
                /* Decompose x from Z_n into Z_p × Z_q using CRT. */
                _cleanup_(BN_clear_freep) BIGNUM *xp = NULL, *xq = NULL;
                r = crt_decompose(x, p, q, bn_ctx, &xp, &xq);
                if (r < 0)
                        return r;

                /* Compute 2^epoch (mod phi(p)). */
                _cleanup_(BN_clear_freep) BIGNUM *kp = NULL;
                r = compute_two_pow_mod_phi(epoch, p, bn_ctx, &kp);
                if (r < 0)
                        return r;

                /* Compute 2^epoch (mod phi(q)). */
                _cleanup_(BN_clear_freep) BIGNUM *kq = NULL;
                r = compute_two_pow_mod_phi(epoch, q, bn_ctx, &kq);
                if (r < 0)
                        return r;

                /* Compute x^(2^epoch) (mod p). */
                if (sym_BN_mod_exp(xp, xp, kp, p, bn_ctx) <= 0)
                        return -EIO;

                /* Compute x^(2^epoch) (mod q). */
                if (sym_BN_mod_exp(xq, xq, kq, q, bn_ctx) <= 0)
                        return -EIO;

                /* Reconstruct x modulo n from its residues modulo p and q. */
                BN_clear_freep(&x);
                r = crt_compose(xp, xq, p, q, bn_ctx, &x);
                if (r < 0)
                        return r;
        }

        return save_state(secpar, n, x, epoch, state);
#else
        return -EOPNOTSUPP;
#endif
}

int fsprg_evolve(struct iovec *state) {
#if HAVE_OPENSSL
        int r;

        assert(iovec_is_set(state));

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        uint16_t secpar;
        uint64_t epoch;
        _cleanup_(BN_clear_freep) BIGNUM *n = NULL, *x = NULL;
        r = parse_state(state, &secpar, &n, &x, &epoch);
        if (r < 0)
                return r;

        _cleanup_(BN_CTX_freep) BN_CTX *bn_ctx = sym_BN_CTX_secure_new();
        if (!bn_ctx)
                return -ENOMEM;

        /* Update the current state x := x^2 mod n */
        if (sym_BN_mod_sqr(x, x, n, bn_ctx) <= 0)
                return -EIO;

        /* Store the updated current state. */
        uint8_t *s = (uint8_t*) state->iov_base + sizeof(uint16_t) + secpar / 8;
        r = mpi_export(&IOVEC_MAKE(s, secpar / 8), x);
        if (r < 0)
                return r;

        /* Increment epoch */
        unaligned_write_be64(s + secpar / 8, epoch + 1);
        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int fsprg_get_epoch(const struct iovec *state, uint64_t *ret) {
#if HAVE_OPENSSL
        int r;

        assert(iovec_is_set(state));

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        return parse_state(
                        state,
                        /* ret_secpar= */ NULL,
                        /* ret_modulus= */ NULL,
                        /* ret_current= */ NULL,
                        ret);
#else
        return -EOPNOTSUPP;
#endif
}

int fsprg_get_key(const struct iovec *state, struct iovec *key) {
#if HAVE_OPENSSL
        int r;

        assert(iovec_is_set(state));
        assert(iovec_is_valid(key));

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        uint16_t secpar;
        r = parse_state(state,
                        /* ret_secpar= */ &secpar,
                        /* ret_modulus= */ NULL,
                        /* ret_current= */ NULL,
                        /* ret_epoch= */ NULL);
        if (r < 0)
                return r;

        struct iovec seed = IOVEC_MAKE(
                        (uint8_t*) state->iov_base + sizeof(uint16_t),
                        2 * secpar / 8 + sizeof(uint64_t));

        return det_randomize(&seed, /* idx= */ 0, key);
#else
        return -EOPNOTSUPP;
#endif
}
