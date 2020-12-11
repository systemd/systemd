/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * fsprg v0.1  -  (seekable) forward-secure pseudorandom generator
 * Copyright © 2012 B. Poettering
 * Contact: fsprg@point-at-infinity.org
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 */

/*
 * See "Practical Secure Logging: Seekable Sequential Key Generators"
 * by G. A. Marson, B. Poettering for details:
 *
 * http://eprint.iacr.org/2013/397
 */

#include <string.h>

#include "fsprg.h"
#include "memory-util.h"
#include "openssl-util.h"

#define ISVALID_SECPAR(secpar) (((secpar) % 16 == 0) && ((secpar) >= 16) && ((secpar) <= 16384))
#define VALIDATE_SECPAR(secpar) assert(ISVALID_SECPAR(secpar));

#define RND_HASH_OPENSSL EVP_sha256()
#define RND_GEN_P 0x01
#define RND_GEN_Q 0x02
#define RND_GEN_X 0x03

#pragma GCC diagnostic ignored "-Wpointer-arith"
/* TODO: remove void* arithmetic and this work-around */

/******************************************************************************/

static void mpi_export(void *buf, size_t buflen, const BIGNUM* x) {
        unsigned len;
        size_t nwritten;
        _cleanup_(BN_freep) BIGNUM *zero;

        zero = BN_new();
        BN_zero(zero);
        assert(BN_ucmp(x, zero) >= 0);
        len = BN_num_bytes(x);
        assert(len <= buflen);
        nwritten = BN_bn2bin(x, buf);
        assert(nwritten == len);
}

static BIGNUM* mpi_import(const void *buf, size_t buflen) {
        BIGNUM *n, *r;
        _cleanup_(BN_freep) BIGNUM *zero = NULL;
        _unused_ unsigned len;

        n = BN_new();
        zero = BN_new();
        BN_zero(zero);

        r = BN_bin2bn(buf, buflen, n);
        assert_se(r != NULL);
        len = (BN_num_bytes(n));
        assert(len <= buflen);
        assert(BN_ucmp(n, zero) >= 0);

        return n;
}


static void uint64_export(void *buf, size_t buflen, uint64_t x) {
        assert(buflen == 8);
        ((uint8_t*) buf)[0] = (x >> 56) & 0xff;
        ((uint8_t*) buf)[1] = (x >> 48) & 0xff;
        ((uint8_t*) buf)[2] = (x >> 40) & 0xff;
        ((uint8_t*) buf)[3] = (x >> 32) & 0xff;
        ((uint8_t*) buf)[4] = (x >> 24) & 0xff;
        ((uint8_t*) buf)[5] = (x >> 16) & 0xff;
        ((uint8_t*) buf)[6] = (x >>  8) & 0xff;
        ((uint8_t*) buf)[7] = (x >>  0) & 0xff;
}

_pure_ static uint64_t uint64_import(const void *buf, size_t buflen) {
        assert(buflen == 8);
        return
                (uint64_t)(((uint8_t*) buf)[0]) << 56 |
                (uint64_t)(((uint8_t*) buf)[1]) << 48 |
                (uint64_t)(((uint8_t*) buf)[2]) << 40 |
                (uint64_t)(((uint8_t*) buf)[3]) << 32 |
                (uint64_t)(((uint8_t*) buf)[4]) << 24 |
                (uint64_t)(((uint8_t*) buf)[5]) << 16 |
                (uint64_t)(((uint8_t*) buf)[6]) <<  8 |
                (uint64_t)(((uint8_t*) buf)[7]) <<  0;
}

/* deterministically generate from seed/idx a string of buflen pseudorandom bytes */
static int det_randomize(void *buf, size_t buflen, const void *seed, size_t seedlen, uint32_t idx) {
        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *ctx1 = NULL;
        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *ctx2 = NULL;
        uint8_t md[DIGEST_MAX];
        size_t olen, cpylen;
        uint32_t ctr;


        ctx1 = EVP_MD_CTX_new();
        if (!ctx1)
                return -ENOMEM;
        ctx2 = EVP_MD_CTX_new();
        if (!ctx2)
                return -ENOMEM;

        olen = EVP_MD_size(RND_HASH_OPENSSL);

        if (EVP_DigestInit_ex(ctx1, RND_HASH_OPENSSL, NULL) <= 0)
                return -EIO;

        if (EVP_DigestUpdate(ctx1, seed, seedlen) <= 0)
                return -EIO;
        if (EVP_DigestUpdate(ctx1, ((uint8_t*) &idx + 3), sizeof(uint8_t)) <= 0)
                return -EIO;
        if (EVP_DigestUpdate(ctx1, ((uint8_t*) &idx + 2), sizeof(uint8_t)) <= 0)
                return -EIO;
        if (EVP_DigestUpdate(ctx1, ((uint8_t*) &idx + 1), sizeof(uint8_t)) <= 0)
                return -EIO;
        if (EVP_DigestUpdate(ctx1, ((uint8_t*) &idx), sizeof(uint8_t)) <= 0)
                return -EIO;

        for (ctr = 0; buflen; ctr++) {
                if (EVP_MD_CTX_copy_ex(ctx2, ctx1) <=0)
                        return -EIO;
                if (EVP_DigestUpdate(ctx2, ((uint8_t*) &ctr + 3), sizeof(uint8_t)) <= 0)
                        return -EIO;
                if (EVP_DigestUpdate(ctx2, ((uint8_t*) &ctr + 2), sizeof(uint8_t)) <= 0)
                        return -EIO;
                if (EVP_DigestUpdate(ctx2, ((uint8_t*) &ctr + 1), sizeof(uint8_t)) <= 0)
                        return -EIO;
                if (EVP_DigestUpdate(ctx2, ((uint8_t*) &ctr), sizeof(uint8_t)) <= 0)
                        return -EIO;
                if (EVP_DigestFinal_ex(ctx2, md, NULL) <= 0)
                        return -EIO;
                cpylen = MIN(buflen, olen);
                memcpy(buf, md, cpylen);
                buf += cpylen;
                buflen -= cpylen;
        }

        return 0;
}

/* deterministically generate from seed/idx a prime of length `bits' that is 3 (mod 4) */
static BIGNUM* genprime3mod4(int bits, const void *seed, size_t seedlen, uint32_t idx) {
        _cleanup_(BN_CTX_freep) BN_CTX *ctx = NULL;
        size_t buflen = bits / 8;
        uint8_t buf[buflen];
        uint8_t buf2[buflen];
        memset(buf2, 0, buflen);
        BIGNUM *p;

        assert(bits % 8 == 0);
        assert(buflen > 0);

        ctx = BN_CTX_new();
        if (!ctx)
                /* Likely out of memory. */
                return NULL;

        if (det_randomize(buf, buflen, seed, seedlen, idx) < 0)
                return NULL;

        buf[0] |= 0xc0; /* set upper two bits, so that n=pq has maximum size */
        buf[buflen - 1] |= 0x03; /* set lower two bits, to have result 3 (mod 4) */

        p = mpi_import(buf, buflen);
        while (BN_is_prime_ex(p, BN_prime_checks, ctx, NULL) == 0)
                assert(BN_add_word(p, 4) == 1);

        return p;
}

/* deterministically generate from seed/idx a quadratic residue (mod n) */
static BIGNUM* gensquare(const BIGNUM *n, const void *seed, size_t seedlen, uint32_t idx, unsigned secpar) {
        size_t buflen = secpar / 8;
        uint8_t buf[buflen];
        _cleanup_(BN_CTX_freep) BN_CTX *ctx = NULL;
        BIGNUM* x;

        ctx = BN_CTX_new();
        if (!ctx)
                return NULL;

        if (det_randomize(buf, buflen, seed, seedlen, idx) < 0)
                return NULL;

        buf[0] &= 0x7f; /* clear upper bit, so that we have x < n */
        x = mpi_import(buf, buflen);
        assert(BN_cmp(x, n) < 0);
        assert(BN_mod_mul(x, x, x, n, ctx) == 1);
        return x;
}

static BIGNUM* twopowmodphi(uint64_t m, const BIGNUM *p) {
        _cleanup_(BN_freep) BIGNUM *phi = NULL;
        _cleanup_(BN_CTX_freep) BN_CTX *ctx = NULL;
        BIGNUM *r;
        int n;

        phi = BN_new();
        if (!phi)
                return NULL;
        phi = BN_dup(p);
        if (!phi)
                return NULL;

        assert(BN_sub_word(phi, 1) == 1);

        /* count number of used bits in m */
        for (n = 0; (1ULL << n) <= m; n++)
                ;

        r = BN_new();
        if (!r)
                return NULL;

        ctx = BN_CTX_new();
        if (!ctx)
                return NULL;

        assert(BN_set_word(r, 1) == 1);
        while (n) { /* square and multiply algorithm for fast exponentiation */
                n--;
                assert(BN_mod_mul(r, r, r, phi, ctx) == 1);;
                if (m & ((uint64_t)1 << n)) {
                        assert(BN_add(r, r, r) == 1);
                        if (BN_cmp(r, phi) >= 0)
                                assert(BN_sub(r, r, r) == 1);
                }
        }

        return r;
}

/* Decompose $x \in Z_n$ into $(xp,xq) \in Z_p \times Z_q$ using Chinese Remainder Theorem */
static int CRT_decompose(BIGNUM *xp, BIGNUM *xq, const BIGNUM *x, const BIGNUM *p, const BIGNUM *q) {
        _cleanup_(BN_CTX_freep) BN_CTX *ctx = NULL;
        ctx = BN_CTX_new();
        if (!ctx)
                return -EIO;

        BN_zero(xp);
        BN_zero(xq);
        BN_mod(xp, x, p, ctx);
        BN_mod(xq, x, q, ctx);

        return 0;
}

/* Compose $(xp,xq) \in Z_p \times Z_q$ into $x \in Z_n$ using Chinese Remainder Theorem */
static int CRT_compose(BIGNUM *x, const BIGNUM *xp, const BIGNUM *xq, const BIGNUM *p, const BIGNUM *q) {
        _cleanup_(BN_freep) BIGNUM *a = NULL, *u = NULL;
        _cleanup_(BN_CTX_freep) BN_CTX *ctx = NULL;
        if (!(a = BN_new()))
                return -ENOMEM;
        if (!(u = BN_new()))
                return -ENOMEM;
        if (!(ctx = BN_CTX_new()))
                return -ENOMEM;

        BN_zero(a);
        BN_zero(u);
        BN_zero(x);
        assert(BN_mod_sub(a, xq, xp, q, ctx) == 1);
        assert(BN_mod_inverse(u, p, q, ctx));
        assert(BN_mod_mul(a, a, u, q, ctx) == 1); /* a = (xq - xp) / p  (mod q) */
        assert(BN_mul(x, p, a, ctx) == 1);
        assert(BN_add(x, x, p) == 1); /* x = p * ((xq - xp) / p mod q) + xp */

        return 0;
}

/******************************************************************************/

size_t FSPRG_mskinbytes(unsigned _secpar) {
        VALIDATE_SECPAR(_secpar);
        return 2 + 2 * (_secpar / 2) / 8; /* to store header,p,q */
}

size_t FSPRG_mpkinbytes(unsigned _secpar) {
        VALIDATE_SECPAR(_secpar);
        return 2 + _secpar / 8; /* to store header,n */
}

size_t FSPRG_stateinbytes(unsigned _secpar) {
        VALIDATE_SECPAR(_secpar);
        return 2 + 2 * _secpar / 8 + 8; /* to store header,n,x,epoch */
}

static void store_secpar(void *buf, uint16_t secpar) {
        secpar = secpar / 16 - 1;
        ((uint8_t*) buf)[0] = (secpar >> 8) & 0xff;
        ((uint8_t*) buf)[1] = (secpar >> 0) & 0xff;
}

static uint16_t read_secpar(const void *buf) {
        uint16_t secpar;
        secpar =
                (uint16_t)(((uint8_t*) buf)[0]) << 8 |
                (uint16_t)(((uint8_t*) buf)[1]) << 0;
        return 16 * (secpar + 1);
}

void FSPRG_GenMK(void *msk, void *mpk, const void *seed, size_t seedlen, unsigned _secpar) {
        uint8_t iseed[FSPRG_RECOMMENDED_SEEDLEN];
        _cleanup_(BN_freep) BIGNUM *n = NULL, *p = NULL, *q = NULL;
        uint16_t secpar;

        VALIDATE_SECPAR(_secpar);
        secpar = _secpar;

        if (!seed) {
                assert(RAND_priv_bytes(iseed, FSPRG_RECOMMENDED_SEEDLEN));
                seed = iseed;
                seedlen = FSPRG_RECOMMENDED_SEEDLEN;
        }

        p = genprime3mod4(secpar / 2, seed, seedlen, RND_GEN_P);
        assert(p);
        q = genprime3mod4(secpar / 2, seed, seedlen, RND_GEN_Q);
        assert(q);

        if (msk) {
                store_secpar(msk + 0, secpar);
                mpi_export(msk + 2 + 0 * (secpar / 2) / 8, (secpar / 2) / 8, p);
                mpi_export(msk + 2 + 1 * (secpar / 2) / 8, (secpar / 2) / 8, q);
        }

        if (mpk) {
                _cleanup_(BN_CTX_freep) BN_CTX *ctx = NULL;
                ctx = BN_CTX_new();
                assert(ctx);
                n = BN_new();
                BN_zero(n);
                assert(BN_mul(n, p, q, ctx) == 1);
                assert(BN_num_bits(n) == secpar);

                store_secpar(mpk + 0, secpar);
                mpi_export(mpk + 2, secpar / 8, n);
        }
}

void FSPRG_GenState0(void *state, const void *mpk, const void *seed, size_t seedlen) {
        _cleanup_(BN_freep) BIGNUM *n = NULL, *x = NULL;
        uint16_t secpar;

        secpar = read_secpar(mpk + 0);
        n = mpi_import(mpk + 2, secpar / 8);
        x = gensquare(n, seed, seedlen, RND_GEN_X, secpar);
        assert(x);

        memcpy(state, mpk, 2 + secpar / 8);
        mpi_export(state + 2 + 1 * secpar / 8, secpar / 8, x);
        memzero(state + 2 + 2 * secpar / 8, 8);
}

int FSPRG_Evolve(void *state) {
        _cleanup_(BN_freep) BIGNUM *n = NULL, *x = NULL;
        _cleanup_(BN_CTX_freep) BN_CTX *ctx = NULL;
        uint16_t secpar;
        uint64_t epoch;

        n = BN_new();
        if (!n)
                return -ENOMEM;
        x = BN_new();
        if (!x)
                return -ENOMEM;
        ctx = BN_CTX_new();
        if (!ctx)
                return -ENOMEM;

        secpar = read_secpar(state + 0);
        n = mpi_import(state + 2 + 0 * secpar / 8, secpar / 8);
        x = mpi_import(state + 2 + 1 * secpar / 8, secpar / 8);
        epoch = uint64_import(state + 2 + 2 * secpar / 8, 8);

        if (BN_mod_mul(x, x, x, n, ctx) <= 0)
                return -EIO;
        epoch++;

        mpi_export(state + 2 + 1 * secpar / 8, secpar / 8, x);
        uint64_export(state + 2 + 2 * secpar / 8, 8, epoch);

        return 0;
}

uint64_t FSPRG_GetEpoch(const void *state) {
        uint16_t secpar;
        secpar = read_secpar(state + 0);
        return uint64_import(state + 2 + 2 * secpar / 8, 8);
}

int FSPRG_Seek(void *state, uint64_t epoch, const void *msk, const void *seed, size_t seedlen) {
        _cleanup_(BN_freep) BIGNUM *p = NULL, *q = NULL, *n = NULL, *x = NULL, *xp = NULL,
                *xq = NULL, *kp = NULL, *kq = NULL, *xm = NULL;
        _cleanup_(BN_CTX_freep) BN_CTX *ctx = NULL;
        uint16_t secpar;
        int r;

        // Ugh...
        if (!(p = BN_new()) ||
                !(q = BN_new()) ||
                !(n = BN_new()) ||
                !(x = BN_new()) ||
                !(xp = BN_new()) ||
                !(xq = BN_new()) ||
                !(kp = BN_new()) ||
                !(kq = BN_new()) ||
                !(xm = BN_new()) ||
                !(ctx = BN_CTX_new())
           )
                return -ENOMEM;

        secpar = read_secpar(msk + 0);
        p  = mpi_import(msk + 2 + 0 * (secpar / 2) / 8, (secpar / 2) / 8);
        q  = mpi_import(msk + 2 + 1 * (secpar / 2) / 8, (secpar / 2) / 8);

        BN_zero(n);
        assert(BN_mul(n, p, q, ctx) == 1);

        x = gensquare(n, seed, seedlen, RND_GEN_X, secpar);
        r = CRT_decompose(xp, xq, x, p, q); /* split (mod n) into (mod p) and (mod q) using CRT */
        if (r < 0)
                return r;

        kp = twopowmodphi(epoch, p); /* compute 2^epoch (mod phi(p)) */
        assert(kp);
        kq = twopowmodphi(epoch, q); /* compute 2^epoch (mod phi(q)) */
        assert(kq);

        assert(BN_mod_exp(xp, xp, kp, p, ctx) == 1); /* compute x^(2^epoch) (mod p) */
        assert(BN_mod_exp(xq, xq, kq, q, ctx) == 1); /* compute x^(2^epoch) (mod q) */

        r = CRT_compose(xm, xp, xq, p, q); /* combine (mod p) and (mod q) to (mod n) using CRT */
        if (r < 0)
                return r;

        store_secpar(state + 0, secpar);
        mpi_export(state + 2 + 0 * secpar / 8, secpar / 8, n);
        mpi_export(state + 2 + 1 * secpar / 8, secpar / 8, xm);
        uint64_export(state + 2 + 2 * secpar / 8, 8, epoch);

        return 0;
}

void FSPRG_GetKey(const void *state, void *key, size_t keylen, uint32_t idx) {
        uint16_t secpar;

        secpar = read_secpar(state + 0);
        assert(det_randomize(key, keylen, state + 2, 2 * secpar / 8 + 8, idx) == 0);
}
