/* SPDX-License-Identifier: LGPL-2.1+
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

#include <gcrypt.h>
#include <string.h>

#include "fsprg.h"
#include "gcrypt-util.h"
#include "memory-util.h"

#define ISVALID_SECPAR(secpar) (((secpar) % 16 == 0) && ((secpar) >= 16) && ((secpar) <= 16384))
#define VALIDATE_SECPAR(secpar) assert(ISVALID_SECPAR(secpar));

#define RND_HASH GCRY_MD_SHA256
#define RND_GEN_P 0x01
#define RND_GEN_Q 0x02
#define RND_GEN_X 0x03

#pragma GCC diagnostic ignored "-Wpointer-arith"
/* TODO: remove void* arithmetic and this work-around */

/******************************************************************************/

static void mpi_export(void *buf, size_t buflen, const gcry_mpi_t x) {
        unsigned len;
        size_t nwritten;

        assert(gcry_mpi_cmp_ui(x, 0) >= 0);
        len = (gcry_mpi_get_nbits(x) + 7) / 8;
        assert(len <= buflen);
        memzero(buf, buflen);
        gcry_mpi_print(GCRYMPI_FMT_USG, buf + (buflen - len), len, &nwritten, x);
        assert(nwritten == len);
}

static gcry_mpi_t mpi_import(const void *buf, size_t buflen) {
        gcry_mpi_t h;
        unsigned len;

        assert_se(gcry_mpi_scan(&h, GCRYMPI_FMT_USG, buf, buflen, NULL) == 0);
        len = (gcry_mpi_get_nbits(h) + 7) / 8;
        assert(len <= buflen);
        assert(gcry_mpi_cmp_ui(h, 0) >= 0);

        return h;
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
static void det_randomize(void *buf, size_t buflen, const void *seed, size_t seedlen, uint32_t idx) {
        gcry_md_hd_t hd, hd2;
        size_t olen, cpylen;
        uint32_t ctr;

        olen = gcry_md_get_algo_dlen(RND_HASH);
        gcry_md_open(&hd, RND_HASH, 0);
        gcry_md_write(hd, seed, seedlen);
        gcry_md_putc(hd, (idx >> 24) & 0xff);
        gcry_md_putc(hd, (idx >> 16) & 0xff);
        gcry_md_putc(hd, (idx >>  8) & 0xff);
        gcry_md_putc(hd, (idx >>  0) & 0xff);

        for (ctr = 0; buflen; ctr++) {
                gcry_md_copy(&hd2, hd);
                gcry_md_putc(hd2, (ctr >> 24) & 0xff);
                gcry_md_putc(hd2, (ctr >> 16) & 0xff);
                gcry_md_putc(hd2, (ctr >>  8) & 0xff);
                gcry_md_putc(hd2, (ctr >>  0) & 0xff);
                gcry_md_final(hd2);
                cpylen = (buflen < olen) ? buflen : olen;
                memcpy(buf, gcry_md_read(hd2, RND_HASH), cpylen);
                gcry_md_close(hd2);
                buf += cpylen;
                buflen -= cpylen;
        }
        gcry_md_close(hd);
}

/* deterministically generate from seed/idx a prime of length `bits' that is 3 (mod 4) */
static gcry_mpi_t genprime3mod4(int bits, const void *seed, size_t seedlen, uint32_t idx) {
        size_t buflen = bits / 8;
        uint8_t buf[buflen];
        gcry_mpi_t p;

        assert(bits % 8 == 0);
        assert(buflen > 0);

        det_randomize(buf, buflen, seed, seedlen, idx);
        buf[0] |= 0xc0; /* set upper two bits, so that n=pq has maximum size */
        buf[buflen - 1] |= 0x03; /* set lower two bits, to have result 3 (mod 4) */

        p = mpi_import(buf, buflen);
        while (gcry_prime_check(p, 0))
                gcry_mpi_add_ui(p, p, 4);

        return p;
}

/* deterministically generate from seed/idx a quadratic residue (mod n) */
static gcry_mpi_t gensquare(const gcry_mpi_t n, const void *seed, size_t seedlen, uint32_t idx, unsigned secpar) {
        size_t buflen = secpar / 8;
        uint8_t buf[buflen];
        gcry_mpi_t x;

        det_randomize(buf, buflen, seed, seedlen, idx);
        buf[0] &= 0x7f; /* clear upper bit, so that we have x < n */
        x = mpi_import(buf, buflen);
        assert(gcry_mpi_cmp(x, n) < 0);
        gcry_mpi_mulm(x, x, x, n);
        return x;
}

/* compute 2^m (mod phi(p)), for a prime p */
static gcry_mpi_t twopowmodphi(uint64_t m, const gcry_mpi_t p) {
        gcry_mpi_t phi, r;
        int n;

        phi = gcry_mpi_new(0);
        gcry_mpi_sub_ui(phi, p, 1);

        /* count number of used bits in m */
        for (n = 0; (1ULL << n) <= m; n++)
                ;

        r = gcry_mpi_new(0);
        gcry_mpi_set_ui(r, 1);
        while (n) { /* square and multiply algorithm for fast exponentiation */
                n--;
                gcry_mpi_mulm(r, r, r, phi);
                if (m & ((uint64_t)1 << n)) {
                        gcry_mpi_add(r, r, r);
                        if (gcry_mpi_cmp(r, phi) >= 0)
                                gcry_mpi_sub(r, r, phi);
                }
        }

        gcry_mpi_release(phi);
        return r;
}

/* Decompose $x \in Z_n$ into $(xp,xq) \in Z_p \times Z_q$ using Chinese Remainder Theorem */
static void CRT_decompose(gcry_mpi_t *xp, gcry_mpi_t *xq, const gcry_mpi_t x, const gcry_mpi_t p, const gcry_mpi_t q) {
        *xp = gcry_mpi_new(0);
        *xq = gcry_mpi_new(0);
        gcry_mpi_mod(*xp, x, p);
        gcry_mpi_mod(*xq, x, q);
}

/* Compose $(xp,xq) \in Z_p \times Z_q$ into $x \in Z_n$ using Chinese Remainder Theorem */
static void CRT_compose(gcry_mpi_t *x, const gcry_mpi_t xp, const gcry_mpi_t xq, const gcry_mpi_t p, const gcry_mpi_t q) {
        gcry_mpi_t a, u;

        a = gcry_mpi_new(0);
        u = gcry_mpi_new(0);
        *x = gcry_mpi_new(0);
        gcry_mpi_subm(a, xq, xp, q);
        gcry_mpi_invm(u, p, q);
        gcry_mpi_mulm(a, a, u, q); /* a = (xq - xp) / p  (mod q) */
        gcry_mpi_mul(*x, p, a);
        gcry_mpi_add(*x, *x, xp); /* x = p * ((xq - xp) / p mod q) + xp */
        gcry_mpi_release(a);
        gcry_mpi_release(u);
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
        gcry_mpi_t n, p, q;
        uint16_t secpar;

        VALIDATE_SECPAR(_secpar);
        secpar = _secpar;

        initialize_libgcrypt(false);

        if (!seed) {
                gcry_randomize(iseed, FSPRG_RECOMMENDED_SEEDLEN, GCRY_STRONG_RANDOM);
                seed = iseed;
                seedlen = FSPRG_RECOMMENDED_SEEDLEN;
        }

        p = genprime3mod4(secpar / 2, seed, seedlen, RND_GEN_P);
        q = genprime3mod4(secpar / 2, seed, seedlen, RND_GEN_Q);

        if (msk) {
                store_secpar(msk + 0, secpar);
                mpi_export(msk + 2 + 0 * (secpar / 2) / 8, (secpar / 2) / 8, p);
                mpi_export(msk + 2 + 1 * (secpar / 2) / 8, (secpar / 2) / 8, q);
        }

        if (mpk) {
                n = gcry_mpi_new(0);
                gcry_mpi_mul(n, p, q);
                assert(gcry_mpi_get_nbits(n) == secpar);

                store_secpar(mpk + 0, secpar);
                mpi_export(mpk + 2, secpar / 8, n);

                gcry_mpi_release(n);
        }

        gcry_mpi_release(p);
        gcry_mpi_release(q);
}

void FSPRG_GenState0(void *state, const void *mpk, const void *seed, size_t seedlen) {
        gcry_mpi_t n, x;
        uint16_t secpar;

        initialize_libgcrypt(false);

        secpar = read_secpar(mpk + 0);
        n = mpi_import(mpk + 2, secpar / 8);
        x = gensquare(n, seed, seedlen, RND_GEN_X, secpar);

        memcpy(state, mpk, 2 + secpar / 8);
        mpi_export(state + 2 + 1 * secpar / 8, secpar / 8, x);
        memzero(state + 2 + 2 * secpar / 8, 8);

        gcry_mpi_release(n);
        gcry_mpi_release(x);
}

void FSPRG_Evolve(void *state) {
        gcry_mpi_t n, x;
        uint16_t secpar;
        uint64_t epoch;

        initialize_libgcrypt(false);

        secpar = read_secpar(state + 0);
        n = mpi_import(state + 2 + 0 * secpar / 8, secpar / 8);
        x = mpi_import(state + 2 + 1 * secpar / 8, secpar / 8);
        epoch = uint64_import(state + 2 + 2 * secpar / 8, 8);

        gcry_mpi_mulm(x, x, x, n);
        epoch++;

        mpi_export(state + 2 + 1 * secpar / 8, secpar / 8, x);
        uint64_export(state + 2 + 2 * secpar / 8, 8, epoch);

        gcry_mpi_release(n);
        gcry_mpi_release(x);
}

uint64_t FSPRG_GetEpoch(const void *state) {
        uint16_t secpar;
        secpar = read_secpar(state + 0);
        return uint64_import(state + 2 + 2 * secpar / 8, 8);
}

void FSPRG_Seek(void *state, uint64_t epoch, const void *msk, const void *seed, size_t seedlen) {
        gcry_mpi_t p, q, n, x, xp, xq, kp, kq, xm;
        uint16_t secpar;

        initialize_libgcrypt(false);

        secpar = read_secpar(msk + 0);
        p  = mpi_import(msk + 2 + 0 * (secpar / 2) / 8, (secpar / 2) / 8);
        q  = mpi_import(msk + 2 + 1 * (secpar / 2) / 8, (secpar / 2) / 8);

        n = gcry_mpi_new(0);
        gcry_mpi_mul(n, p, q);

        x = gensquare(n, seed, seedlen, RND_GEN_X, secpar);
        CRT_decompose(&xp, &xq, x, p, q); /* split (mod n) into (mod p) and (mod q) using CRT */

        kp = twopowmodphi(epoch, p); /* compute 2^epoch (mod phi(p)) */
        kq = twopowmodphi(epoch, q); /* compute 2^epoch (mod phi(q)) */

        gcry_mpi_powm(xp, xp, kp, p); /* compute x^(2^epoch) (mod p) */
        gcry_mpi_powm(xq, xq, kq, q); /* compute x^(2^epoch) (mod q) */

        CRT_compose(&xm, xp, xq, p, q); /* combine (mod p) and (mod q) to (mod n) using CRT */

        store_secpar(state + 0, secpar);
        mpi_export(state + 2 + 0 * secpar / 8, secpar / 8, n);
        mpi_export(state + 2 + 1 * secpar / 8, secpar / 8, xm);
        uint64_export(state + 2 + 2 * secpar / 8, 8, epoch);

        gcry_mpi_release(p);
        gcry_mpi_release(q);
        gcry_mpi_release(n);
        gcry_mpi_release(x);
        gcry_mpi_release(xp);
        gcry_mpi_release(xq);
        gcry_mpi_release(kp);
        gcry_mpi_release(kq);
        gcry_mpi_release(xm);
}

void FSPRG_GetKey(const void *state, void *key, size_t keylen, uint32_t idx) {
        uint16_t secpar;

        initialize_libgcrypt(false);

        secpar = read_secpar(state + 0);
        det_randomize(key, keylen, state + 2, 2 * secpar / 8 + 8, idx);
}
