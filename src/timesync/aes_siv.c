/* Copyright (c) 2017-2019 Akamai Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200112L
#define _ISOC99_SOURCE 1

#include "config.h"
#include "aes_siv.h"

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#ifdef ENABLE_DEBUG_OUTPUT
#include <stdio.h>
#endif
#ifdef _MSC_VER
/* For _byteswap_uint64 */
#include <stdlib.h>
#endif
#include <string.h>

#include <openssl/cmac.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#ifdef ENABLE_CTGRIND
#include <ctgrind.h>
#endif

#if CHAR_BIT != 8
#error "libaes_siv requires an 8-bit char type"
#endif

#if -1 != ~0
#error "libaes_siv requires a two's-complement architecture"
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901
#undef inline
#elif defined(__GNUC__) || defined(__clang__)
#define inline __inline__
#elif defined(_MSC_VER)
#define inline __inline
#else
#define inline
#endif

#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(cond) __builtin_expect(cond, 1)
#define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#define LIKELY(cond) cond
#define UNLIKELY(cond) cond
#endif

#ifndef ENABLE_CTGRIND
static inline void ct_poison(const void *data, size_t len) {
        (void)data;
        (void)len;
}
static inline void ct_unpoison(const void *data, size_t len) {
        (void)data;
        (void)len;
}
#endif

static void debug(const char *label, const unsigned char *hex, size_t len) {
/* ENABLE_CTGRIND has to override ENABLE_DEBUG_OUTPUT since sensitive data
   gets printed.
*/
#if defined(ENABLE_DEBUG_OUTPUT) && !defined(ENABLE_CTGRIND)
        size_t i;
        printf("%16s: ", label);
        for (i = 0; i < len; i++) {
                if (i > 0 && i % 16 == 0) {
                        printf("\n                  ");
                }
                printf("%.2x", (int)hex[i]);
                if (i > 0 && i % 4 == 3) {
                        printf(" ");
                }
        }
        printf("\n");
#else
        (void)label;
        (void)hex;
        (void)len;
#endif
}

typedef union block_un {
        uint64_t word[2];
        unsigned char byte[16];
} block;

const union {
        uint64_t word;
        char byte[8];
} endian = {0x0102030405060708};

#define I_AM_BIG_ENDIAN (endian.byte[0] == 1 && \
                         endian.byte[1] == 2 && \
                         endian.byte[2] == 3 && \
                         endian.byte[3] == 4 && \
                         endian.byte[4] == 5 && \
                         endian.byte[5] == 6 && \
                         endian.byte[6] == 7 && \
                         endian.byte[7] == 8)

#define I_AM_LITTLE_ENDIAN (endian.byte[0] == 8 && \
                            endian.byte[1] == 7 && \
                            endian.byte[2] == 6 && \
                            endian.byte[3] == 5 && \
                            endian.byte[4] == 4 && \
                            endian.byte[5] == 3 && \
                            endian.byte[6] == 2 && \
                            endian.byte[7] == 1)

#if defined(__GNUC__) || defined(__clang__)
static inline uint64_t bswap64(uint64_t x) { return __builtin_bswap64(x); }
#elif defined(_MSC_VER)
static inline uint64_t bswap64(uint64_t x) { return _byteswap_uint64(x); }
#else

static inline uint32_t rotl(uint32_t x) { return (x << 8) | (x >> 24); }
static inline uint32_t rotr(uint32_t x) { return (x >> 8) | (x << 24); }

static inline uint64_t bswap64(uint64_t x) {
        uint32_t high = (uint32_t)(x >> 32);
        uint32_t low = (uint32_t)x;

        high = (rotl(high) & 0x00ff00ff) | (rotr(high) & 0xff00ff00);
        low = (rotl(low) & 0x00ff00ff) | (rotr(low) & 0xff00ff00);
        return ((uint64_t)low) << 32 | (uint64_t)high;
}
#endif

static inline uint64_t getword(block const *b, size_t i) {
#ifndef ENABLE_DEBUG_WEIRD_ENDIAN
        if (I_AM_BIG_ENDIAN) {
                return b->word[i];
        } else if (I_AM_LITTLE_ENDIAN) {
                return bswap64(b->word[i]);
        } else {
#endif
                i <<= 3;
                return ((uint64_t)b->byte[i + 7]) |
                       ((uint64_t)b->byte[i + 6] << 8) |
                       ((uint64_t)b->byte[i + 5] << 16) |
                       ((uint64_t)b->byte[i + 4] << 24) |
                       ((uint64_t)b->byte[i + 3] << 32) |
                       ((uint64_t)b->byte[i + 2] << 40) |
                       ((uint64_t)b->byte[i + 1] << 48) |
                       ((uint64_t)b->byte[i] << 56);
#ifndef ENABLE_DEBUG_WEIRD_ENDIAN
        }
#endif
}

static inline void putword(block *b, size_t i, uint64_t x) {
#ifndef ENABLE_DEBUG_WEIRD_ENDIAN
        if (I_AM_BIG_ENDIAN) {
                b->word[i] = x;
        } else if (I_AM_LITTLE_ENDIAN) {
                b->word[i] = bswap64(x);
        } else {
#endif
                i <<= 3;
                b->byte[i] = (unsigned char)(x >> 56);
                b->byte[i + 1] = (unsigned char)((x >> 48) & 0xff);
                b->byte[i + 2] = (unsigned char)((x >> 40) & 0xff);
                b->byte[i + 3] = (unsigned char)((x >> 32) & 0xff);
                b->byte[i + 4] = (unsigned char)((x >> 24) & 0xff);
                b->byte[i + 5] = (unsigned char)((x >> 16) & 0xff);
                b->byte[i + 6] = (unsigned char)((x >> 8) & 0xff);
                b->byte[i + 7] = (unsigned char)(x & 0xff);
#ifndef ENABLE_DEBUG_WEIRD_ENDIAN
        }
#endif
}

static inline void xorblock(block *x, block const *y) {
        x->word[0] ^= y->word[0];
        x->word[1] ^= y->word[1];
}

/* Doubles `block`, which is 16 bytes representing an element
   of GF(2**128) modulo the irreducible polynomial
   x**128 + x**7 + x**2 + x + 1. */
static inline void dbl(block *b) {
        uint64_t high = getword(b, 0);
        uint64_t low = getword(b, 1);
        uint64_t high_carry = high & (((uint64_t)1) << 63);
        uint64_t low_carry = low & (((uint64_t)1) << 63);
        /* Assumes two's-complement arithmetic */
        int64_t low_mask = -((int64_t)(high_carry >> 63)) & 0x87;
        uint64_t high_mask = low_carry >> 63;
        high = (high << 1) | high_mask;
        low = (low << 1) ^ (uint64_t)low_mask;
        putword(b, 0, high);
        putword(b, 1, low);
}

struct AES_SIV_CTX_st {
        /* d stores intermediate results of S2V; it corresponds to D from the
           pseudocode in section 2.4 of RFC 5297. */
        block d;
        EVP_CIPHER_CTX *cipher_ctx;
        /* SIV_AES_Init() sets up cmac_ctx_init. cmac_ctx is a scratchpad used
           by SIV_AES_AssociateData() and SIV_AES_(En|De)cryptFinal. */
        CMAC_CTX *cmac_ctx_init, *cmac_ctx;
};

void AES_SIV_CTX_cleanup(AES_SIV_CTX *ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_reset(ctx->cipher_ctx);
#else
        EVP_CIPHER_CTX_cleanup(ctx->cipher_ctx);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && OPENSSL_VERSION_NUMBER <= 0x10100060L
        /* Workaround for an OpenSSL bug that causes a double free
           if you call CMAC_CTX_cleanup() before CMAC_CTX_free().
           https://github.com/openssl/openssl/pull/2798
        */
        CMAC_CTX_free(ctx->cmac_ctx_init);
        ctx->cmac_ctx_init = CMAC_CTX_new();
        CMAC_CTX_free(ctx->cmac_ctx);
        ctx->cmac_ctx = CMAC_CTX_new();
#else
        CMAC_CTX_cleanup(ctx->cmac_ctx_init);
        CMAC_CTX_cleanup(ctx->cmac_ctx);
#endif
        OPENSSL_cleanse(&ctx->d, sizeof ctx->d);
}

void AES_SIV_CTX_free(AES_SIV_CTX *ctx) {
        if (ctx) {
                EVP_CIPHER_CTX_free(ctx->cipher_ctx);
                /* Prior to OpenSSL 1.0.2b, CMAC_CTX_free() crashes on NULL */
                if (LIKELY(ctx->cmac_ctx_init != NULL)) {
                        CMAC_CTX_free(ctx->cmac_ctx_init);
                }
                if (LIKELY(ctx->cmac_ctx != NULL)) {
                        CMAC_CTX_free(ctx->cmac_ctx);
                }
                OPENSSL_cleanse(&ctx->d, sizeof ctx->d);
                OPENSSL_free(ctx);
        }
}

AES_SIV_CTX *AES_SIV_CTX_new(void) {
        AES_SIV_CTX *ctx = OPENSSL_malloc(sizeof(struct AES_SIV_CTX_st));
        if (UNLIKELY(ctx == NULL)) {
                return NULL;
        }

        ctx->cipher_ctx = EVP_CIPHER_CTX_new();
        ctx->cmac_ctx_init = CMAC_CTX_new();
        ctx->cmac_ctx = CMAC_CTX_new();

        if (UNLIKELY(ctx->cipher_ctx == NULL ||
                     ctx->cmac_ctx_init == NULL ||
                     ctx->cmac_ctx == NULL)) {
                AES_SIV_CTX_free(ctx);
                return NULL;
        }

        return ctx;
}

int AES_SIV_CTX_copy(AES_SIV_CTX *dst, AES_SIV_CTX const *src) {
        memcpy(&dst->d, &src->d, sizeof src->d);
        if(UNLIKELY(EVP_CIPHER_CTX_copy(dst->cipher_ctx, src->cipher_ctx)
                    != 1)) {
                return 0;
        }
        if (UNLIKELY(CMAC_CTX_copy(dst->cmac_ctx_init, src->cmac_ctx_init)
                     != 1)) {
                return 0;
        }
        /* Not necessary to copy cmac_ctx since it's just temporary
         * storage */
        return 1;
}

int AES_SIV_Init(AES_SIV_CTX *ctx, unsigned char const *key, size_t key_len) {
        static const unsigned char zero[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 0};
        size_t out_len;
        int ret = 0;

        ct_poison(key, key_len);

        switch (key_len) {
        case 32:
                if (UNLIKELY(CMAC_Init(ctx->cmac_ctx_init, key, 16,
                                       EVP_aes_128_cbc(), NULL) != 1)) {
                        goto done;
                }
                if (UNLIKELY(EVP_EncryptInit_ex(ctx->cipher_ctx,
                                                EVP_aes_128_ctr(),
                                                NULL, key + 16, NULL) != 1)) {
                        goto done;
                }
                break;
        case 48:
                if (UNLIKELY(CMAC_Init(ctx->cmac_ctx_init, key, 24,
                                       EVP_aes_192_cbc(), NULL) != 1)) {
                        goto done;
                }
                if (UNLIKELY(EVP_EncryptInit_ex(ctx->cipher_ctx,
                                                EVP_aes_192_ctr(),
                                                NULL, key + 24, NULL) != 1)) {
                        goto done;
                }
                break;
        case 64:
                if (UNLIKELY(CMAC_Init(ctx->cmac_ctx_init, key, 32,
                                       EVP_aes_256_cbc(), NULL) != 1)) {
                        goto done;
                }
                if (UNLIKELY(EVP_EncryptInit_ex(ctx->cipher_ctx,
                                                EVP_aes_256_ctr(),
                                                NULL, key + 32, NULL) != 1)) {
                        goto done;
                }
                break;
        default:
                goto done;
        }

        if (UNLIKELY(CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1)) {
                goto done;
        }
        if (UNLIKELY(CMAC_Update(ctx->cmac_ctx, zero, sizeof zero) != 1)) {
                goto done;
        }
        out_len = sizeof ctx->d;
        if (UNLIKELY(CMAC_Final(ctx->cmac_ctx, ctx->d.byte, &out_len) != 1)) {
                goto done;
        }
        debug("CMAC(zero)", ctx->d.byte, out_len);
        ret = 1;

 done:
        ct_unpoison(key, key_len);
        return ret;
}

int AES_SIV_AssociateData(AES_SIV_CTX *ctx, unsigned char const *data,
                          size_t len) {
        block cmac_out;
        size_t out_len = sizeof cmac_out;
        int ret = 0;

        ct_poison(data, len);

        dbl(&ctx->d);
        debug("double()", ctx->d.byte, 16);

        if (UNLIKELY(CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1)) {
                goto done;
        }
        if (UNLIKELY(CMAC_Update(ctx->cmac_ctx, data, len) != 1)) {
                goto done;
        }
        if (UNLIKELY(CMAC_Final(ctx->cmac_ctx, cmac_out.byte, &out_len) != 1)) {
                goto done;
        }
        assert(out_len == 16);
        debug("CMAC(ad)", cmac_out.byte, 16);

        xorblock(&ctx->d, &cmac_out);
        debug("xor", ctx->d.byte, 16);
        ret = 1;

done:
        ct_unpoison(data, len);
        return ret;
}

static inline int do_s2v_p(AES_SIV_CTX *ctx, block *out,
                           unsigned char const* in, size_t len) {
        block t;
        size_t out_len = sizeof out->byte;

        if (UNLIKELY(CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1)) {
                return 0;
        }

        if(len >= 16) {
                if(UNLIKELY(CMAC_Update(ctx->cmac_ctx, in, len - 16) != 1)) {
                        return 0;
                }
                debug("xorend part 1", in, len - 16);
                memcpy(&t, in + (len-16), 16);
                xorblock(&t, &ctx->d);
                debug("xorend part 2", t.byte, 16);
                if(UNLIKELY(CMAC_Update(ctx->cmac_ctx, t.byte, 16) != 1)) {
                        return 0;
                }
        } else {
                size_t i;
                memcpy(&t, in, len);
                t.byte[len] = 0x80;
                for(i = len + 1; i < 16; i++) {
                        t.byte[i] = 0;
                }
                debug("pad", t.byte, 16);
                dbl(&ctx->d);
                xorblock(&t, &ctx->d);
                debug("xor", t.byte, 16);
                if(UNLIKELY(CMAC_Update(ctx->cmac_ctx, t.byte, 16) != 1)) {
                        return 0;
                }
        }
        if(UNLIKELY(CMAC_Final(ctx->cmac_ctx, out->byte, &out_len) != 1)) {
                return 0;
        }
        assert(out_len == 16);
        debug("CMAC(final)", out->byte, 16);
        return 1;
}

static inline int do_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             unsigned char const *in, size_t len, block *icv) {
#ifdef ENABLE_DEBUG_TINY_CHUNK_SIZE
        const int chunk_size = 7;
#else
        const int chunk_size = 1 << 30;
#endif
        size_t len_remaining = len;
        int out_len;
        int ret;

        if(UNLIKELY(EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, icv->byte)
                    != 1)) {
                return 0;
        }

        while(UNLIKELY(len_remaining > (size_t)chunk_size)) {
                out_len = chunk_size;
                if(UNLIKELY(EVP_EncryptUpdate(ctx, out, &out_len, in, out_len)
                            != 1)) {
                        return 0;
                }
                assert(out_len == chunk_size);
                out += out_len;
                in += out_len;
                len_remaining -= (size_t)out_len;
        }

        out_len = (int)len_remaining;
        ret = EVP_EncryptUpdate(ctx, out, &out_len, in, out_len);
        assert(!ret || out_len == (int)len_remaining);
        return ret;
}

int AES_SIV_EncryptFinal(AES_SIV_CTX *ctx, unsigned char *v_out,
                         unsigned char *c_out, unsigned char const *plaintext,
                         size_t len) {
        block q;
        int ret = 0;

        ct_poison(plaintext, len);

        if(UNLIKELY(do_s2v_p(ctx, &q, plaintext, len) != 1)) {
                goto done;
        }

        ct_unpoison(&q, sizeof q);
        memcpy(v_out, &q, 16);
        q.byte[8] &= 0x7f;
        q.byte[12] &= 0x7f;

        if(UNLIKELY(do_encrypt(ctx->cipher_ctx, c_out, plaintext, len, &q)
                    != 1)) {
                goto done;
        }

        ret = 1;
        debug("ciphertext", c_out, len);

done:
        ct_unpoison(plaintext, len);
        ct_unpoison(c_out, len);
        ct_unpoison(v_out, 16);
        return ret;
}

int AES_SIV_DecryptFinal(AES_SIV_CTX *ctx, unsigned char *out,
                         unsigned char const *v, unsigned char const *c,
                         size_t len) {
        block t, q;
        size_t i;
        uint64_t result;
        int ret = 0;

        ct_poison(c, len);

        memcpy(&q, v, 16);
        q.byte[8] &= 0x7f;
        q.byte[12] &= 0x7f;

        if(UNLIKELY(do_encrypt(ctx->cipher_ctx, out, c, len, &q) != 1)) {
                goto done;
        }
        debug("plaintext", out, len);

        if(UNLIKELY(do_s2v_p(ctx, &t, out, len) != 1)) {
                goto done;
        }

        for (i = 0; i < 16; i++) {
                t.byte[i] ^= v[i];
        }

        result = t.word[0] | t.word[1];
        ct_unpoison(&result, sizeof result);
        ret = !result;

        if(ret) {
                ct_unpoison(out, len);
        } else {
                OPENSSL_cleanse(out, len);
        }

done:
        ct_unpoison(c, len);
        return ret;
}

int AES_SIV_Encrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
                    unsigned char const *key, size_t key_len,
                    unsigned char const *nonce, size_t nonce_len,
                    unsigned char const *plaintext, size_t plaintext_len,
                    unsigned char const *ad, size_t ad_len) {
        if (UNLIKELY(*out_len < plaintext_len + 16)) {
                return 0;
        }
        *out_len = plaintext_len + 16;

        if (UNLIKELY(AES_SIV_Init(ctx, key, key_len) != 1)) {
                return 0;
        }
        if (UNLIKELY(AES_SIV_AssociateData(ctx, ad, ad_len) != 1)) {
                return 0;
        }
        if (nonce != NULL &&
            UNLIKELY(AES_SIV_AssociateData(ctx, nonce, nonce_len) != 1)) {
                return 0;
        }
        if (UNLIKELY(AES_SIV_EncryptFinal(ctx, out, out + 16, plaintext,
                                          plaintext_len) != 1)) {
                return 0;
        }

        debug("IV || C", out, *out_len);
        return 1;
}

int AES_SIV_Decrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
                    unsigned char const *key, size_t key_len,
                    unsigned char const *nonce, size_t nonce_len,
                    unsigned char const *ciphertext, size_t ciphertext_len,
                    unsigned char const *ad, size_t ad_len) {
        if (UNLIKELY(ciphertext_len < 16)) {
                return 0;
        }
        if (UNLIKELY(*out_len < ciphertext_len - 16)) {
                return 0;
        }
        *out_len = ciphertext_len - 16;

        if (UNLIKELY(AES_SIV_Init(ctx, key, key_len) != 1)) {
                return 0;
        }
        if (UNLIKELY(AES_SIV_AssociateData(ctx, ad, ad_len) != 1)) {
                return 0;
        }
        if (nonce != NULL &&
            UNLIKELY(AES_SIV_AssociateData(ctx, nonce, nonce_len) != 1)) {
                return 0;
        }
        if (UNLIKELY(AES_SIV_DecryptFinal(ctx, out, ciphertext, ciphertext + 16,
                                          ciphertext_len - 16) != 1)) {
                return 0;
        }
        debug("plaintext", out, *out_len);
        return 1;
}
