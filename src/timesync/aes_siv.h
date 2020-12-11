/* Copyright (c) 2017-2019 Akamai Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AES_SIV_H_
#define AES_SIV_H_

#include <stddef.h>

#define LIBAES_SIV_VERSION_MAJOR 1
#define LIBAES_SIV_VERSION_MINOR 0
#define LIBAES_SIV_VERSION_PATCH 1

#define LIBAES_SIV_VERSION ((LIBAES_SIV_VERSION_MAJOR << 16) + \
                            (LIBAES_SIV_VERSION_MINOR << 8) +  \
                            LIBAES_SIV_VERSION_PATCH)


#ifdef __cplusplus
extern "C" {
#endif

typedef struct AES_SIV_CTX_st AES_SIV_CTX;

AES_SIV_CTX *AES_SIV_CTX_new(void);
int AES_SIV_CTX_copy(AES_SIV_CTX *dst, AES_SIV_CTX const *src);
void AES_SIV_CTX_cleanup(AES_SIV_CTX *ctx);
void AES_SIV_CTX_free(AES_SIV_CTX *ctx);

int AES_SIV_Init(AES_SIV_CTX *ctx, unsigned char const *key, size_t key_len);
int AES_SIV_AssociateData(AES_SIV_CTX *ctx, unsigned char const *data,
                          size_t len);
int AES_SIV_EncryptFinal(AES_SIV_CTX *ctx, unsigned char *v_out,
                         unsigned char *c_out, unsigned char const *plaintext,
                         size_t len);
int AES_SIV_DecryptFinal(AES_SIV_CTX *ctx, unsigned char *out,
                         unsigned char const *v, unsigned char const *c,
                         size_t len);

int AES_SIV_Encrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
                    unsigned char const *key, size_t key_len,
                    unsigned char const *nonce, size_t nonce_len,
                    unsigned char const *plaintext, size_t plaintext_len,
                    unsigned char const *ad, size_t ad_len);

int AES_SIV_Decrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
                    unsigned char const *key, size_t key_len,
                    unsigned char const *nonce, size_t nonce_len,
                    unsigned char const *ciphertext, size_t ciphertext_len,
                    unsigned char const *ad, size_t ad_len);


#ifdef __cplusplus
}
#endif

#endif
