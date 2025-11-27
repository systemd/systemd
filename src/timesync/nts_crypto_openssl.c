/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <openssl/ssl.h>

#include "nts_crypto.h"
#include "timesyncd-forward.h"

#if !OPENSSL_VERSION_PREREQ(3,0)
#    error Your OpenSSL version does not support SIV modes, need at least version 3.0.
#endif

#if defined(OPENSSL_WORKAROUND) && OPENSSL_VERSION_PREREQ(3,5)
#    warning The OpenSSL workaround is not necessary.
#endif

static const struct NTS_AEADParam supported_algos[] = {
        { NTS_AEAD_AES_SIV_CMAC_256, 256/8, 16, 16, true, false, "AES-128-SIV" },
        { NTS_AEAD_AES_SIV_CMAC_512, 512/8, 16, 16, true, false, "AES-256-SIV" },
        { NTS_AEAD_AES_SIV_CMAC_384, 384/8, 16, 16, true, false, "AES-192-SIV" },
#if OPENSSL_VERSION_PREREQ(3,2)
        { NTS_AEAD_AES_128_GCM_SIV,  128/8, 16, 12, false, true, "AES-128-GCM-SIV" },
        { NTS_AEAD_AES_256_GCM_SIV,  256/8, 16, 12, false, true, "AES-256-GCM-SIV" },
#endif
};

const struct NTS_AEADParam* NTS_get_param(NTS_AEADAlgorithmType id) {
        FOREACH_ELEMENT(algo, supported_algos)
                if (algo->aead_id == id)
                        return algo;

        return NULL;
}

#define CHECK(expr) if (expr); else goto exit;

typedef int init_f(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const uint8_t*, const uint8_t*);
typedef int upd_f(EVP_CIPHER_CTX*, uint8_t*, int*, const uint8_t*, int);

static int process_assoc_data(
                EVP_CIPHER_CTX *state,
                const AssociatedData *info,
                const struct NTS_AEADParam *aead,
                init_f EVP_CryptInit_ex,
                upd_f EVP_CryptUpdate) {

        assert(state);
        assert(info);
        assert(aead);

        /* process the associated data and nonce first */
        const AssociatedData *last = NULL;
        if (aead->nonce_is_iv) {
                /* workaround for the OpenSSL GCM-SIV interface, where the IV is set directly in
                 * contradiction to the documentation;
                 * our interface *does* interpret the last AAD item as the siv/nonce
                 */
                assert(info->data);
                for (last = info; (last+1)->data != NULL; )
                        last++;

                CHECK(last->length == aead->nonce_size);
                CHECK(EVP_CryptInit_ex(state, NULL, NULL, NULL, last->data));
        }

        for ( ; info->data && info != last; info++) {
                int len = 0;
                CHECK(EVP_CryptUpdate(state, NULL, &len, info->data, info->length));
                assert((size_t)len == info->length);
        }

        return 1;
exit:
        return 0;
}

int NTS_encrypt(uint8_t *ctxt,
                int ctxt_len,
                const uint8_t *ptxt,
                int ptxt_len,
                const AssociatedData *info,
                const struct NTS_AEADParam *aead,
                const uint8_t *key) {

        assert(ctxt);
        assert(ctxt_len >= 0); /* see below */
        assert(ptxt);
        assert(ptxt_len >= 0); /* passed as an int since OpenSSL expects an int */
        assert(info);
        assert(aead);
        assert(key);

        int result = -1;
        int len;

        EVP_CIPHER *cipher = NULL;
        EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
        CHECK(state);

        CHECK((cipher = EVP_CIPHER_fetch(NULL, aead->cipher_name, NULL)));
        CHECK(ctxt_len >= ptxt_len + aead->block_size);

        uint8_t *ctxt_start = ctxt;
        uint8_t *tag;
        if (aead->tag_first) {
                tag = ctxt;
                ctxt += aead->block_size;
        } else
                tag = ctxt + ptxt_len;

        CHECK(EVP_EncryptInit_ex(state, cipher, NULL, key, NULL));
        CHECK(process_assoc_data(state, info, aead, EVP_EncryptInit_ex, EVP_EncryptUpdate));

        /* encrypt data */
        CHECK(EVP_EncryptUpdate(state, ctxt, &len, ptxt, ptxt_len));
        assert(len <= ptxt_len);
        ctxt += len;

        CHECK(EVP_EncryptFinal_ex(state, ctxt, &len));
        assert(len <= aead->block_size);
        ctxt += len;
        assert(ctxt - ctxt_start == ptxt_len + aead->tag_first * aead->block_size);

        /* append/prepend the AEAD tag */
        CHECK(EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_GET_TAG, aead->block_size, tag));

        result = ptxt_len + aead->block_size;
exit:
        EVP_CIPHER_CTX_free(state);
        EVP_CIPHER_free(cipher);
        return result;
}

int NTS_decrypt(uint8_t *ptxt,
                int ptxt_len,
                const uint8_t *ctxt,
                int ctxt_len,
                const AssociatedData *info,
                const struct NTS_AEADParam *aead,
                const uint8_t *key) {

        assert(ptxt);
        assert(ptxt_len >= 0); /* see below */
        assert(ctxt);
        assert(ctxt_len >= 0); /* passed as an int since OpenSSL expects an int */
        assert(info);
        assert(aead);
        assert(key);

        int result = -1;
        int len;

        EVP_CIPHER *cipher = NULL;
        EVP_CIPHER_CTX *state = EVP_CIPHER_CTX_new();
        CHECK(state);
        CHECK(ctxt_len >= aead->block_size);
        CHECK(ptxt_len >= ctxt_len - aead->block_size);

        CHECK((cipher = EVP_CIPHER_fetch(NULL, aead->cipher_name, NULL)));

        /* set the AEAD tag */
        const uint8_t *tag;
        if (aead->tag_first) {
                tag = ctxt;
                ctxt += aead->block_size;
        } else
                tag = ctxt + ctxt_len - aead->block_size;

        ctxt_len -= aead->block_size;

        CHECK(EVP_DecryptInit_ex(state, cipher, NULL, key, NULL));
        CHECK(EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_SET_TAG, aead->block_size, (uint8_t*)tag));

        CHECK(process_assoc_data(state, info, aead, EVP_DecryptInit_ex, EVP_DecryptUpdate));

        uint8_t *ptxt_start = ptxt;

        /* decrypt data */
        CHECK(EVP_DecryptUpdate(state, ptxt, &len, ctxt, ctxt_len));
        assert(len <= ctxt_len);
        ptxt += len;

        CHECK(EVP_DecryptFinal_ex(state, ptxt, &len));
        assert(len <= aead->block_size);
        ptxt += len;

        assert(ptxt - ptxt_start == ctxt_len);

        result = ctxt_len;
exit:
        EVP_CIPHER_CTX_free(state);
        EVP_CIPHER_free(cipher);
        return result;
}
