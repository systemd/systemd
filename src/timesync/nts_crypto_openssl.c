/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <syslog.h>

#include "crypto-util.h"
#include "nts_crypto.h"
#include "timesyncd-forward.h"

#if !OPENSSL_VERSION_PREREQ(3,0)
#    error Your OpenSSL version does not support SIV modes, need at least version 3.0.
#endif

#if defined(OPENSSL_WORKAROUND) && OPENSSL_VERSION_PREREQ(3,5)
#    warning The OpenSSL workaround is not necessary.
#endif

static const NTS_AEADParam supported_algos[] = {
        { NTS_AEAD_AES_SIV_CMAC_256, 256/8, 16, 16, true, false, "AES-128-SIV" },
        { NTS_AEAD_AES_SIV_CMAC_512, 512/8, 16, 16, true, false, "AES-256-SIV" },
        { NTS_AEAD_AES_SIV_CMAC_384, 384/8, 16, 16, true, false, "AES-192-SIV" },
#if OPENSSL_VERSION_PREREQ(3,2)
        { NTS_AEAD_AES_128_GCM_SIV,  128/8, 16, 12, false, true, "AES-128-GCM-SIV" },
        { NTS_AEAD_AES_256_GCM_SIV,  256/8, 16, 12, false, true, "AES-256-GCM-SIV" },
#endif
};

const NTS_AEADParam* NTS_get_param(NTS_AEADAlgorithmType id) {
        FOREACH_ELEMENT(algo, supported_algos)
                if (algo->aead_id == id)
                        return algo;

        return NULL;
}

/* two function types to aid readability down below and avoid code duplication
 * NOTE: these two signatures are straight from the OpenSSL docs since they are intended
 * to match the EVP_En/DecryptInit_ex and EVP_En/DecryptUpdate functions.
 */

typedef int EVP_CryptInit_func(
                EVP_CIPHER_CTX *ctx,
                const EVP_CIPHER *type,
                ENGINE *impl,
                const uint8_t *key,
                const uint8_t *iv);

typedef int EVP_CryptUpdate_func(
                EVP_CIPHER_CTX* ctx,
                uint8_t *out,
                int *outl,
                const uint8_t *in,
                int inl);

static int process_assoc_data(
                EVP_CIPHER_CTX *state,
                const AssociatedData *info,
                const NTS_AEADParam *aead,
                EVP_CryptInit_func CryptInit_ex,
                EVP_CryptUpdate_func CryptUpdate) {

        int r;

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
                assert(info->iov_base);
                for (last = info; (last+1)->iov_base != NULL; )
                        last++;

                if (last->iov_len != aead->nonce_size)
                        return -EINVAL;

                r = CryptInit_ex(state, /* type= */ NULL, /* impl= */ NULL, /* key= */ NULL, last->iov_base);
                if (r == 0)
                        return -EINVAL;
        }

        for ( ; info->iov_base && info != last; info++) {
                int len = 0;
                r = CryptUpdate(state, /* out= */ NULL, &len, info->iov_base, info->iov_len);
                if (r == 0)
                        return -EINVAL;

                assert((size_t)len == info->iov_len);
        }

        return 0;
}

ssize_t NTS_encrypt(const struct iovec *ctxt,
                const struct iovec *ptxt,
                const AssociatedData *info,
                const NTS_AEADParam *aead,
                const uint8_t *key) {

        int r;

        assert(ctxt);
        assert(ptxt);
        assert(info);
        assert(aead);
        assert(key);

        uint8_t *ctxt_buf = ctxt->iov_base;
        size_t ctxt_len = ctxt->iov_len;
        const uint8_t *ptxt_buf = ptxt->iov_base;
        size_t ptxt_len = ptxt->iov_len;

        assert(ctxt_buf);
        assert(ctxt_len <= (size_t)INT_MAX); /* OpenSSL expects an int */
        assert(ptxt_buf);
        assert(ptxt_len <= (size_t)INT_MAX); /* same */

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        _cleanup_(EVP_CIPHER_freep) EVP_CIPHER *cipher = NULL;
        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *state = sym_EVP_CIPHER_CTX_new();
        if (!state)
                return -ENOMEM;

        cipher = sym_EVP_CIPHER_fetch(/* ctx= */ NULL, aead->cipher_name, /* properties= */ NULL);
        if (!cipher)
                return -EINVAL;

        /* check that the ciphertext length is large enough */
        assert(ptxt_len <= SIZE_MAX - aead->block_size);
        if (ctxt_len < ptxt_len + aead->block_size)
                return -EINVAL;

        uint8_t *tag, *ctxt_start = ctxt_buf;
        if (aead->tag_first) {
                tag = ctxt_buf;
                ctxt_buf += aead->block_size;
        } else
                tag = ctxt_buf + ptxt_len;

        r = sym_EVP_EncryptInit_ex(state, cipher, /* impl= */ NULL, key, /* iv= */ NULL);
        if (r == 0)
                return -EINVAL;

        r = process_assoc_data(state, info, aead, sym_EVP_EncryptInit_ex, sym_EVP_EncryptUpdate);
        if (r < 0)
                return r;

        /* encrypt data */
        int len;
        r = sym_EVP_EncryptUpdate(state, ctxt_buf, &len, ptxt_buf, ptxt_len);
        if (r == 0)
                return -EINVAL;

        assert((size_t) len <= ptxt_len);
        ctxt_buf += len;

        r = sym_EVP_EncryptFinal_ex(state, ctxt_buf, &len);
        if (r == 0)
                return -EINVAL;

        assert(len <= aead->block_size);
        ctxt_buf += len;
        assert(ctxt_buf - ctxt_start == (ptrdiff_t) ptxt_len + aead->tag_first * aead->block_size);

        /* append/prepend the AEAD tag */
        r = sym_EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_GET_TAG, aead->block_size, tag);
        if (r == 0)
                return -EINVAL;

        return ptxt_len + aead->block_size;
}

ssize_t NTS_decrypt(const struct iovec *ptxt,
                const struct iovec *ctxt,
                const AssociatedData *info,
                const NTS_AEADParam *aead,
                const uint8_t *key) {

        int r;

        assert(ptxt);
        assert(ctxt);
        assert(info);
        assert(aead);
        assert(key);

        uint8_t *ptxt_buf = ptxt->iov_base;
        size_t ptxt_len = ptxt->iov_len;
        const uint8_t *ctxt_buf = ctxt->iov_base;
        size_t ctxt_len = ctxt->iov_len;

        assert(ptxt_buf);
        assert(ptxt_len <= (size_t)INT_MAX); /* OpenSSL expects an int */
        assert(ctxt_buf);
        assert(ctxt_len <= (size_t)INT_MAX); /* same */

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        _cleanup_(EVP_CIPHER_freep) EVP_CIPHER *cipher = NULL;
        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *state = sym_EVP_CIPHER_CTX_new();
        if (!state)
                return -ENOMEM;

        /* check that the ciphertext size is valid */
        if (ctxt_len < aead->block_size || ptxt_len < ctxt_len - aead->block_size)
                return -EINVAL;

        cipher = sym_EVP_CIPHER_fetch(/* ctx= */ NULL, aead->cipher_name, /* properties= */ NULL);
        if (!cipher)
                return -EINVAL;

        /* set the AEAD tag */
        const uint8_t *tag;
        if (aead->tag_first) {
                tag = ctxt_buf;
                ctxt_buf += aead->block_size;
        } else
                tag = ctxt_buf + ctxt_len - aead->block_size;

        ctxt_len -= aead->block_size;

        r = sym_EVP_DecryptInit_ex(state, cipher, /* impl= */ NULL, key, /* iv= */ NULL);
        if (r == 0)
                return -EINVAL;

        r = sym_EVP_CIPHER_CTX_ctrl(state, EVP_CTRL_AEAD_SET_TAG, aead->block_size, (uint8_t*)tag);
        if (r == 0)
                return -EINVAL;

        r = process_assoc_data(state, info, aead, sym_EVP_DecryptInit_ex, sym_EVP_DecryptUpdate);
        if (r < 0)
                return r;

        uint8_t *ptxt_start = ptxt_buf;

        /* decrypt data */
        int len;
        r = sym_EVP_DecryptUpdate(state, ptxt_buf, &len, ctxt_buf, ctxt_len);
        if (r == 0)
                return -EINVAL;

        assert((size_t) len <= ctxt_len);
        ptxt_buf += len;

        r = sym_EVP_DecryptFinal_ex(state, ptxt_buf, &len);
        if (r == 0)
                return -EINVAL;

        assert(len <= aead->block_size);
        ptxt_buf += len;

        assert(ptxt_buf - ptxt_start == (ptrdiff_t) ctxt_len);

        return ctxt_len;
}
