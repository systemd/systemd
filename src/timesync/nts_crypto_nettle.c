#include <assert.h>
#include <nettle/version.h>
#include <nettle/siv-cmac.h>
#if NETTLE_VERSION_MAJOR > 3 || NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR >= 9
#  include <nettle/siv-gcm.h>
#elif NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR < 8
#  error Your Nettle version is too old, need at least version 3.8
#endif
#include <string.h>

#include "nts_crypto.h"

static const struct NTS_AEADParam supported_algos[] = {
        { NTS_AEAD_AES_SIV_CMAC_256, 256/8, 16, 16, true, false, "AES-128-SIV" },
        { NTS_AEAD_AES_SIV_CMAC_512, 512/8, 16, 16, true, false, "AES-256-SIV" },
#ifdef SIV_GCM_BLOCK_SIZE
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

#define CHECK(expr) if (expr == 1); else goto exit;

union ctx {
        struct siv_cmac_aes128_ctx siv_cmac128;
        struct siv_cmac_aes256_ctx siv_cmac256;
        struct aes128_ctx aes128;
        struct aes256_ctx aes256;
};

int NTS_encrypt(uint8_t *ctxt,
                const uint8_t *ptxt,
                int ptxt_len,
                const AssociatedData *info,
                const struct NTS_AEADParam *aead,
                const uint8_t *key) {

        assert(info[0].data);
        assert(info[1].data && info[1].length >= SIV_MIN_NONCE_SIZE);
        assert(!info[2].data);

        const int ctxt_len = ptxt_len + aead->block_size;
        if (ctxt == ptxt && aead->tag_first) {
                /* nettle can't handle in-place encryption well in SIV-CMAC mode */
                memmove(ctxt + aead->block_size, ptxt, ptxt_len);
                ptxt = ctxt + aead->block_size;
        }

        switch (aead->aead_id) {
                union ctx ctx_obj;
        case NTS_AEAD_AES_SIV_CMAC_256: {
                struct siv_cmac_aes128_ctx *state = &ctx_obj.siv_cmac128;
                siv_cmac_aes128_set_key(state, key);
                siv_cmac_aes128_encrypt_message(
                        state,
                        info[1].length, info[1].data,
                        info[0].length, info[0].data,
                        ctxt_len, ctxt,
                        ptxt
                );
                break;
        }
        case NTS_AEAD_AES_SIV_CMAC_512: {
                struct siv_cmac_aes256_ctx *state = &ctx_obj.siv_cmac256;
                siv_cmac_aes256_set_key(state, key);
                siv_cmac_aes256_encrypt_message(
                        state,
                        info[1].length, info[1].data,
                        info[0].length, info[0].data,
                        ctxt_len, ctxt,
                        ptxt
                );
                break;
        }
#ifdef SIV_GCM_BLOCK_SIZE
        case NTS_AEAD_AES_128_GCM_SIV: {
                struct aes128_ctx *state = &ctx_obj.aes128;
                aes128_set_encrypt_key(state, key);
                siv_gcm_aes128_encrypt_message(
                        state,
                        info[1].length, info[1].data,
                        info[0].length, info[0].data,
                        ctxt_len, ctxt,
                        ptxt
                );
                break;
        }
        case NTS_AEAD_AES_256_GCM_SIV: {
                struct aes256_ctx *state = &ctx_obj.aes256;
                aes256_set_encrypt_key(state, key);
                siv_gcm_aes256_encrypt_message(
                        state,
                        info[1].length, info[1].data,
                        info[0].length, info[0].data,
                        ctxt_len, ctxt,
                        ptxt
                );
                break;
        }
#endif
        default:
                assert(!"unreachable");
        }

        /* apparently encryption can't fail with nettle */
        return ctxt_len;
}

int NTS_decrypt(uint8_t *ptxt,
                const uint8_t *ctxt,
                int ctxt_len,
                const AssociatedData *info,
                const struct NTS_AEADParam *aead,
                const uint8_t *key) {

        int result = -1;

        assert(info[0].data);
        assert(info[1].data && info[1].length >= SIV_MIN_NONCE_SIZE);
        assert(!info[2].data);

        assert(ctxt_len >= aead->block_size);

        const int ptxt_len = ctxt_len - aead->block_size;
        uint8_t *real_ptxt = ptxt;
        if (ctxt == ptxt && aead->tag_first)
                /* nettle can't handle in-place decryption well in SIV-CMAC mode */
                ptxt += aead->block_size;

        switch (aead->aead_id) {
                union ctx ctx_obj;
        case NTS_AEAD_AES_SIV_CMAC_256: {
                struct siv_cmac_aes128_ctx *state = &ctx_obj.siv_cmac128;
                siv_cmac_aes128_set_key(state, key);
                CHECK(siv_cmac_aes128_decrypt_message(
                        state,
                        info[1].length, info[1].data,
                        info[0].length, info[0].data,
                        ptxt_len, ptxt,
                        ctxt
                ));
                break;
        }
        case NTS_AEAD_AES_SIV_CMAC_512: {
                struct siv_cmac_aes256_ctx *state = &ctx_obj.siv_cmac256;
                siv_cmac_aes256_set_key(state, key);
                CHECK(siv_cmac_aes256_decrypt_message(
                        state,
                        info[1].length, info[1].data,
                        info[0].length, info[0].data,
                        ptxt_len, ptxt,
                        ctxt
                ));
                break;
        }
#ifdef SIV_GCM_BLOCK_SIZE
        case NTS_AEAD_AES_128_GCM_SIV: {
                struct aes128_ctx *state = &ctx_obj.aes128;
                aes128_set_encrypt_key(state, key);
                CHECK(siv_gcm_aes128_decrypt_message(
                        state,
                        info[1].length, info[1].data,
                        info[0].length, info[0].data,
                        ptxt_len, ptxt,
                        ctxt
                ));
                break;
        }
        case NTS_AEAD_AES_256_GCM_SIV: {
                struct aes256_ctx *state = &ctx_obj.aes256;
                aes256_set_encrypt_key(state, key);
                CHECK(siv_gcm_aes256_decrypt_message(
                        state,
                        info[1].length, info[1].data,
                        info[0].length, info[0].data,
                        ptxt_len, ptxt,
                        ctxt
                ));
                break;
        }
#endif
        default:
                assert(!"unreachable");
        }

        if (real_ptxt != ptxt)
                memmove(real_ptxt, ptxt, ptxt_len);

        result = ptxt_len;
exit:
        return result;
}
