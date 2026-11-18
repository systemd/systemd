/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptenroll.h"
#include "forward.h"
#include "tpm2-util.h"

int load_volume_key_tpm2(const EnrollContext *c, struct crypt_device *cd, struct iovec *ret_vk);
int enroll_tpm2(const EnrollContext *c, struct crypt_device *cd, const struct iovec *volume_key, int *ret_slot_to_wipe);

typedef enum Tpm2TokenState {
        TPM2_TOKEN_CURRENT,           /* The policy can be satisfied in the current system state */
        TPM2_TOKEN_STALE,             /* PCR values the token is bound to changed, re-enrolling fixes that */
        TPM2_TOKEN_STALE_SIGNATURE,   /* No PCR signature covers the current system state */
        TPM2_TOKEN_STALE_PCRLOCK,     /* The pcrlock policy doesn't cover the current system state */
        TPM2_TOKEN_OTHER_TPM,         /* Sealed by a different TPM */
        TPM2_TOKEN_UNKNOWN,           /* Couldn't tell */
        _TPM2_TOKEN_STATE_MAX,
        _TPM2_TOKEN_STATE_INVALID = -EINVAL,
} Tpm2TokenState;

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(tpm2_token_state, Tpm2TokenState);

/* A TPM2 token from the LUKS2 header, with the parameters it was enrolled with. */
typedef struct Tpm2Token {
        int token;
        int keyslot;
        uint32_t hash_pcr_mask;
        uint16_t pcr_bank;
        struct iovec pubkey;
        char *pubkey_policy_ref;
        uint32_t pubkey_pcr_mask;
        uint16_t primary_alg;
        struct iovec *blobs;
        size_t n_blobs;
        struct iovec *policy_hash;
        size_t n_policy_hash;
        struct iovec salt;
        struct iovec srk;
        struct iovec pcrlock_nv;
        TPM2Flags flags;
        Argon2IdParameters argon2id_params;
        Tpm2TokenState state;
} Tpm2Token;

void tpm2_token_array_free(Tpm2Token *tokens, size_t n);

/* Loads all TPM2 tokens of the volume and determines for each whether it can unlock it in the current
 * system state, without needing a PIN. */
int tpm2_tokens_load(const EnrollContext *c, struct crypt_device *cd, Tpm2Token **ret, size_t *ret_n);
