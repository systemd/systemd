/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "libfido2-util.h"

typedef enum EnrollType {
        ENROLL_PASSWORD,
        ENROLL_RECOVERY,
        ENROLL_PKCS11,
        ENROLL_FIDO2,
        ENROLL_TPM2,
        _ENROLL_TYPE_MAX,
        _ENROLL_TYPE_INVALID = -EINVAL,
} EnrollType;

typedef enum UnlockType {
        UNLOCK_PASSWORD,
        UNLOCK_KEYFILE,
        UNLOCK_FIDO2,
        UNLOCK_TPM2,
        UNLOCK_EMPTY,
        UNLOCK_HEADLESS,
        _UNLOCK_TYPE_MAX,
        _UNLOCK_TYPE_INVALID = -EINVAL,
} UnlockType;

typedef enum WipeScope {
        WIPE_EXPLICIT,          /* only wipe the listed slots */
        WIPE_ALL,               /* wipe all slots */
        WIPE_EMPTY_PASSPHRASE,  /* wipe slots with empty passphrases plus listed slots */
        _WIPE_SCOPE_MAX,
        _WIPE_SCOPE_INVALID = -EINVAL,
} WipeScope;

DECLARE_STRING_TABLE_LOOKUP(enroll_type, EnrollType);
DECLARE_STRING_TABLE_LOOKUP(luks2_token_type, EnrollType);

/* A single bag of parameters consumed by the enrollment helpers. Populated either from the command line
 * (see enroll_context_from_args() in cryptenroll.c), from a Varlink request (see cryptenroll-varlink.c),
 * or by the interactive wizard (see cryptenroll-interactive.c). Owns all strings/arrays it points to. */
typedef struct EnrollContext {
        EnrollType enroll_type;
        UnlockType unlock_type;

        /* Target device */
        char *node;

        /* Unlock side */
        char *unlock_keyfile;
        char *unlock_fido2_device;
        char *unlock_tpm2_device;
        char *unlock_password;          /* used by Varlink; NULL on CLI path */

        /* New password to enroll (mechanism == password). When NULL the helpers fall back to
         * $NEWPASSWORD / askpw. */
        char *passphrase;
        size_t passphrase_size;

        /* FIDO2 */
        char *fido2_device;
        char *fido2_salt_file;
        bool fido2_parameters_in_header;
        Fido2EnrollFlags fido2_lock_with;
        int fido2_cred_alg;
        char *fido2_pin;                /* optional pre-supplied token PIN; NULL means prompt (if interactive) */

        /* PKCS#11 */
        char *pkcs11_token_uri;

        /* TPM2 */
        char *tpm2_device;
        uint32_t tpm2_seal_key_handle;
        char *tpm2_device_key;
        Tpm2PCRValue *tpm2_hash_pcr_values;
        size_t tpm2_n_hash_pcr_values;
        bool tpm2_pin;
        char *tpm2_public_key;
        bool tpm2_load_public_key;
        char *tpm2_public_key_policyref;
        uint32_t tpm2_public_key_pcr_mask;
        char *tpm2_signature;
        char *tpm2_pcrlock;

        /* Wipe selection */
        int *wipe_slots;
        size_t n_wipe_slots;
        WipeScope wipe_slots_scope;
        unsigned wipe_slots_mask;
        int wipe_except_slot;           /* slot to never wipe (e.g. the one we just enrolled); -1 for none */

        /* If false, the enrollment helpers must never prompt the user (no askpw, no terminal I/O,
         * no log printing of credential material). They use the fields in this context as the
         * sole input, and fail with ENOPKG if a required piece of input is missing. CLI and
         * interactive callers set this to true; the Varlink dispatcher sets it to false. */
        bool interactive;

        /* Varlink link the request came in on, if the caller asked for 'more'. NULL otherwise.
         * Owned (sd_varlink_ref'd) by the context. */
        sd_varlink *link;
} EnrollContext;

#define ENROLL_CONTEXT_NULL                                             \
        (EnrollContext) {                                               \
                .enroll_type = _ENROLL_TYPE_INVALID,                    \
                .unlock_type = UNLOCK_PASSWORD,                         \
                .fido2_parameters_in_header = true,                     \
                .fido2_lock_with = FIDO2ENROLL_PIN | FIDO2ENROLL_UP,    \
                .tpm2_load_public_key = true,                           \
                .wipe_slots_scope = WIPE_EXPLICIT,                      \
                .wipe_except_slot = -1,                                 \
                .interactive = true,                                    \
        }

void enroll_context_done(EnrollContext *c);

/* Opens & loads the LUKS2 superblock of c->node, refuses homed-managed volumes, and (if ret_volume_key is
 * non-NULL) unlocks it according to c->unlock_type, returning the volume key. */
int prepare_luks(const EnrollContext *c, struct crypt_device **ret_cd, struct iovec *ret_volume_key);

/* Dispatches to the enroll_*() helper matching c->enroll_type and returns the keyslot the new credential
 * was added to. For ENROLL_RECOVERY the generated key is returned via ret_recovery_key (if non-NULL).
 * Defined in cryptenroll.c, shared by the command line and Varlink code paths. */
int enroll_now(const EnrollContext *c, struct crypt_device *cd, const struct iovec *volume_key, char **ret_recovery_key);
