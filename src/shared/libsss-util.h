/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "gcrypt-util.h"
#include "hexdecoct.h"
#include "json.h"
#include "libfido2-util.h"
#include "cryptsetup-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "random-util.h"
#include "string-table.h"

#include <errno.h>
#include <sys/types.h>
#include <libecc/sss.h>

extern int (*sym_sss_generate)(sss_share *shares, unsigned short k, unsigned short n, sss_secret *secret, boolean input_secret);
extern int (*sym_sss_regenerate)(sss_share *shares, unsigned short k, unsigned short n, sss_secret *secret);
extern int (*sym_sss_combine)(const sss_share *shares, unsigned short k, sss_secret *secret);
int dlopen_libsss(void);

#define DERIVATION_KEY_SIZE 32
#define MAX_FACTOR 32
#define NONCE_LEN 16
#define TAG_LEN 16
#define SALT_LEN 16

typedef enum CombinationType {
    MANDATORY = 0x0,
    SHARED,
} CombinationType;

typedef enum TPM2Flags {
        TPM2_FLAGS_USE_PIN = 1 << 0,
} TPM2Flags;

typedef enum EnrollType {
        ENROLL_PASSWORD,
        ENROLL_RECOVERY,
        ENROLL_PKCS11,
        ENROLL_FIDO2,
        ENROLL_TPM2,
        ENROLL_MANDATORY,// Change name
        _ENROLL_TYPE_MAX,
        _ENROLL_TYPE_INVALID = -EINVAL,
} EnrollType;

static const char *const sss_enroll_types[_ENROLL_TYPE_MAX] = {
        [ENROLL_PASSWORD] = "systemd-password",
        [ENROLL_RECOVERY] = "systemd-recovery",
        [ENROLL_PKCS11] = "systemd-pkcs11",
        [ENROLL_FIDO2] = "systemd-fido2",
        [ENROLL_TPM2] = "systemd-tpm2",
        [ENROLL_MANDATORY] = "systemd-sss",
};

typedef struct FactorFido2 {
    char *device;
    bool device_auto;
    void *cid;
    size_t cid_size;
    char *rp_id;
    Fido2EnrollFlags lock_with;
    int cred_alg;
} FactorFido2;

typedef struct FactorTpm2 {
    char *device;
    bool device_auto;
    uint32_t pcr_mask;
    uint16_t pcr_bank;
    uint16_t primary_alg;
    TPM2Flags flags;
    bool use_pin;
} FactorTpm2;

typedef struct FactorPkcs11 {
    char *token_uri;
    bool token_uri_auto;
} FactorPkcs11;

typedef struct Factor {
        int token;
        EnrollType enroll_type;
        sss_share *share;
        CombinationType combination_type;
        unsigned char *tag;//[TAG_LEN];         // stack variable ?
        unsigned char *nonce;//[NONCE_LEN];     // stack variable ?
        unsigned char *salt;//[TAG_LEN]         // stack variable ?
        union {
                FactorFido2 fido2;
                FactorTpm2 tpm2;
                FactorPkcs11 pkcs11;
        };
} Factor;


int decrypt_share(const void *const key, const size_t key_size, const unsigned char *const encrypted_share, Factor *factor);
int encrypt_share(const void *const key, const size_t key_size, Factor *const factor, unsigned char *ret_encrypted_share);
int enroll_mandatory(struct crypt_device *cd, const void *volume_key, size_t volume_key_size, Factor *factor, int keyslot);
int factor_compare(const void *a, const void *b);
int factor_init(Factor *factor, EnrollType type);
int fetch_sss_json_data(Factor *factor, JsonVariant *v, unsigned char **ret_encrypted_share);
int find_sss_auto_data(Factor *factor, struct crypt_device *cd, unsigned char **ret_encrypted_share, int *ret_keyslot);
int is_factor_already_assigned(const Factor *const factor_list, uint16_t factor_number, int token);
int sss_valid_combination_check(const int n_shared, const int quorum);
sss_share *factors_to_shares(const Factor *const factors, size_t n_factors, CombinationType combination_type, size_t n_shares);
void try_validate_factor(bool *is_factor, uint16_t *n_factor);
int get_random(unsigned char *buf, uint16_t len);
