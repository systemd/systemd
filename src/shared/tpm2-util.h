/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bitfield.h"
#include "openssl-util.h"
#include "shared-forward.h"

typedef enum TPM2Flags {
        TPM2_FLAGS_USE_PIN     = 1 << 0,
        TPM2_FLAGS_USE_PCRLOCK = 1 << 1,
} TPM2Flags;

/* As per https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf a
 * TPM2 on a Client PC must have at least 24 PCRs. This hardcodes our expectation of 24. */
#define TPM2_PCRS_MAX 24U
#define TPM2_PCRS_MASK ((UINT32_C(1) << TPM2_PCRS_MAX) - 1)

/* The SRK handle is defined in the Provisioning Guidance document (see above) in the table "Reserved Handles
 * for TPM Provisioning Fundamental Elements". The SRK is useful because it is "shared", meaning it has no
 * authValue nor authPolicy set, and thus may be used by anyone on the system to generate derived keys or
 * seal secrets. This is useful if the TPM has an auth (password) set for the 'owner hierarchy', which would
 * prevent users from generating primary transient keys, unless they knew the owner hierarchy auth. See
 * the Provisioning Guidance document for more details. */
#define TPM2_SRK_HANDLE UINT32_C(0x81000001)

/* The TPM specification limits sealed data to MAX_SYM_DATA. Unfortunately, tpm2-tss incorrectly
 * defines this value as 256; the TPM specification Part 2 ("Structures") section
 * "TPMU_SENSITIVE_CREATE" states "For interoperability, MAX_SYM_DATA should be 128." */
#define TPM2_MAX_SEALED_DATA UINT16_C(128)

static inline bool TPM2_PCR_INDEX_VALID(unsigned pcr) {
        return pcr < TPM2_PCRS_MAX;
}
static inline bool TPM2_PCR_MASK_VALID(uint32_t pcr_mask) {
        return pcr_mask <= TPM2_PCRS_MASK;
}

#define FOREACH_PCR_IN_MASK(pcr, mask) BIT_FOREACH(pcr, mask)

#define TPM2_N_HASH_ALGORITHMS 4U

int dlopen_tpm2(void);

#if HAVE_TPM2

#include <tss2/tss2_esys.h>     /* IWYU pragma: export */
#include <tss2/tss2_mu.h>       /* IWYU pragma: export */
#include <tss2/tss2_rc.h>       /* IWYU pragma: export */

typedef struct Tpm2Context {
        unsigned n_ref;

        void *tcti_dl;
        TSS2_TCTI_CONTEXT *tcti_context;
        ESYS_CONTEXT *esys_context;

        /* Some selected cached capabilities of the TPM */
        TPMS_ALG_PROPERTY *capability_algorithms;
        size_t n_capability_algorithms;
        TPMA_CC *capability_commands;
        size_t n_capability_commands;
        TPM2_ECC_CURVE *capability_ecc_curves;
        size_t n_capability_ecc_curves;
        TPML_PCR_SELECTION capability_pcrs;
} Tpm2Context;

int tpm2_context_new(const char *device, Tpm2Context **ret_context);
int tpm2_context_new_or_warn(const char *device, Tpm2Context **ret_context);
DECLARE_TRIVIAL_REF_UNREF_FUNC(Tpm2Context, tpm2_context);
DEFINE_TRIVIAL_CLEANUP_FUNC(Tpm2Context*, tpm2_context_unref);

typedef struct Tpm2Handle {
        Tpm2Context *tpm2_context;
        ESYS_TR esys_handle;

        bool flush;
} Tpm2Handle;

#define _tpm2_handle(c, h) { .tpm2_context = (c), .esys_handle = (h), }
static const Tpm2Handle TPM2_HANDLE_NONE = _tpm2_handle(NULL, ESYS_TR_NONE);

void Esys_Freep(void *p);

int tpm2_handle_new(Tpm2Context *context, Tpm2Handle **ret_handle);
Tpm2Handle *tpm2_handle_free(Tpm2Handle *handle);
DEFINE_TRIVIAL_CLEANUP_FUNC(Tpm2Handle*, tpm2_handle_free);

typedef struct Tpm2PCRValue {
        unsigned index;
        TPMI_ALG_HASH hash;
        TPM2B_DIGEST value;
} Tpm2PCRValue;

#define TPM2_PCR_VALUE_MAKE(i, h, v)                                    \
        (Tpm2PCRValue) {                                                \
                .index = (i),                                           \
                .hash = (h),                                            \
                .value = ((TPM2B_DIGEST) v),                            \
        }

bool tpm2_pcr_value_valid(const Tpm2PCRValue *pcr_value);
bool tpm2_pcr_values_has_any_values(const Tpm2PCRValue *pcr_values, size_t n_pcr_values);
bool tpm2_pcr_values_has_all_values(const Tpm2PCRValue *pcr_values, size_t n_pcr_values);
int tpm2_pcr_value_from_string(const char *arg, Tpm2PCRValue *ret_pcr_value);
char* tpm2_pcr_value_to_string(const Tpm2PCRValue *pcr_value);

bool tpm2_pcr_values_valid(const Tpm2PCRValue *pcr_values, size_t n_pcr_values);
void tpm2_sort_pcr_values(Tpm2PCRValue *pcr_values, size_t n_pcr_values);
int tpm2_pcr_values_to_mask(const Tpm2PCRValue *pcr_values, size_t n_pcr_values, TPMI_ALG_HASH hash, uint32_t *ret_mask);
int tpm2_pcr_values_from_string(const char *arg, Tpm2PCRValue **ret_pcr_values, size_t *ret_n_pcr_values);
int tpm2_pcr_values_hash_count(const Tpm2PCRValue *pcr_values, size_t n_pcr_values, size_t *ret_count);
int tpm2_tpml_pcr_selection_from_pcr_values(const Tpm2PCRValue *pcr_values, size_t n_pcr_values, TPML_PCR_SELECTION *ret_selection, TPM2B_DIGEST **ret_values, size_t *ret_n_values);

int tpm2_make_encryption_session(Tpm2Context *c, const Tpm2Handle *primary, const Tpm2Handle *bind_key, Tpm2Handle **ret_session);

int tpm2_create_primary(Tpm2Context *c, const Tpm2Handle *session, const TPM2B_PUBLIC *template, const TPM2B_SENSITIVE_CREATE *sensitive, TPM2B_PUBLIC **ret_public, Tpm2Handle **ret_handle);
int tpm2_create(Tpm2Context *c, const Tpm2Handle *parent, const Tpm2Handle *session, const TPMT_PUBLIC *template, const TPMS_SENSITIVE_CREATE *sensitive, TPM2B_PUBLIC **ret_public, TPM2B_PRIVATE **ret_private);
int tpm2_load(Tpm2Context *c, const Tpm2Handle *parent, const Tpm2Handle *session, const TPM2B_PUBLIC *public, const TPM2B_PRIVATE *private, Tpm2Handle **ret_handle);
int tpm2_marshal_public(const TPM2B_PUBLIC *public, void **ret, size_t *ret_size);
int tpm2_marshal_nv_public(const TPM2B_NV_PUBLIC *nv_public, void **ret, size_t *ret_size);
int tpm2_unmarshal_nv_public(const void *data, size_t size, TPM2B_NV_PUBLIC *ret_nv_public);
int tpm2_marshal_blob(const TPM2B_PUBLIC *public, const TPM2B_PRIVATE *private, const TPM2B_ENCRYPTED_SECRET *seed, void **ret_blob, size_t *ret_blob_size);
int tpm2_unmarshal_blob(const void *blob, size_t blob_size, TPM2B_PUBLIC *ret_public, TPM2B_PRIVATE *ret_private, TPM2B_ENCRYPTED_SECRET *ret_seed);
int tpm2_get_name(Tpm2Context *c, const Tpm2Handle *handle, TPM2B_NAME **ret_name);

bool tpm2_supports_alg(Tpm2Context *c, TPM2_ALG_ID alg);
bool tpm2_supports_command(Tpm2Context *c, TPM2_CC command);
bool tpm2_supports_ecc_curve(Tpm2Context *c, TPM2_ECC_CURVE ecc_curve);

bool tpm2_test_parms(Tpm2Context *c, TPMI_ALG_PUBLIC alg, const TPMU_PUBLIC_PARMS *parms);

int tpm2_get_good_pcr_banks(Tpm2Context *c, uint32_t pcr_mask, TPMI_ALG_HASH **ret_banks);
int tpm2_get_good_pcr_banks_strv(Tpm2Context *c, uint32_t pcr_mask, char ***ret);
int tpm2_get_best_pcr_bank(Tpm2Context *c, uint32_t pcr_mask, TPMI_ALG_HASH *ret);

const char* tpm2_userspace_log_path(void);
const char* tpm2_firmware_log_path(void);

typedef enum Tpm2UserspaceEventType {
        TPM2_EVENT_PHASE,
        TPM2_EVENT_FILESYSTEM,
        TPM2_EVENT_VOLUME_KEY,
        TPM2_EVENT_MACHINE_ID,
        TPM2_EVENT_PRODUCT_ID,
        TPM2_EVENT_KEYSLOT,
        TPM2_EVENT_NVPCR_INIT,
        TPM2_EVENT_NVPCR_SEPARATOR,
        TPM2_EVENT_DM_VERITY,
        _TPM2_USERSPACE_EVENT_TYPE_MAX,
        _TPM2_USERSPACE_EVENT_TYPE_INVALID = -EINVAL,
} Tpm2UserspaceEventType;

DECLARE_STRING_TABLE_LOOKUP(tpm2_userspace_event_type, Tpm2UserspaceEventType);

int tpm2_pcr_extend_bytes(Tpm2Context *c, char **banks, unsigned pcr_index, const struct iovec *data, const struct iovec *secret, Tpm2UserspaceEventType event_type, const char *description);
int tpm2_nvpcr_get_index(const char *name, uint32_t *ret);
int tpm2_nvpcr_extend_bytes(Tpm2Context *c, const Tpm2Handle *session, const char *name, const struct iovec *data, const struct iovec *secret, Tpm2UserspaceEventType event_type, const char *description);
int tpm2_nvpcr_acquire_anchor_secret(struct iovec *ret, bool sync_secondary);
int tpm2_nvpcr_initialize(Tpm2Context *c, const Tpm2Handle *session, const char *name, const struct iovec *anchor_secret);
int tpm2_nvpcr_read(Tpm2Context *c, const Tpm2Handle *session, const char *name, struct iovec *ret, uint32_t *ret_nv_index);

uint32_t tpm2_tpms_pcr_selection_to_mask(const TPMS_PCR_SELECTION *s);
void tpm2_tpms_pcr_selection_from_mask(uint32_t mask, TPMI_ALG_HASH hash, TPMS_PCR_SELECTION *ret);
bool tpm2_tpms_pcr_selection_has_mask(const TPMS_PCR_SELECTION *s, uint32_t mask);
void tpm2_tpms_pcr_selection_add_mask(TPMS_PCR_SELECTION *s, uint32_t mask);
void tpm2_tpms_pcr_selection_sub_mask(TPMS_PCR_SELECTION *s, uint32_t mask);
void tpm2_tpms_pcr_selection_add(TPMS_PCR_SELECTION *a, const TPMS_PCR_SELECTION *b);
void tpm2_tpms_pcr_selection_sub(TPMS_PCR_SELECTION *a, const TPMS_PCR_SELECTION *b);
void tpm2_tpms_pcr_selection_move(TPMS_PCR_SELECTION *a, TPMS_PCR_SELECTION *b);
char* tpm2_tpms_pcr_selection_to_string(const TPMS_PCR_SELECTION *s);
size_t tpm2_tpms_pcr_selection_weight(const TPMS_PCR_SELECTION *s);
#define tpm2_tpms_pcr_selection_is_empty(s) (tpm2_tpms_pcr_selection_weight(s) == 0)

uint32_t tpm2_tpml_pcr_selection_to_mask(const TPML_PCR_SELECTION *l, TPMI_ALG_HASH hash);
void tpm2_tpml_pcr_selection_from_mask(uint32_t mask, TPMI_ALG_HASH hash, TPML_PCR_SELECTION *ret);
bool tpm2_tpml_pcr_selection_has_mask(const TPML_PCR_SELECTION *l, TPMI_ALG_HASH hash, uint32_t mask);
void tpm2_tpml_pcr_selection_add_mask(TPML_PCR_SELECTION *l, TPMI_ALG_HASH hash, uint32_t mask);
void tpm2_tpml_pcr_selection_add_tpms_pcr_selection(TPML_PCR_SELECTION *l, const TPMS_PCR_SELECTION *s);
void tpm2_tpml_pcr_selection_sub_tpms_pcr_selection(TPML_PCR_SELECTION *l, const TPMS_PCR_SELECTION *s);
void tpm2_tpml_pcr_selection_add(TPML_PCR_SELECTION *a, const TPML_PCR_SELECTION *b);
void tpm2_tpml_pcr_selection_sub(TPML_PCR_SELECTION *a, const TPML_PCR_SELECTION *b);
char* tpm2_tpml_pcr_selection_to_string(const TPML_PCR_SELECTION *l);
size_t tpm2_tpml_pcr_selection_weight(const TPML_PCR_SELECTION *l);
#define tpm2_tpml_pcr_selection_is_empty(l) (tpm2_tpml_pcr_selection_weight(l) == 0)

int tpm2_digest_many(TPMI_ALG_HASH alg, TPM2B_DIGEST *digest, const struct iovec data[], size_t n_data, bool extend);
static inline int tpm2_digest_buffer(TPMI_ALG_HASH alg, TPM2B_DIGEST *digest, const void *data, size_t len, bool extend) {
        return tpm2_digest_many(alg, digest, &IOVEC_MAKE((void*) data, len), 1, extend);
}
int tpm2_digest_many_digests(TPMI_ALG_HASH alg, TPM2B_DIGEST *digest, const TPM2B_DIGEST data[], size_t n_data, bool extend);
static inline int tpm2_digest_rehash(TPMI_ALG_HASH alg, TPM2B_DIGEST *digest) {
        return tpm2_digest_many(alg, digest, NULL, 0, true);
}
static inline int tpm2_digest_init(TPMI_ALG_HASH alg, TPM2B_DIGEST *digest) {
        return tpm2_digest_many(alg, digest, NULL, 0, false);
}

void tpm2_log_debug_tpml_pcr_selection(const TPML_PCR_SELECTION *l, const char *msg);
void tpm2_log_debug_pcr_value(const Tpm2PCRValue *pcr_value, const char *msg);
void tpm2_log_debug_buffer(const void *buffer, size_t size, const char *msg);
void tpm2_log_debug_digest(const TPM2B_DIGEST *digest, const char *msg);
void tpm2_log_debug_name(const TPM2B_NAME *name, const char *msg);

typedef struct Tpm2PCRPredictionResult {
        TPM2B_DIGEST hash[TPM2_N_HASH_ALGORITHMS]; /* a hash for each potential algorithm */
} Tpm2PCRPredictionResult;

TPM2B_DIGEST *tpm2_pcr_prediction_result_get_hash(Tpm2PCRPredictionResult *result, uint16_t alg);

/* A structure encapsulating a full set of PCR predictions with alternatives. This can be converted into a
 * series of PolicyOR + PolicyPCR items for the TPM. */
typedef struct Tpm2PCRPrediction {
        uint32_t pcrs;                      /* A mask of pcrs included */
        OrderedSet* results[TPM2_PCRS_MAX]; /* set of Tpm2PCRPredictionResult objects, one for each PCR */
} Tpm2PCRPrediction;

void tpm2_pcr_prediction_done(Tpm2PCRPrediction *p);

extern const struct hash_ops tpm2_pcr_prediction_result_hash_ops;

bool tpm2_pcr_prediction_equal(Tpm2PCRPrediction *a, Tpm2PCRPrediction *b, uint16_t algorithm);

int tpm2_pcr_prediction_to_json(const Tpm2PCRPrediction *prediction, uint16_t algorithm, sd_json_variant **ret);
int tpm2_pcr_prediction_from_json(Tpm2PCRPrediction *prediction, uint16_t algorithm, sd_json_variant *aj);

/* As structure encapsulating all metadata stored for a pcrlock policy on disk */
typedef struct Tpm2PCRLockPolicy {
        /* The below is the fixed metadata encoding information about the NV index we store the
         * PolicyAuthorizeNV policy in, as well as a pinned SRK, and the encrypted PIN to use for writing to
         * the NV Index. */
        uint16_t algorithm;
        uint32_t nv_index;
        struct iovec nv_handle;
        struct iovec nv_public;
        struct iovec srk_handle;
        struct iovec pin_public;
        struct iovec pin_private;

        /* The below contains the current prediction whose resulting policy is stored in the NV
         * index. Once in JSON and once in parsed form. When the policy is updated the fields below are
         * changed, the fields above remain fixed. */
        sd_json_variant *prediction_json;
        Tpm2PCRPrediction prediction;
} Tpm2PCRLockPolicy;

void tpm2_pcrlock_policy_done(Tpm2PCRLockPolicy *data);
int tpm2_pcrlock_policy_from_json(sd_json_variant *v, Tpm2PCRLockPolicy *ret_policy);
int tpm2_pcrlock_search_file(const char *path, FILE **ret_file, char **ret_path);
int tpm2_pcrlock_policy_load(const char *path, Tpm2PCRLockPolicy *ret_policy);
int tpm2_pcrlock_policy_from_credentials(const struct iovec *srk, const struct iovec *nv, Tpm2PCRLockPolicy *ret);

int tpm2_index_to_handle(Tpm2Context *c, TPM2_HANDLE index, const Tpm2Handle *session, TPM2B_PUBLIC **ret_public, TPM2B_NAME **ret_name, TPM2B_NAME **ret_qname, Tpm2Handle **ret_handle);
int tpm2_index_from_handle(Tpm2Context *c, const Tpm2Handle *handle, TPM2_HANDLE *ret_index);

int tpm2_pcr_read(Tpm2Context *c, const TPML_PCR_SELECTION *pcr_selection, Tpm2PCRValue **ret_pcr_values, size_t *ret_n_pcr_values);
int tpm2_pcr_read_missing_values(Tpm2Context *c, Tpm2PCRValue *pcr_values, size_t n_pcr_values);

int tpm2_auth_value_from_pin(TPMI_ALG_HASH hash, const char *pin, TPM2B_AUTH *ret_auth);
int tpm2_set_auth(Tpm2Context *c, const Tpm2Handle *handle, const char *pin);
int tpm2_set_auth_binary(Tpm2Context *c, const Tpm2Handle *handle, const TPM2B_AUTH *auth);

int tpm2_make_policy_session(Tpm2Context *c, const Tpm2Handle *primary, const Tpm2Handle *encryption_session, Tpm2Handle **ret_session);

int tpm2_policy_auth_value(Tpm2Context *c, const Tpm2Handle *session, TPM2B_DIGEST **ret_policy_digest);
int tpm2_policy_authorize_nv(Tpm2Context *c, const Tpm2Handle *session, const Tpm2Handle *nv_handle, TPM2B_DIGEST **ret_policy_digest);
int tpm2_policy_pcr(Tpm2Context *c, const Tpm2Handle *session, const TPML_PCR_SELECTION *pcr_selection, TPM2B_DIGEST **ret_policy_digest);
int tpm2_policy_or(Tpm2Context *c, const Tpm2Handle *session, const TPM2B_DIGEST *branches, size_t n_branches, TPM2B_DIGEST **ret_policy_digest);
int tpm2_policy_super_pcr(Tpm2Context *c, const Tpm2Handle *session, const Tpm2PCRPrediction *prediction, uint16_t algorithm);
int tpm2_policy_signed_hmac_sha256(Tpm2Context *c, const Tpm2Handle *session, const Tpm2Handle *hmac_key_handle, const struct iovec *hmac_key, TPM2B_DIGEST **ret_policy_digest);

int tpm2_calculate_pubkey_name(const TPMT_PUBLIC *public, TPM2B_NAME *ret_name);
int tpm2_calculate_nv_index_name(const TPMS_NV_PUBLIC *nvpublic, TPM2B_NAME *ret_name);

int tpm2_calculate_policy_auth_value(TPM2B_DIGEST *digest);
int tpm2_calculate_policy_authorize(const TPM2B_PUBLIC *public, const TPM2B_DIGEST *policy_ref, TPM2B_DIGEST *digest);
int tpm2_calculate_policy_authorize_nv(const TPM2B_NV_PUBLIC *public, TPM2B_DIGEST *digest);
int tpm2_calculate_policy_pcr(const Tpm2PCRValue *pcr_values, size_t n_pcr_values, TPM2B_DIGEST *digest);
int tpm2_calculate_policy_or(const TPM2B_DIGEST *branches, size_t n_branches, TPM2B_DIGEST *digest);
int tpm2_calculate_policy_super_pcr(Tpm2PCRPrediction *prediction, uint16_t algorithm, TPM2B_DIGEST *pcr_policy);
int tpm2_calculate_policy_signed(TPM2B_DIGEST *digest, const TPM2B_NAME *name);
int tpm2_calculate_serialize(TPM2_HANDLE handle, const TPM2B_NAME *name, const TPM2B_PUBLIC *public, void **ret_serialized, size_t *ret_serialized_size);
int tpm2_calculate_sealing_policy(const Tpm2PCRValue *pcr_values, size_t n_pcr_values, const TPM2B_PUBLIC *public, bool use_pin, const Tpm2PCRLockPolicy *pcrlock_policy, TPM2B_DIGEST *digest);
int tpm2_calculate_seal(TPM2_HANDLE parent_handle, const TPM2B_PUBLIC *parent_public, const TPMA_OBJECT *attributes, const struct iovec *secret, const TPM2B_DIGEST *policy, const char *pin, struct iovec *ret_secret, struct iovec *ret_blob, struct iovec *ret_serialized_parent);

int tpm2_get_srk_template(TPMI_ALG_PUBLIC alg, TPMT_PUBLIC *ret_template);
int tpm2_get_best_srk_template(Tpm2Context *c, TPMT_PUBLIC *ret_template);

int tpm2_get_srk(Tpm2Context *c, const Tpm2Handle *session, TPM2B_PUBLIC **ret_public, TPM2B_NAME **ret_name, TPM2B_NAME **ret_qname, Tpm2Handle **ret_handle);
int tpm2_get_or_create_srk(Tpm2Context *c, const Tpm2Handle *session, TPM2B_PUBLIC **ret_public, TPM2B_NAME **ret_name, TPM2B_NAME **ret_qname, Tpm2Handle **ret_handle);

int tpm2_seal(Tpm2Context *c, uint32_t seal_key_handle, const TPM2B_DIGEST policy_hash[], size_t n_policy, const char *pin, struct iovec *ret_secret, struct iovec **ret_blobs, size_t *ret_n_blobs, uint16_t *ret_primary_alg, struct iovec *ret_srk);
int tpm2_unseal(Tpm2Context *c, uint32_t hash_pcr_mask, uint16_t pcr_bank, const struct iovec *pubkey, uint32_t pubkey_pcr_mask, sd_json_variant *signature, const char *pin, const Tpm2PCRLockPolicy *pcrlock_policy, uint16_t primary_alg, const struct iovec blobs[], size_t n_blobs, const struct iovec known_policy_hash[], size_t n_known_policy_hash, const struct iovec *srk, struct iovec *ret_secret);

/* tpm2_unseal() returns a bunch of different errors for various flavours of PCR issues, let's group them */
#define ERRNO_IS_NEG_TPM2_UNSEAL_BAD_PCR(r) IN_SET(r, -EREMCHG, -ENOANO, -EUCLEAN, -EPERM)

#if HAVE_OPENSSL
int tpm2_tpm2b_public_to_openssl_pkey(const TPM2B_PUBLIC *public, EVP_PKEY **ret);
int tpm2_tpm2b_public_from_openssl_pkey(const EVP_PKEY *pkey, TPM2B_PUBLIC *ret);
#endif

int tpm2_tpm2b_public_from_pem(const void *pem, size_t pem_size, TPM2B_PUBLIC *ret);
int tpm2_tpm2b_public_to_fingerprint(const TPM2B_PUBLIC *public, void **ret_fingerprint, size_t *ret_fingerprint_size);

int tpm2_define_policy_nv_index(Tpm2Context *c, const Tpm2Handle *session, TPM2_HANDLE requested_nv_index, const TPM2B_DIGEST *write_policy, TPM2_HANDLE *ret_nv_index, Tpm2Handle **ret_nv_handle, TPM2B_NV_PUBLIC *ret_nv_public);
int tpm2_write_policy_nv_index(Tpm2Context *c, const Tpm2Handle *policy_session, TPM2_HANDLE nv_index, const Tpm2Handle *nv_handle, const TPM2B_DIGEST *policy_digest);
int tpm2_define_nvpcr_nv_index(Tpm2Context *c, const Tpm2Handle *session, TPM2_HANDLE nv_index, TPMI_ALG_HASH algorithm, Tpm2Handle **ret_nv_handle);
int tpm2_extend_nvpcr_nv_index(Tpm2Context *c, TPM2_HANDLE nv_index, const Tpm2Handle *nv_handle, const struct iovec *digest);
int tpm2_undefine_nv_index(Tpm2Context *c, const Tpm2Handle *session, TPM2_HANDLE nv_index, const Tpm2Handle *nv_handle);
int tpm2_read_nv_index(Tpm2Context *c, const Tpm2Handle *session, TPM2_HANDLE nv_index, const Tpm2Handle *nv_handle, struct iovec *ret_value);

int tpm2_seal_data(Tpm2Context *c, const struct iovec *data, const Tpm2Handle *primary_handle, const Tpm2Handle *encryption_session, const TPM2B_DIGEST *policy, struct iovec *ret_public, struct iovec *ret_private);
int tpm2_unseal_data(Tpm2Context *c, const struct iovec *public, const struct iovec *private, const Tpm2Handle *primary_handle, const Tpm2Handle *policy_session, const Tpm2Handle *encryption_session, struct iovec *ret_data);

int tpm2_serialize(Tpm2Context *c, const Tpm2Handle *handle, struct iovec *ret);
int tpm2_deserialize(Tpm2Context *c, const struct iovec *serialized, Tpm2Handle **ret_handle);

int tpm2_load_public_key_file(const char *path, TPM2B_PUBLIC *ret);

int tpm2_hmac_key_from_pin(Tpm2Context *c, const Tpm2Handle *session, const TPM2B_AUTH *pin, Tpm2Handle **ret);

/* The tpm2-tss library has many structs that are simply a combination of an array (or object) and
 * size. These macros allow easily initializing or assigning instances of such structs from an existing
 * buffer/object and size, while also checking the size for safety with the struct buffer/object size. If the
 * provided buffer/object is NULL, the resulting struct's buffer/object will be 0s. If the provided size is
 * larger than the struct's buffer/object size, this results in assertion failure; to check the size, use one
 * of the TPM2B_*_CHECK_SIZE() macros. */
#define TPM2B_AUTH_MAKE(b, s) TPM2B_BUF_SIZE_STRUCT_MAKE(b, s, TPM2B_AUTH, buffer, size)
#define TPM2B_DATA_MAKE(b, s) TPM2B_BUF_SIZE_STRUCT_MAKE(b, s, TPM2B_DATA, buffer, size)
#define TPM2B_DIGEST_MAKE(b, s) TPM2B_BUF_SIZE_STRUCT_MAKE(b, s, TPM2B_DIGEST, buffer, size)
#define TPM2B_ECC_PARAMETER_MAKE(b, s) TPM2B_BUF_SIZE_STRUCT_MAKE(b, s, TPM2B_ECC_PARAMETER, buffer, size)
#define TPM2B_ENCRYPTED_SECRET_MAKE(b, s) TPM2B_BUF_SIZE_STRUCT_MAKE(b, s, TPM2B_ENCRYPTED_SECRET, secret, size)
#define TPM2B_MAX_BUFFER_MAKE(b, s) TPM2B_BUF_SIZE_STRUCT_MAKE(b, s, TPM2B_MAX_BUFFER, buffer, size)
#define TPM2B_NAME_MAKE(b, s) TPM2B_BUF_SIZE_STRUCT_MAKE(b, s, TPM2B_NAME, name, size)
#define TPM2B_PRIVATE_MAKE(b, s) TPM2B_BUF_SIZE_STRUCT_MAKE(b, s, TPM2B_PRIVATE, buffer, size)
#define TPM2B_PRIVATE_KEY_RSA_MAKE(b, s) TPM2B_BUF_SIZE_STRUCT_MAKE(b, s, TPM2B_PRIVATE_KEY_RSA, buffer, size)
#define TPM2B_PUBLIC_KEY_RSA_MAKE(b, s) TPM2B_BUF_SIZE_STRUCT_MAKE(b, s, TPM2B_PUBLIC_KEY_RSA, buffer, size)
#define TPM2B_SENSITIVE_DATA_MAKE(b, s) TPM2B_BUF_SIZE_STRUCT_MAKE(b, s, TPM2B_SENSITIVE_DATA, buffer, size)
#define TPM2B_BUF_SIZE_STRUCT_MAKE(buf, size, struct_type, buffer_field, size_field) \
        _TPM2B_BUF_SIZE_STRUCT_MAKE(buf, size, UNIQ, struct_type, buffer_field, size_field)
#define _TPM2B_BUF_SIZE_STRUCT_MAKE(buf, size, uniq, struct_type, buffer_field, size_field) \
        ({                                                              \
                typeof(buf) UNIQ_T(BUF, uniq) = (buf);                  \
                typeof(size) UNIQ_T(SIZE, uniq) = (size);               \
                struct_type UNIQ_T(STRUCT, uniq) = { .size_field = UNIQ_T(SIZE, uniq), }; \
                assert(sizeof(UNIQ_T(STRUCT, uniq).buffer_field) >= (size_t) UNIQ_T(SIZE, uniq)); \
                if (UNIQ_T(BUF, uniq))                                  \
                        memcpy_safe(UNIQ_T(STRUCT, uniq).buffer_field, UNIQ_T(BUF, uniq), UNIQ_T(SIZE, uniq)); \
                UNIQ_T(STRUCT, uniq);                                   \
        })

/* Check if the size will fit in the TPM2B struct buffer. Returns 0 if the size will fit, otherwise this logs
 * a debug message and returns < 0. */
#define TPM2B_AUTH_CHECK_SIZE(s) TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(s, TPM2B_AUTH, buffer)
#define TPM2B_DATA_CHECK_SIZE(s) TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(s, TPM2B_DATA, buffer)
#define TPM2B_DIGEST_CHECK_SIZE(s) TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(s, TPM2B_DIGEST, buffer)
#define TPM2B_ECC_PARAMETER_CHECK_SIZE(s) TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(s, TPM2B_ECC_PARAMETER, buffer)
#define TPM2B_ENCRYPTED_SECRET_CHECK_SIZE(s) TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(s, TPM2B_ENCRYPTED_SECRET, buffer)
#define TPM2B_MAX_BUFFER_CHECK_SIZE(s) TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(s, TPM2B_MAX_BUFFER, buffer)
#define TPM2B_NAME_CHECK_SIZE(s) TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(s, TPM2B_NAME, name)
#define TPM2B_PRIVATE_CHECK_SIZE(s) TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(s, TPM2B_PRIVATE, buffer)
#define TPM2B_PRIVATE_KEY_RSA_CHECK_SIZE(s) TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(s, TPM2B_PRIVATE_KEY_RSA, buffer)
#define TPM2B_PUBLIC_KEY_RSA_CHECK_SIZE(s) TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(s, TPM2B_PUBLIC_KEY_RSA, buffer)
#define TPM2B_SENSITIVE_DATA_CHECK_SIZE(s) TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(s, TPM2B_SENSITIVE_DATA, buffer)
#define TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(size, struct_type, buffer_field) \
        _TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(size, UNIQ, struct_type, buffer_field)
#define _TPM2B_BUF_SIZE_STRUCT_CHECK_SIZE(size, uniq, struct_type, buffer_field) \
        ({                                                              \
                size_t UNIQ_T(SIZE, uniq) = (size_t) (size);            \
                size_t UNIQ_T(BUFSIZE, uniq) = sizeof_field(struct_type, buffer_field); \
                UNIQ_T(BUFSIZE, uniq) < UNIQ_T(SIZE, uniq) ?            \
                        log_debug_errno(SYNTHETIC_ERRNO(EINVAL),        \
                                        "Size %zu larger than " #struct_type " buffer size %zu.", \
                                        UNIQ_T(SIZE, uniq), UNIQ_T(BUFSIZE, uniq)) : \
                        0;                                              \
        })

#else /* HAVE_TPM2 */
typedef struct Tpm2Context {} Tpm2Context;
typedef struct Tpm2Handle {} Tpm2Handle;
typedef struct Tpm2PCRValue {} Tpm2PCRValue;

#define TPM2_PCR_VALUE_MAKE(i, h, v) (Tpm2PCRValue) {}

static inline int tpm2_pcrlock_search_file(const char *path, FILE **ret_file, char **ret_path) {
        return -ENOENT;
}

#endif /* HAVE_TPM2 */

int tpm2_list_devices(bool legend, bool quiet);
int tpm2_find_device_auto(char **ret);

int tpm2_make_pcr_json_array(uint32_t pcr_mask, sd_json_variant **ret);
int tpm2_parse_pcr_json_array(sd_json_variant *v, uint32_t *ret);

int tpm2_make_luks2_json(int keyslot, uint32_t hash_pcr_mask, uint16_t pcr_bank, const struct iovec *pubkey, uint32_t pubkey_pcr_mask, uint16_t primary_alg, const struct iovec blobs[], size_t n_blobs, const struct iovec policy_hash[], size_t n_policy_hash, const struct iovec *salt, const struct iovec *srk, const struct iovec *pcrlock_nv, TPM2Flags flags, sd_json_variant **ret);
int tpm2_parse_luks2_json(sd_json_variant *v, int *ret_keyslot, uint32_t *ret_hash_pcr_mask, uint16_t *ret_pcr_bank, struct iovec *ret_pubkey, uint32_t *ret_pubkey_pcr_mask, uint16_t *ret_primary_alg, struct iovec **ret_blobs, size_t *ret_n_blobs, struct iovec **ret_policy_hash, size_t *ret_n_policy_hash, struct iovec *ret_salt, struct iovec *ret_srk, struct iovec *ret_pcrlock_nv, TPM2Flags *ret_flags);

/* Before v258 we used to bind to PCR 7 by default at various places if no explicit PCR mask was set. With
 * v258 we stopped doing that (since the SecureBoot DB is as much subject to regular updates by tools such as
 * fwupd as the firmware itself), but when unlocking to maintain compatibility when no mask is specified we
 * still need to default to PCR 7. */
#define TPM2_PCR_INDEX_DEFAULT_LEGACY TPM2_PCR_SECURE_BOOT_POLICY
#define TPM2_PCR_MASK_DEFAULT_LEGACY INDEX_TO_MASK(uint32_t, TPM2_PCR_INDEX_DEFAULT_LEGACY)

/* We want the helpers below to work also if TPM2 libs are not available, hence define these four defines if
 * they are missing. */
#ifndef TPM2_ALG_SHA1
#define TPM2_ALG_SHA1 0x4
#endif

#ifndef TPM2_ALG_SHA256
#define TPM2_ALG_SHA256 0xB
#endif

#ifndef TPM2_ALG_SHA384
#define TPM2_ALG_SHA384 0xC
#endif

#ifndef TPM2_ALG_SHA512
#define TPM2_ALG_SHA512 0xD
#endif

#ifndef TPM2_ALG_ECC
#define TPM2_ALG_ECC 0x23
#endif

#ifndef TPM2_ALG_RSA
#define TPM2_ALG_RSA 0x1
#endif

int tpm2_hash_alg_to_size(uint16_t alg);

const char* tpm2_hash_alg_to_string(uint16_t alg) _const_;
int tpm2_hash_alg_from_string(const char *alg) _pure_;

const char* tpm2_asym_alg_to_string(uint16_t alg) _const_;
int tpm2_asym_alg_from_string(const char *alg) _pure_;

const char* tpm2_sym_alg_to_string(uint16_t alg) _const_;
const char* tpm2_sym_mode_to_string(uint16_t mode) _const_;
int tpm2_sym_mode_from_string(const char *mode) _pure_;

char* tpm2_pcr_mask_to_string(uint32_t mask);

extern const uint16_t tpm2_hash_algorithms[];

typedef struct systemd_tpm2_plugin_params {
        uint32_t search_pcr_mask;
        const char *device;
        const char *signature_path;
        const char *pcrlock_path;
} systemd_tpm2_plugin_params;

typedef enum Tpm2Support {
        /* NOTE! The systemd-analyze has-tpm2 command returns these flags 1:1 as exit status. Hence these
         * flags are pretty much ABI! Hence, be extra careful when changing/extending these definitions. */
        TPM2_SUPPORT_NONE         = 0,       /* no support */
        TPM2_SUPPORT_FIRMWARE     = 1 << 0,  /* firmware reports TPM2 was used */
        TPM2_SUPPORT_DRIVER       = 1 << 1,  /* the kernel has a driver loaded for it */
        TPM2_SUPPORT_SYSTEM       = 1 << 2,  /* we support it ourselves */
        TPM2_SUPPORT_SUBSYSTEM    = 1 << 3,  /* the kernel has the tpm subsystem enabled */
        TPM2_SUPPORT_LIBRARIES    = 1 << 4,  /* we can dlopen the tpm2 libraries */
        TPM2_SUPPORT_API          = TPM2_SUPPORT_FIRMWARE|TPM2_SUPPORT_DRIVER|TPM2_SUPPORT_SYSTEM|TPM2_SUPPORT_SUBSYSTEM|TPM2_SUPPORT_LIBRARIES,

        /* Flags below are used by pcrlock, to indicate hardware specific features. It's not used by systemd-analyze has-tpm2. */
        TPM2_SUPPORT_AUTHORIZE_NV = 1 << 5,  /* chip supports PolicyAuthorizeNV */
        TPM2_SUPPORT_SHA256       = 1 << 6,  /* chip supports SHA-256 */
        TPM2_SUPPORT_API_PCRLOCK  = TPM2_SUPPORT_API | TPM2_SUPPORT_AUTHORIZE_NV | TPM2_SUPPORT_SHA256,

        /* Flags below are not returned by systemd-analyze has-tpm2 nor by systemd-pcrlock as exit status. */
        TPM2_SUPPORT_LIBTSS2_ESYS = 1 << 7,  /* we can dlopen libtss2-esys.so.0 */
        TPM2_SUPPORT_LIBTSS2_RC   = 1 << 8,  /* we can dlopen libtss2-rc.so.0 */
        TPM2_SUPPORT_LIBTSS2_MU   = 1 << 9,  /* we can dlopen libtss2-mu.so.0 */
        TPM2_SUPPORT_LIBTSS2_ALL  = TPM2_SUPPORT_LIBTSS2_ESYS|TPM2_SUPPORT_LIBTSS2_RC|TPM2_SUPPORT_LIBTSS2_MU,

        /* Combined flags for generic (i.e. not tool-specific) support */
        TPM2_SUPPORT_FULL         = TPM2_SUPPORT_API|TPM2_SUPPORT_LIBTSS2_ALL,
} Tpm2Support;

Tpm2Support tpm2_support_full(Tpm2Support mask);
static inline Tpm2Support tpm2_support(void) {
        return tpm2_support_full(TPM2_SUPPORT_FULL);
}
static inline bool tpm2_is_fully_supported(void) {
        return tpm2_support() == TPM2_SUPPORT_FULL;
}

int verb_has_tpm2_generic(bool quiet);

int tpm2_parse_pcr_argument(const char *arg, Tpm2PCRValue **ret_pcr_values, size_t *ret_n_pcr_values);
int tpm2_parse_pcr_argument_append(const char *arg, Tpm2PCRValue **pcr_values, size_t *n_pcr_values);
int tpm2_parse_pcr_argument_to_mask(const char *arg, uint32_t *mask);

int tpm2_load_pcr_signature(const char *path, sd_json_variant **ret);
int tpm2_load_pcr_public_key(const char *path, void **ret_pubkey, size_t *ret_pubkey_size);

int tpm2_util_pbkdf2_hmac_sha256(const void *pass,
                    size_t passlen,
                    const void *salt,
                    size_t saltlen,
                    uint8_t ret[static SHA256_DIGEST_SIZE]);

enum {
        /* Additional defines for the PCR index naming enum from "fundamental/tpm2-pcr.h" */
        _TPM2_PCR_INDEX_MAX_DEFINED = TPM2_PCRS_MAX,
        _TPM2_PCR_INDEX_INVALID     = -EINVAL,
};

DECLARE_STRING_TABLE_LOOKUP(tpm2_pcr_index, int);

/* The first and last NV index handle that is not registered to any company, as per TCG's "Registry of
 * Reserved TPM 2.0 Handles and Localities", section 2.2.2. */
#define TPM2_NV_INDEX_UNASSIGNED_FIRST UINT32_C(0x01800000)
#define TPM2_NV_INDEX_UNASSIGNED_LAST  UINT32_C(0x01BFFFFF)

#if HAVE_TPM2
/* Verify that the above is indeed a subset of the general NV Index range */
assert_cc(TPM2_NV_INDEX_UNASSIGNED_FIRST >= TPM2_NV_INDEX_FIRST);
assert_cc(TPM2_NV_INDEX_UNASSIGNED_LAST <= TPM2_NV_INDEX_LAST);
#endif

bool tpm2_nvpcr_name_is_valid(const char *name);
