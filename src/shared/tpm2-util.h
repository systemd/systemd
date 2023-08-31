/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "bitfield.h"
#include "io-util.h"
#include "json.h"
#include "macro.h"
#include "openssl-util.h"
#include "sha256.h"
#include "tpm2-pcr.h"

typedef enum TPM2Flags {
        TPM2_FLAGS_USE_PIN = 1 << 0,
} TPM2Flags;

/* As per https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf a
 * TPM2 on a Client PC must have at least 24 PCRs. This hardcodes our expectation of 24. */
#define TPM2_PCRS_MAX 24U
#define TPM2_PCRS_MASK ((UINT32_C(1) << TPM2_PCRS_MAX) - 1)

static inline bool TPM2_PCR_INDEX_VALID(unsigned pcr) {
        return pcr < TPM2_PCRS_MAX;
}
static inline bool TPM2_PCR_MASK_VALID(uint32_t pcr_mask) {
        return pcr_mask <= TPM2_PCRS_MASK;
}

#define FOREACH_PCR_IN_MASK(pcr, mask) BIT_FOREACH(pcr, mask)

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

#if HAVE_TPM2

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>

int dlopen_tpm2(void);

/* Calls dlopen_tpm2() and returns 0 on success, < 0 on error. Also logs on error. Useful in "elvis operator"
 * ternary checks. */
static inline int tpm2_dlopen(void) {
        int r = dlopen_tpm2();
        if (r < 0)
                return log_error_errno(r, "Could not dlopen libtss2 libraries: %m");

        return 0;
}

typedef struct {
        unsigned n_ref;

        void *tcti_dl;
        TSS2_TCTI_CONTEXT *tcti_context;
        ESYS_CONTEXT *esys_context;

        /* Some selected cached capabilities of the TPM */
        TPMS_ALG_PROPERTY *capability_algorithms;
        size_t n_capability_algorithms;
        TPMA_CC *capability_commands;
        size_t n_capability_commands;
        TPML_PCR_SELECTION capability_pcrs;
} Tpm2Context;

int tpm2_context_new(const char *device, Tpm2Context **ret_context);
Tpm2Context *tpm2_context_ref(Tpm2Context *context);
Tpm2Context *tpm2_context_unref(Tpm2Context *context);
DEFINE_TRIVIAL_CLEANUP_FUNC(Tpm2Context*, tpm2_context_unref);

typedef struct {
        Tpm2Context *tpm2_context;
        ESYS_TR esys_handle;

        bool flush;
} Tpm2Handle;

#define _tpm2_handle(c, h) { .tpm2_context = (c), .esys_handle = (h), }
static const Tpm2Handle TPM2_HANDLE_NONE = _tpm2_handle(NULL, ESYS_TR_NONE);

int tpm2_handle_new(Tpm2Context *context, Tpm2Handle **ret_handle);
Tpm2Handle *tpm2_handle_free(Tpm2Handle *handle);
DEFINE_TRIVIAL_CLEANUP_FUNC(Tpm2Handle*, tpm2_handle_free);

typedef struct {
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
char *tpm2_pcr_value_to_string(const Tpm2PCRValue *pcr_value);

bool tpm2_pcr_values_valid(const Tpm2PCRValue *pcr_values, size_t n_pcr_values);
void tpm2_sort_pcr_values(Tpm2PCRValue *pcr_values, size_t n_pcr_values);
int tpm2_pcr_values_from_mask(uint32_t mask, TPMI_ALG_HASH hash, Tpm2PCRValue **ret_pcr_values, size_t *ret_n_pcr_values);
int tpm2_pcr_values_to_mask(const Tpm2PCRValue *pcr_values, size_t n_pcr_values, TPMI_ALG_HASH hash, uint32_t *ret_mask);
int tpm2_pcr_values_from_string(const char *arg, Tpm2PCRValue **ret_pcr_values, size_t *ret_n_pcr_values);
char *tpm2_pcr_values_to_string(const Tpm2PCRValue *pcr_values, size_t n_pcr_values);
int tpm2_pcr_values_hash_count(const Tpm2PCRValue *pcr_values, size_t n_pcr_values, size_t *ret_count);
int tpm2_tpml_pcr_selection_from_pcr_values(const Tpm2PCRValue *pcr_values, size_t n_pcr_values, TPML_PCR_SELECTION *ret_selection, TPM2B_DIGEST **ret_values, size_t *ret_n_values);

int tpm2_create_primary(Tpm2Context *c, const Tpm2Handle *session, const TPM2B_PUBLIC *template, const TPM2B_SENSITIVE_CREATE *sensitive, TPM2B_PUBLIC **ret_public, Tpm2Handle **ret_handle);
int tpm2_create(Tpm2Context *c, const Tpm2Handle *parent, const Tpm2Handle *session, const TPMT_PUBLIC *template, const TPMS_SENSITIVE_CREATE *sensitive, TPM2B_PUBLIC **ret_public, TPM2B_PRIVATE **ret_private);
int tpm2_create_loaded(Tpm2Context *c, const Tpm2Handle *parent, const Tpm2Handle *session, const TPMT_PUBLIC *template, const TPMS_SENSITIVE_CREATE *sensitive, TPM2B_PUBLIC **ret_public, TPM2B_PRIVATE **ret_private, Tpm2Handle **ret_handle);

bool tpm2_supports_alg(Tpm2Context *c, TPM2_ALG_ID alg);
bool tpm2_supports_command(Tpm2Context *c, TPM2_CC command);

bool tpm2_test_parms(Tpm2Context *c, TPMI_ALG_PUBLIC alg, const TPMU_PUBLIC_PARMS *parms);

int tpm2_get_good_pcr_banks(Tpm2Context *c, uint32_t pcr_mask, TPMI_ALG_HASH **ret_banks);
int tpm2_get_good_pcr_banks_strv(Tpm2Context *c, uint32_t pcr_mask, char ***ret);
int tpm2_get_best_pcr_bank(Tpm2Context *c, uint32_t pcr_mask, TPMI_ALG_HASH *ret);

const char *tpm2_userspace_log_path(void);

typedef enum Tpm2UserspaceEventType {
        TPM2_EVENT_PHASE,
        TPM2_EVENT_FILESYSTEM,
        TPM2_EVENT_VOLUME_KEY,
        TPM2_EVENT_MACHINE_ID,
        _TPM2_USERSPACE_EVENT_TYPE_MAX,
        _TPM2_USERSPACE_EVENT_TYPE_INVALID = -EINVAL,
} Tpm2UserspaceEventType;

const char* tpm2_userspace_event_type_to_string(Tpm2UserspaceEventType type) _const_;
Tpm2UserspaceEventType tpm2_userspace_event_type_from_string(const char *s) _pure_;

int tpm2_extend_bytes(Tpm2Context *c, char **banks, unsigned pcr_index, const void *data, size_t data_size, const void *secret, size_t secret_size, Tpm2UserspaceEventType event, const char *description);

uint32_t tpm2_tpms_pcr_selection_to_mask(const TPMS_PCR_SELECTION *s);
void tpm2_tpms_pcr_selection_from_mask(uint32_t mask, TPMI_ALG_HASH hash, TPMS_PCR_SELECTION *ret);
bool tpm2_tpms_pcr_selection_has_mask(const TPMS_PCR_SELECTION *s, uint32_t mask);
void tpm2_tpms_pcr_selection_add_mask(TPMS_PCR_SELECTION *s, uint32_t mask);
void tpm2_tpms_pcr_selection_sub_mask(TPMS_PCR_SELECTION *s, uint32_t mask);
void tpm2_tpms_pcr_selection_add(TPMS_PCR_SELECTION *a, const TPMS_PCR_SELECTION *b);
void tpm2_tpms_pcr_selection_sub(TPMS_PCR_SELECTION *a, const TPMS_PCR_SELECTION *b);
void tpm2_tpms_pcr_selection_move(TPMS_PCR_SELECTION *a, TPMS_PCR_SELECTION *b);
char *tpm2_tpms_pcr_selection_to_string(const TPMS_PCR_SELECTION *s);
size_t tpm2_tpms_pcr_selection_weight(const TPMS_PCR_SELECTION *s);
#define tpm2_tpms_pcr_selection_is_empty(s) (tpm2_tpms_pcr_selection_weight(s) == 0)

uint32_t tpm2_tpml_pcr_selection_to_mask(const TPML_PCR_SELECTION *l, TPMI_ALG_HASH hash);
void tpm2_tpml_pcr_selection_from_mask(uint32_t mask, TPMI_ALG_HASH hash, TPML_PCR_SELECTION *ret);
bool tpm2_tpml_pcr_selection_has_mask(const TPML_PCR_SELECTION *l, TPMI_ALG_HASH hash, uint32_t mask);
void tpm2_tpml_pcr_selection_add_mask(TPML_PCR_SELECTION *l, TPMI_ALG_HASH hash, uint32_t mask);
void tpm2_tpml_pcr_selection_sub_mask(TPML_PCR_SELECTION *l, TPMI_ALG_HASH hash, uint32_t mask);
void tpm2_tpml_pcr_selection_add_tpms_pcr_selection(TPML_PCR_SELECTION *l, const TPMS_PCR_SELECTION *s);
void tpm2_tpml_pcr_selection_sub_tpms_pcr_selection(TPML_PCR_SELECTION *l, const TPMS_PCR_SELECTION *s);
void tpm2_tpml_pcr_selection_add(TPML_PCR_SELECTION *a, const TPML_PCR_SELECTION *b);
void tpm2_tpml_pcr_selection_sub(TPML_PCR_SELECTION *a, const TPML_PCR_SELECTION *b);
char *tpm2_tpml_pcr_selection_to_string(const TPML_PCR_SELECTION *l);
size_t tpm2_tpml_pcr_selection_weight(const TPML_PCR_SELECTION *l);
#define tpm2_tpml_pcr_selection_is_empty(l) (tpm2_tpml_pcr_selection_weight(l) == 0)

int tpm2_digest_many(TPMI_ALG_HASH alg, TPM2B_DIGEST *digest, const struct iovec data[], size_t count, bool extend);
static inline int tpm2_digest_buffer(TPMI_ALG_HASH alg, TPM2B_DIGEST *digest, const void *data, size_t len, bool extend) {
        return tpm2_digest_many(alg, digest, &IOVEC_MAKE((void*) data, len), 1, extend);
}
int tpm2_digest_many_digests(TPMI_ALG_HASH alg, TPM2B_DIGEST *digest, const TPM2B_DIGEST data[], size_t count, bool extend);
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

int tpm2_get_handle_index(Tpm2Context *c, const Tpm2Handle *handle, TPM2_HANDLE *ret_index);
int tpm2_get_handle(Tpm2Context *c, TPM2_HANDLE index, const Tpm2Handle *session, TPM2B_PUBLIC **ret_public, TPM2B_NAME **ret_name, TPM2B_NAME **ret_qname, Tpm2Handle **ret_handle);

int tpm2_get_srk_template(Tpm2Context *c, TPMI_ALG_PUBLIC alg, TPMT_PUBLIC *ret_template);
int tpm2_get_best_srk_template(Tpm2Context *c, TPMT_PUBLIC *ret_template);

int tpm2_get_srk(Tpm2Context *c, const Tpm2Handle *session, TPM2B_PUBLIC **ret_public, TPM2B_NAME **ret_name, TPM2B_NAME **ret_qname, Tpm2Handle **ret_handle);
int tpm2_get_or_create_srk(Tpm2Context *c, const Tpm2Handle *session, TPM2B_PUBLIC **ret_public, TPM2B_NAME **ret_name, TPM2B_NAME **ret_qname, Tpm2Handle **ret_handle);

int tpm2_pcr_read(Tpm2Context *c, const TPML_PCR_SELECTION *pcr_selection, Tpm2PCRValue **ret_pcr_values, size_t *ret_n_pcr_values);
int tpm2_pcr_read_missing_values(Tpm2Context *c, Tpm2PCRValue *pcr_values, size_t n_pcr_values);

int tpm2_calculate_name(const TPMT_PUBLIC *public, TPM2B_NAME *ret_name);
int tpm2_calculate_policy_auth_value(TPM2B_DIGEST *digest);
int tpm2_calculate_policy_authorize(const TPM2B_PUBLIC *public, const TPM2B_DIGEST *policy_ref, TPM2B_DIGEST *digest);
int tpm2_calculate_policy_pcr(const Tpm2PCRValue *pcr_values, size_t n_pcr_values, TPM2B_DIGEST *digest);
int tpm2_calculate_sealing_policy(const Tpm2PCRValue *pcr_values, size_t n_pcr_values, const TPM2B_PUBLIC *public, bool use_pin, TPM2B_DIGEST *digest);
int tpm2_calculate_seal(TPM2_HANDLE parent_handle, const TPM2B_PUBLIC *parent_public, const TPMA_OBJECT *attributes, const void *secret, size_t secret_size, const TPM2B_DIGEST *policy, const char *pin, void **ret_secret, size_t *ret_secret_size, void **ret_blob, size_t *ret_blob_size, void **ret_serialized_parent, size_t *ret_serialized_parent_size);

int tpm2_create_blob(const TPM2B_PUBLIC *public, const TPM2B_PRIVATE *private, const TPM2B_ENCRYPTED_SECRET *seed, void **ret_blob, size_t *ret_blob_size);
int tpm2_extract_blob(const void *blob, size_t blob_size, TPM2B_PUBLIC *ret_public, TPM2B_PRIVATE *ret_private, TPM2B_ENCRYPTED_SECRET *ret_seed);

int tpm2_seal(Tpm2Context *c, uint32_t handle_index, const TPM2B_DIGEST *policy, const char *pin, void **ret_secret, size_t *ret_secret_size, void **ret_blob, size_t *ret_blob_size, uint16_t *ret_primary_alg, void **ret_srk_buf, size_t *ret_srk_buf_size);
int tpm2_unseal(Tpm2Context *c, uint32_t hash_pcr_mask, uint16_t pcr_bank, const void *pubkey, size_t pubkey_size, uint32_t pubkey_pcr_mask, JsonVariant *signature, const char *pin, uint16_t primary_alg, const void *blob, size_t blob_size, const void *policy_hash, size_t policy_hash_size, const void *srk_buf, size_t srk_buf_size, void **ret_secret, size_t *ret_secret_size);

#if HAVE_OPENSSL
int tpm2_tpm2b_public_to_openssl_pkey(const TPM2B_PUBLIC *public, EVP_PKEY **ret);
int tpm2_tpm2b_public_from_openssl_pkey(const EVP_PKEY *pkey, TPM2B_PUBLIC *ret);
#endif

int tpm2_tpm2b_public_from_pem(const void *pem, size_t pem_size, TPM2B_PUBLIC *ret);
int tpm2_tpm2b_public_to_fingerprint(const TPM2B_PUBLIC *public, void **ret_fingerprint, size_t *ret_fingerprint_size);

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

/* Marshal/unmarshal macros */

/* Most types are defined like this */
#define DEFINE_EXTERN_MU(TYPE)                                          \
        extern TSS2_RC (*sym_Tss2_MU_##TYPE##_Marshal)(TYPE const *src, uint8_t buffer[], size_t buffer_size, size_t *offset); \
        extern TSS2_RC (*sym_Tss2_MU_##TYPE##_Unmarshal)(uint8_t const buffer[], size_t buffer_size, size_t *offset, TYPE *dest)

DEFINE_EXTERN_MU(TPM2B_DIGEST);
DEFINE_EXTERN_MU(TPM2B_ENCRYPTED_SECRET);
DEFINE_EXTERN_MU(TPM2B_NAME);
DEFINE_EXTERN_MU(TPM2B_PRIVATE);
DEFINE_EXTERN_MU(TPM2B_PUBLIC);
DEFINE_EXTERN_MU(TPM2B_SENSITIVE);
DEFINE_EXTERN_MU(TPML_PCR_SELECTION);
DEFINE_EXTERN_MU(TPMS_ECC_POINT);
DEFINE_EXTERN_MU(TPMT_HA);
DEFINE_EXTERN_MU(TPMT_PUBLIC);

/* Number types are defined like this; note that we only need the base UINT8-64 types; all others
 * (e.g. TPM2_CC) are just typedefs of UINTs. */
#define DEFINE_EXTERN_MU_UINT(SIZE)                                     \
        extern TSS2_RC (*sym_Tss2_MU_UINT##SIZE##_Marshal)(UINT##SIZE src, uint8_t buffer[], size_t buffer_size, size_t *offset); \
        extern TSS2_RC (*sym_Tss2_MU_UINT##SIZE##_Unmarshal)(uint8_t const buffer[], size_t buffer_size, size_t *offset, UINT##SIZE *dest)

DEFINE_EXTERN_MU_UINT(8);
DEFINE_EXTERN_MU_UINT(16);
DEFINE_EXTERN_MU_UINT(32);
DEFINE_EXTERN_MU_UINT(64);

extern const char* (*sym_Tss2_RC_Decode)(TSS2_RC rc);

#define _MARSHAL_MAPPING(TYPE) TYPE*: sym_Tss2_MU_##TYPE##_Marshal, const TYPE*: sym_Tss2_MU_##TYPE##_Marshal
#define _MARSHAL_MAPPING_UINT(SIZE) UINT##SIZE: sym_Tss2_MU_UINT##SIZE##_Marshal
#define _UNMARSHAL_MAPPING(TYPE) TYPE*: sym_Tss2_MU_##TYPE##_Unmarshal
#define _UNMARSHAL_MAPPING_UINT(SIZE) UINT##SIZE*: sym_Tss2_MU_UINT##SIZE##_Unmarshal

/* Generic mappings for marshal/unmarshal type->function. */
#define _MARSHAL(src)                                                   \
        _Generic(src,                                                   \
                 _MARSHAL_MAPPING(TPM2B_DIGEST),                        \
                 _MARSHAL_MAPPING(TPM2B_ENCRYPTED_SECRET),              \
                 _MARSHAL_MAPPING(TPM2B_NAME),                          \
                 _MARSHAL_MAPPING(TPM2B_PRIVATE),                       \
                 _MARSHAL_MAPPING(TPM2B_PUBLIC),                        \
                 _MARSHAL_MAPPING(TPM2B_SENSITIVE),                     \
                 _MARSHAL_MAPPING(TPML_PCR_SELECTION),                  \
                 _MARSHAL_MAPPING(TPMS_ECC_POINT),                      \
                 _MARSHAL_MAPPING(TPMT_HA),                             \
                 _MARSHAL_MAPPING(TPMT_PUBLIC),                         \
                 _MARSHAL_MAPPING_UINT(8),                              \
                 _MARSHAL_MAPPING_UINT(16),                             \
                 _MARSHAL_MAPPING_UINT(32),                             \
                 _MARSHAL_MAPPING_UINT(64))
#define _UNMARSHAL(dst)                                                 \
        _Generic(dst,                                                   \
                 _UNMARSHAL_MAPPING(TPM2B_DIGEST),                      \
                 _UNMARSHAL_MAPPING(TPM2B_ENCRYPTED_SECRET),            \
                 _UNMARSHAL_MAPPING(TPM2B_NAME),                        \
                 _UNMARSHAL_MAPPING(TPM2B_PRIVATE),                     \
                 _UNMARSHAL_MAPPING(TPM2B_PUBLIC),                      \
                 _UNMARSHAL_MAPPING(TPM2B_SENSITIVE),                   \
                 _UNMARSHAL_MAPPING(TPML_PCR_SELECTION),                \
                 _UNMARSHAL_MAPPING(TPMS_ECC_POINT),                    \
                 _UNMARSHAL_MAPPING(TPMT_HA),                           \
                 _UNMARSHAL_MAPPING(TPMT_PUBLIC),                       \
                 _UNMARSHAL_MAPPING_UINT(8),                            \
                 _UNMARSHAL_MAPPING_UINT(16),                           \
                 _UNMARSHAL_MAPPING_UINT(32),                           \
                 _UNMARSHAL_MAPPING_UINT(64))

/* Helper macro to set ret_size unless it is NULL. Note that ret_size may be a pointer to any numeric
 * type. Returns 0. */
#define _tpm2_marshalling_update_ret_size(size, ret_size, u)            \
        ({                                                              \
                size_t UNIQ_T(S, u) = (size);                           \
                typeof(__builtin_choose_expr(__builtin_types_compatible_p(typeof(ret_size), void*), &UNIQ_T(S, u), ret_size)) UNIQ_T(RET, u) = (ret_size); \
                if (UNIQ_T(RET, u))                                     \
                        *UNIQ_T(RET, u) = UNIQ_T(S, u);                 \
                0;                                                      \
        })

/* Marshal src into buf, starting at offset. The size of buf is max. If succesful and ret_size is not NULL,
 * it is set to offset plus the number of marshalled bytes. Returns 0 on success or < 0 on error. */
#define tpm2_marshal(desc, src, buf, max, offset, ret_size)             \
        (tpm2_dlopen() ?: _tpm2_marshal(desc, src, buf, max, offset, ret_size, UNIQ))
#define _tpm2_marshal(desc, src, buf, max, offset, ret_size, u)         \
        ({                                                              \
                const char *UNIQ_T(DESC, u) = (desc);                   \
                log_debug("Marshalling %s", UNIQ_T(DESC, u));           \
                __tpm2_marshal(UNIQ_T(DESC, u), src, buf, max, offset, ret_size, u); \
        })
#define __tpm2_marshal(desc, src, buf, max, offset, ret_size, u)        \
        ({                                                              \
                size_t UNIQ_T(O, u) = (offset);                         \
                TSS2_RC UNIQ_T(RC, u) = _MARSHAL(src)(src, buf, max, &UNIQ_T(O, u)); \
                UNIQ_T(RC, u) == TSS2_RC_SUCCESS                        \
                        ? _tpm2_marshalling_update_ret_size(UNIQ_T(O, u), (ret_size), CONCATENATE(u, __tpm2_marshal)) \
                        : log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), \
                                          "Failed to marshal %s: %s",   \
                                          desc, sym_Tss2_RC_Decode(UNIQ_T(RC, u))); \
        })

/* Similar to tpm2_marshal() but only calculates the size required for marshalling. ret_size cannot be
 * NULL. Returns 0 if successful or < 0 on an error. */
#define tpm2_marshal_size(desc, src, ret_size)                          \
        (tpm2_dlopen() ?: _tpm2_marshal_size(desc, src, ret_size, UNIQ))
#define _tpm2_marshal_size(desc, src, ret_size, u)                      \
        ({                                                              \
                const char *UNIQ_T(DESC, u) = (desc);                   \
                size_t UNIQ_T(S, u);                                    \
                __tpm2_marshal(UNIQ_T(DESC, u), src, NULL, TPM2_MAX_COMMAND_SIZE, 0, &UNIQ_T(S, u), CONCATENATE(u, _tpm2_marshal_size)) \
                        ? /* != 0 (failure) */                          \
                        : ({                                            \
                                        log_debug("Marshalling %s requires %zu bytes.", UNIQ_T(DESC, u), UNIQ_T(S, u)); \
                                        _tpm2_marshalling_update_ret_size(UNIQ_T(S, u), (ret_size), CONCATENATE(u, __tpm2_marshal)); \
                                });                                     \
        })

/* Similar to tpm2_marshal() but uses greedy_realloc() to append the marshalled data. The buf must be usable
 * with greedy_realloc(). The value of buf (i.e. location of allocated memory) may be modified, so it must be
 * an lvalue. Returns 0 if successful or < 0 on an error. */
#define tpm2_marshal_realloc(desc, src, buf, offset, ret_size)          \
        (tpm2_dlopen() ?: _tpm2_marshal_realloc(desc, src, buf, offset, ret_size, UNIQ))
#define _tpm2_marshal_realloc(desc, src, buf, offset, ret_size, u)      \
        ({                                                              \
                const char *UNIQ_T(DESC, u) = (desc);                   \
                typeof(src) UNIQ_T(SRC, u) = (src);                     \
                void **UNIQ_T(BUF, u) = (void**) &(buf);                \
                size_t UNIQ_T(O, u) = (offset);                         \
                size_t UNIQ_T(S, u);                                    \
                _tpm2_marshal_size(UNIQ_T(DESC, u), UNIQ_T(SRC, u), &UNIQ_T(S, u), CONCATENATE(u, _tpm2_marshal_realloc)) \
                        ? /* != 0 (failure) */                          \
                        : greedy_realloc(UNIQ_T(BUF, u), UNIQ_T(O, u) + UNIQ_T(S, u), 1) \
                        ? _tpm2_marshal(UNIQ_T(DESC, u), UNIQ_T(SRC, u), *UNIQ_T(BUF, u), UNIQ_T(O, u) + UNIQ_T(S, u), UNIQ_T(O, u), (ret_size), CONCATENATE(u, _tpm2_marshal_realloc)) \
                        : log_oom();                                    \
        })

/* Unmarshal data from buf, starting at offset, into dst. The size of buf is max. If successful and ret_size
 * is not NULL, it is set to offset plus the number of unmarshalled bytes. Returns 0 on success or < 0 on
 * error. */
#define tpm2_unmarshal(desc, dst, buf, max, offset, ret_size)           \
        (tpm2_dlopen() ?: _tpm2_unmarshal(desc, dst, buf, max, offset, ret_size, UNIQ))
#define _tpm2_unmarshal(desc, dst, buf, max, offset, ret_size, u)       \
        ({                                                              \
                const char *UNIQ_T(DESC, u) = (desc);                   \
                log_debug("Unmarshalling %s", UNIQ_T(DESC, u));         \
                size_t UNIQ_T(O, u) = (offset);                         \
                TSS2_RC UNIQ_T(RC, u) = _UNMARSHAL(dst)(buf, max, &UNIQ_T(O, u), dst); \
                UNIQ_T(RC, u) == TSS2_RC_SUCCESS     \
                        ? _tpm2_marshalling_update_ret_size(UNIQ_T(O, u), (ret_size), CONCATENATE(u, _tpm2_unmarshal)) \
                        : log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), \
                                          "Failed to unmarshal %s: %s", \
                                          desc, sym_Tss2_RC_Decode(UNIQ_T(RC, u))); \
        })

#define tpm2_unmarshal_from_file(desc, dst, f, ret_size)                \
        (tpm2_dlopen() ?: _tpm2_unmarshal_from_file(desc, dst, f, ret_size, UNIQ))
#define _tpm2_unmarshal_from_file(desc, dst, f, ret_size, u)            \
        ({                                                              \
                _cleanup_free_ char *UNIQ_T(B, u) = NULL;               \
                size_t UNIQ_T(S, u);                                    \
                int UNIQ_T(R, u) = read_full_file(f, &UNIQ_T(B, u), &UNIQ_T(S, u)); \
                if (UNIQ_T(R, u) >= 0)                                  \
                        UNIQ_T(R, u) = _tpm2_unmarshal(desc, dst, (uint8_t*) UNIQ_T(B, u), UNIQ_T(S, u), 0, ret_size, CONCATENATE(u, _tpm2_unmarshal_from_file)); \
                UNIQ_T(R, u);                                           \
        })

#else /* HAVE_TPM2 */
typedef struct {} Tpm2Context;
typedef struct {} Tpm2Handle;
typedef struct {} Tpm2PCRValue;

#define TPM2_PCR_VALUE_MAKE(i, h, v) (Tpm2PCRValue) {}
#endif /* HAVE_TPM2 */

int tpm2_list_devices(void);
int tpm2_find_device_auto(int log_level, char **ret);

int tpm2_make_pcr_json_array(uint32_t pcr_mask, JsonVariant **ret);
int tpm2_parse_pcr_json_array(JsonVariant *v, uint32_t *ret);

int tpm2_make_luks2_json(int keyslot, uint32_t hash_pcr_mask, uint16_t pcr_bank, const void *pubkey, size_t pubkey_size, uint32_t pubkey_pcr_mask, uint16_t primary_alg, const void *blob, size_t blob_size, const void *policy_hash, size_t policy_hash_size, const void *salt, size_t salt_size, const void *srk_buf, size_t srk_buf_size, TPM2Flags flags, JsonVariant **ret);
int tpm2_parse_luks2_json(JsonVariant *v, int *ret_keyslot, uint32_t *ret_hash_pcr_mask, uint16_t *ret_pcr_bank, void **ret_pubkey, size_t *ret_pubkey_size, uint32_t *ret_pubkey_pcr_mask, uint16_t *ret_primary_alg, void **ret_blob, size_t *ret_blob_size, void **ret_policy_hash, size_t *ret_policy_hash_size, void **ret_salt, size_t *ret_salt_size, void **ret_srk_buf, size_t *ret_srk_buf_size, TPM2Flags *ret_flags);

/* Default to PCR 7 only */
#define TPM2_PCR_INDEX_DEFAULT UINT32_C(7)
#define TPM2_PCR_MASK_DEFAULT INDEX_TO_MASK(uint32_t, TPM2_PCR_INDEX_DEFAULT)

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

const char *tpm2_hash_alg_to_string(uint16_t alg) _const_;
int tpm2_hash_alg_from_string(const char *alg) _pure_;

const char *tpm2_asym_alg_to_string(uint16_t alg) _const_;
int tpm2_asym_alg_from_string(const char *alg) _pure_;

char *tpm2_pcr_mask_to_string(uint32_t mask);

typedef struct {
        uint32_t search_pcr_mask;
        const char *device;
        const char *signature_path;
} systemd_tpm2_plugin_params;

typedef enum Tpm2Support {
        /* NOTE! The systemd-creds tool returns these flags 1:1 as exit status. Hence these flags are pretty
         * much ABI! Hence, be extra careful when changing/extending these definitions. */
        TPM2_SUPPORT_NONE      = 0,       /* no support */
        TPM2_SUPPORT_FIRMWARE  = 1 << 0,  /* firmware reports TPM2 was used */
        TPM2_SUPPORT_DRIVER    = 1 << 1,  /* the kernel has a driver loaded for it */
        TPM2_SUPPORT_SYSTEM    = 1 << 2,  /* we support it ourselves */
        TPM2_SUPPORT_SUBSYSTEM = 1 << 3,  /* the kernel has the tpm subsystem enabled */
        TPM2_SUPPORT_LIBRARIES = 1 << 4,  /* we can dlopen the tpm2 libraries */
        TPM2_SUPPORT_FULL      = TPM2_SUPPORT_FIRMWARE|TPM2_SUPPORT_DRIVER|TPM2_SUPPORT_SYSTEM|TPM2_SUPPORT_SUBSYSTEM|TPM2_SUPPORT_LIBRARIES,
} Tpm2Support;

Tpm2Support tpm2_support(void);

int tpm2_parse_pcr_argument(const char *arg, Tpm2PCRValue **ret_pcr_values, size_t *ret_n_pcr_values);
int tpm2_parse_pcr_argument_append(const char *arg, Tpm2PCRValue **ret_pcr_values, size_t *ret_n_pcr_values);
int tpm2_parse_pcr_argument_to_mask(const char *arg, uint32_t *mask);

int tpm2_load_pcr_signature(const char *path, JsonVariant **ret);
int tpm2_load_pcr_public_key(const char *path, void **ret_pubkey, size_t *ret_pubkey_size);

int tpm2_util_pbkdf2_hmac_sha256(const void *pass,
                    size_t passlen,
                    const void *salt,
                    size_t saltlen,
                    uint8_t res[static SHA256_DIGEST_SIZE]);

enum {
        /* Additional defines for the PCR index naming enum from "fundamental/tpm2-pcr.h" */
        _TPM2_PCR_INDEX_MAX_DEFINED = TPM2_PCRS_MAX,
        _TPM2_PCR_INDEX_INVALID     = -EINVAL,
};

int tpm2_pcr_index_from_string(const char *s) _pure_;
const char *tpm2_pcr_index_to_string(int pcr) _const_;
