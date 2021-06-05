/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"
#include "macro.h"

#if HAVE_TPM2

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>

extern TSS2_RC (*sym_Esys_Create)(ESYS_CONTEXT *esysContext, ESYS_TR parentHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_SENSITIVE_CREATE *inSensitive, const TPM2B_PUBLIC *inPublic, const TPM2B_DATA *outsideInfo, const TPML_PCR_SELECTION *creationPCR, TPM2B_PRIVATE **outPrivate, TPM2B_PUBLIC **outPublic, TPM2B_CREATION_DATA **creationData, TPM2B_DIGEST **creationHash, TPMT_TK_CREATION **creationTicket);
extern TSS2_RC (*sym_Esys_CreatePrimary)(ESYS_CONTEXT *esysContext, ESYS_TR primaryHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_SENSITIVE_CREATE *inSensitive, const TPM2B_PUBLIC *inPublic, const TPM2B_DATA *outsideInfo, const TPML_PCR_SELECTION *creationPCR, ESYS_TR *objectHandle, TPM2B_PUBLIC **outPublic, TPM2B_CREATION_DATA **creationData, TPM2B_DIGEST **creationHash, TPMT_TK_CREATION **creationTicket);
extern void (*sym_Esys_Finalize)(ESYS_CONTEXT **context);
extern TSS2_RC (*sym_Esys_FlushContext)(ESYS_CONTEXT *esysContext, ESYS_TR flushHandle);
extern void (*sym_Esys_Free)(void *ptr);
extern TSS2_RC (*sym_Esys_GetRandom)(ESYS_CONTEXT *esysContext, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, UINT16 bytesRequested, TPM2B_DIGEST **randomBytes);
extern TSS2_RC (*sym_Esys_Initialize)(ESYS_CONTEXT **esys_context,  TSS2_TCTI_CONTEXT *tcti, TSS2_ABI_VERSION *abiVersion);
extern TSS2_RC (*sym_Esys_Load)(ESYS_CONTEXT *esysContext, ESYS_TR parentHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_PRIVATE *inPrivate, const TPM2B_PUBLIC *inPublic, ESYS_TR *objectHandle);
extern TSS2_RC (*sym_Esys_PolicyGetDigest)(ESYS_CONTEXT *esysContext, ESYS_TR policySession, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, TPM2B_DIGEST **policyDigest);
extern TSS2_RC (*sym_Esys_PolicyPCR)(ESYS_CONTEXT *esysContext, ESYS_TR policySession, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_DIGEST *pcrDigest, const TPML_PCR_SELECTION *pcrs);
extern TSS2_RC (*sym_Esys_StartAuthSession)(ESYS_CONTEXT *esysContext, ESYS_TR tpmKey, ESYS_TR bind, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_NONCE *nonceCaller, TPM2_SE sessionType, const TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH authHash, ESYS_TR *sessionHandle);
extern TSS2_RC (*sym_Esys_Startup)(ESYS_CONTEXT *esysContext, TPM2_SU startupType);
extern TSS2_RC (*sym_Esys_Unseal)(ESYS_CONTEXT *esysContext, ESYS_TR itemHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, TPM2B_SENSITIVE_DATA **outData);

extern const char* (*sym_Tss2_RC_Decode)(TSS2_RC rc);

extern TSS2_RC (*sym_Tss2_MU_TPM2B_PRIVATE_Marshal)(TPM2B_PRIVATE const *src, uint8_t buffer[], size_t buffer_size, size_t *offset);
extern TSS2_RC (*sym_Tss2_MU_TPM2B_PRIVATE_Unmarshal)(uint8_t const buffer[], size_t buffer_size, size_t *offset, TPM2B_PRIVATE  *dest);
extern TSS2_RC (*sym_Tss2_MU_TPM2B_PUBLIC_Marshal)(TPM2B_PUBLIC const *src, uint8_t buffer[], size_t buffer_size, size_t *offset);
extern TSS2_RC (*sym_Tss2_MU_TPM2B_PUBLIC_Unmarshal)(uint8_t const buffer[], size_t buffer_size, size_t *offset, TPM2B_PUBLIC *dest);

int dlopen_tpm2(void);

int tpm2_seal(const char *device, uint32_t pcr_mask, void **ret_secret, size_t *ret_secret_size, void **ret_blob, size_t *ret_blob_size, void **ret_pcr_hash, size_t *ret_pcr_hash_size);
int tpm2_unseal(const char *device, uint32_t pcr_mask, const void *blob, size_t blob_size, const void *pcr_hash, size_t pcr_hash_size, void **ret_secret, size_t *ret_secret_size);

#endif

int tpm2_list_devices(void);
int tpm2_find_device_auto(int log_level, char **ret);

int tpm2_parse_pcrs(const char *s, uint32_t *ret);

int tpm2_make_luks2_json(int keyslot, uint32_t pcr_mask, const void *blob, size_t blob_size, const void *policy_hash, size_t policy_hash_size, JsonVariant **ret);

#define TPM2_PCRS_MAX 24

/* Default to PCR 7 only */
#define TPM2_PCR_MASK_DEFAULT (UINT32_C(1) << 7)
