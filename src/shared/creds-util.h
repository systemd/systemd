/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "sd-id128.h"

#include "fd-util.h"
#include "time-util.h"

#define CREDENTIAL_NAME_MAX FDNAME_MAX

/* Put a size limit on the individual credential */
#define CREDENTIAL_SIZE_MAX (1024U*1024U)

/* Refuse to store more than 1M per service, after all this is unswappable memory. Note that for now we put
 * this to the same limit as the per-credential limit, i.e. if the user has n > 1 credentials instead of 1 it
 * won't get them more space. */
#define CREDENTIALS_TOTAL_SIZE_MAX CREDENTIAL_SIZE_MAX

/* Put a size limit on encrypted credentials (which is the same as the unencrypted size plus a spacious 128K of extra
 * space for headers, IVs, exported TPM2 key material and so on. */
#define CREDENTIAL_ENCRYPTED_SIZE_MAX (CREDENTIAL_SIZE_MAX + 128U*1024U)

bool credential_name_valid(const char *s);

int get_credentials_dir(const char **ret);

int read_credential(const char *name, void **ret, size_t *ret_size);

typedef enum CredentialSecretFlags {
        CREDENTIAL_SECRET_GENERATE             = 1 << 0,
        CREDENTIAL_SECRET_WARN_NOT_ENCRYPTED   = 1 << 1,
        CREDENTIAL_SECRET_FAIL_ON_TEMPORARY_FS = 1 << 2,
} CredentialSecretFlags;

int get_credential_host_secret(CredentialSecretFlags flags, void **ret, size_t *ret_size);

/* The three modes we support: keyed only by on-disk key, only by TPM2 HMAC key, and by the combination of both */
#define CRED_AES256_GCM_BY_HOST               SD_ID128_MAKE(5a,1c,6a,86,df,9d,40,96,b1,d5,a6,5e,08,62,f1,9a)
#define CRED_AES256_GCM_BY_TPM2_HMAC          SD_ID128_MAKE(0c,7c,c0,7b,11,76,45,91,9c,4b,0b,ea,08,bc,20,fe)
#define CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC SD_ID128_MAKE(93,a8,94,09,48,74,44,90,90,ca,f2,fc,93,ca,b5,53)

/* Special ID to pick automatic mode (i.e. tpm2+host if TPM2 exists, only host otherwise). This ID will never
 * be stored on disk, but is useful only internally while figuring out what precisely to write to disk. To
 * mark that this isn't a "real" type, we'll prefix it with an underscore. */
#define _CRED_AUTO                            SD_ID128_MAKE(a2,19,cb,07,85,b2,4c,04,b1,6d,18,ca,b9,d2,ee,01)

int encrypt_credential_and_warn(sd_id128_t with_key, const char *name, usec_t timestamp, usec_t not_after, const char *tpm2_device, uint32_t tpm2_pcr_mask, const void *input, size_t input_size, void **ret, size_t *ret_size);
int decrypt_credential_and_warn(const char *validate_name, usec_t validate_timestamp, const char *tpm2_device, const void *input, size_t input_size, void **ret, size_t *ret_size);
