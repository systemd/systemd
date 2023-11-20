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
bool credential_glob_valid(const char *s);

/* Where creds have been passed to the local execution context */
int get_credentials_dir(const char **ret);
int get_encrypted_credentials_dir(const char **ret);

/* Where creds have been passed to the system */
#define SYSTEM_CREDENTIALS_DIRECTORY "/run/credentials/@system"
#define ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY "/run/credentials/@encrypted"

int read_credential(const char *name, void **ret, size_t *ret_size); /* use in services! */
int read_credential_with_decryption(const char *name, void **ret, size_t *ret_size); /* use in generators + pid1! */

int read_credential_strings_many_internal(const char *first_name, char **first_value, ...);

#define read_credential_strings_many(first_name, first_value, ...) \
        read_credential_strings_many_internal(first_name, first_value, __VA_ARGS__, NULL)

int read_credential_bool(const char *name);

typedef enum CredentialSecretFlags {
        CREDENTIAL_SECRET_GENERATE             = 1 << 0,
        CREDENTIAL_SECRET_WARN_NOT_ENCRYPTED   = 1 << 1,
        CREDENTIAL_SECRET_FAIL_ON_TEMPORARY_FS = 1 << 2,
} CredentialSecretFlags;

int get_credential_host_secret(CredentialSecretFlags flags, struct iovec *ret);

int get_credential_user_password(const char *username, char **ret_password, bool *ret_is_hashed);

/* The four modes we support: keyed only by on-disk key, only by TPM2 HMAC key, and by the combination of
 * both, as well as one with a fixed zero length key if TPM2 is missing (the latter of course provides no
 * authenticity or confidentiality, but is still useful for integrity protection, and makes things simpler
 * for us to handle). */
#define CRED_AES256_GCM_BY_HOST               SD_ID128_MAKE(5a,1c,6a,86,df,9d,40,96,b1,d5,a6,5e,08,62,f1,9a)
#define CRED_AES256_GCM_BY_TPM2_HMAC          SD_ID128_MAKE(0c,7c,c0,7b,11,76,45,91,9c,4b,0b,ea,08,bc,20,fe)
#define CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK  SD_ID128_MAKE(fa,f7,eb,93,41,e3,41,2c,a1,a4,36,f9,5a,29,36,2f)
#define CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC SD_ID128_MAKE(93,a8,94,09,48,74,44,90,90,ca,f2,fc,93,ca,b5,53)
#define CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK           \
                                              SD_ID128_MAKE(af,49,50,a8,49,13,4e,b1,a7,38,46,30,4f,f3,0c,05)
#define CRED_AES256_GCM_BY_NULL               SD_ID128_MAKE(05,84,69,da,f6,f5,43,24,80,05,49,da,0f,8e,a2,fb)

/* Two special IDs to pick a general automatic mode (i.e. tpm2+host if TPM2 exists, only host otherwise) or
 * an initrd-specific automatic mode (i.e. tpm2 if firmware can do it, otherwise fixed zero-length key, and
 * never involve host keys). These IDs will never be stored on disk, but are useful only internally while
 * figuring out what precisely to write to disk. To mark that these aren't a "real" type, we'll prefix them
 * with an underscore. */
#define _CRED_AUTO                            SD_ID128_MAKE(a2,19,cb,07,85,b2,4c,04,b1,6d,18,ca,b9,d2,ee,01)
#define _CRED_AUTO_INITRD                     SD_ID128_MAKE(02,dc,8e,de,3a,02,43,ab,a9,ec,54,9c,05,e6,a0,71)

int encrypt_credential_and_warn(sd_id128_t with_key, const char *name, usec_t timestamp, usec_t not_after, const char *tpm2_device, uint32_t tpm2_hash_pcr_mask, const char *tpm2_pubkey_path, uint32_t tpm2_pubkey_pcr_mask, const struct iovec *input, struct iovec *ret);
int decrypt_credential_and_warn(const char *validate_name, usec_t validate_timestamp, const char *tpm2_device, const char *tpm2_signature_path, const struct iovec *input, struct iovec *ret);
