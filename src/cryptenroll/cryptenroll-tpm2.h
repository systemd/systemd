/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"
#include "log.h"
#include "tpm2-util.h"
#include "varlink.h"

#if HAVE_TPM2

int enroll_tpm2(struct crypt_device *cd, const void *volume_key, size_t volume_key_size, const char *device, uint32_t seal_key_handle, const char *device_key, Tpm2PCRValue *hash_pcrs, size_t n_hash_pcrs, const char *pubkey_path, uint32_t pubkey_pcr_mask, const char *signature_path, bool use_pin, const char *pcrlock_path);
int vl_method_enroll_tpm2(Varlink *link, JsonVariant *params, VarlinkMethodFlags flags, void *userdata);

#else

static inline int enroll_tpm2(struct crypt_device *cd, const void *volume_key, size_t volume_key_size, const char *device, uint32_t seal_key_handle, const char *device_key, Tpm2PCRValue *hash_pcrs, size_t n_hash_pcrs, const char *pubkey_path, uint32_t pubkey_pcr_mask, const char *signature_path, bool use_pin, const char *pcrlock_path) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "TPM2 key enrollment not supported.");
}

static inline int vl_method_enroll_tpm2(Varlink *link, JsonVariant *params, VarlinkMethodFlags flags, void *userdata) {
        return varlink_errorb(
                        link,
                        VARLINK_ERROR_METHOD_NOT_IMPLEMENTED,
                        JSON_BUILD_OBJECT(JSON_BUILD_PAIR("method", "io.systemd.CryptEnroll.EnrollTPM2")));
}

#endif
