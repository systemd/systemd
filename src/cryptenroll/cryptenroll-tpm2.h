/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"
#include "log.h"
#include "tpm2-util.h"

#if HAVE_TPM2
int load_volume_key_tpm2(struct crypt_device *cd, const char *cd_node, const char *device, void *ret_vk, size_t *ret_vks);
int enroll_tpm2(struct crypt_device *cd, const struct iovec *volume_key, const char *device, uint32_t seal_key_handle, const char *device_key, Tpm2PCRValue *hash_pcr_values, size_t n_hash_pcr_values, const char *pubkey_path, bool load_pcr_pubkey, uint32_t pubkey_pcr_mask, const char *signature_path, bool use_pin, const char *pcrlock_path, int *ret_slot_to_wipe);
#else
static inline int load_volume_key_tpm2(struct crypt_device *cd, const char *cd_node, const char *device, void *ret_vk, size_t *ret_vks) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "TPM2 unlocking not supported.");
}

static inline int enroll_tpm2(struct crypt_device *cd, const struct iovec *volume_key, const char *device, uint32_t seal_key_handle, const char *device_key, Tpm2PCRValue *hash_pcr_values, size_t n_hash_pcr_values, const char *pubkey_path, bool load_pcr_pubkey, uint32_t pubkey_pcr_mask, const char *signature_path, bool use_pin, const char *pcrlock_path, int *ret_slot_to_wipe) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "TPM2 key enrollment not supported.");
}
#endif
