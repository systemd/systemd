/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"
#include "libsss-util.h"
#include "libfido2-util.h"
#include "log.h"
#include "time-util.h"

#if HAVE_LIBFIDO2

int acquire_fido2_key(
                const char *volume_name,
                const char *friendly_name,
                const char *device,
                const char *rp_id,
                const void *cid,
                size_t cid_size,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const void *key_data,
                size_t key_data_size,
                usec_t until,
                bool headless,
                Fido2EnrollFlags required,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                AskPasswordFlags ask_password_flags);

int find_fido2_auto_data(
                Factor *factor,
                Factor *factor_list,
                uint16_t factor_number,
                struct crypt_device *cd,
                char **ret_rp_id,
                void **ret_salt,
                size_t *ret_salt_size,
                void **ret_cid,
                size_t *ret_cid_size,
                unsigned char **ret_encrypted_share,
                int *ret_keyslot,
                Fido2EnrollFlags *ret_required);

#else

static inline int acquire_fido2_key(
                const char *volume_name,
                const char *friendly_name,
                const char *device,
                const char *rp_id,
                const void *cid,
                size_t cid_size,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const void *key_data,
                size_t key_data_size,
                usec_t until,
                bool headless,
                Fido2EnrollFlags required,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                AskPasswordFlags ask_password_flags) {

        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "FIDO2 token support not available.");
}

static inline int find_fido2_auto_data(
                Factor *factor,
                Factor *factor_list,
                uint16_t factor_number,
                struct crypt_device *cd,
                char **ret_rp_id,
                void **ret_salt,
                size_t *ret_salt_size,
                void **ret_cid,
                size_t *ret_cid_size,
                unsigned char **ret_encrypted_share,
                int *ret_keyslot,
                Fido2EnrollFlags *ret_required) {

        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "FIDO2 token support not available.");
}
#endif
