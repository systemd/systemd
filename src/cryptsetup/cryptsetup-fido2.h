/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"
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

int acquire_fido2_key_auto(
                struct crypt_device *cd,
                const char *name,
                const char *friendly_name,
                const char *fido2_device,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                usec_t until,
                bool headless,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                AskPasswordFlags ask_password_flags);

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

static inline int acquire_fido2_key_auto(
                struct crypt_device *cd,
                const char *name,
                const char *friendly_name,
                const char *fido2_device,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                usec_t until,
                bool headless,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                AskPasswordFlags ask_password_flags) {

        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "FIDO2 token support not available.");
}
#endif
