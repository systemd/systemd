/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "log.h"
#include "time-util.h"

#if HAVE_P11KIT

int decrypt_pkcs11_key(
                const char *friendly_name,
                const char *pkcs11_uri,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const void *key_data,
                size_t key_data_size,
                usec_t until,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size);

#else

static inline int decrypt_pkcs11_key(
                const char *friendly_name,
                const char *pkcs11_uri,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const void *key_data,
                size_t key_data_size,
                usec_t until,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "PKCS#11 Token support not available.");
}

#endif
