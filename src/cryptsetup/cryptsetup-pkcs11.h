/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int decrypt_pkcs11_key(
                const char *volume_name,
                const char *friendly_name,
                const char *pkcs11_uri,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const struct iovec *key_data,
                usec_t until,
                AskPasswordFlags askpw_flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size);

int find_pkcs11_auto_data(
                struct crypt_device *cd,
                char **ret_uri,
                void **ret_encrypted_key,
                size_t *ret_encrypted_key_size,
                int *ret_keyslot);
