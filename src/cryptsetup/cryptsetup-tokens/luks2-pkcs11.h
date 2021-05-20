/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

struct crypt_device;

int acquire_luks2_key(
                struct crypt_device *cd,
                const char *json,
                void *usrptr,
                const char *pin,
                char **password,
                size_t *password_size);

int parse_luks2_pkcs11_data(
                struct crypt_device *cd,
                const char *json,
                char **ret_uri,
                void **ret_encrypted_key,
                size_t *ret_encrypted_key_size);
