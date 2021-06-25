/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "libfido2-util.h"

struct crypt_device;

int acquire_luks2_key(
                struct crypt_device *cd,
                const char *json,
                const char *device,
                const char *pin,
                char **ret_keyslot_passphrase,
                size_t *ret_keyslot_passphrase_size);

int parse_luks2_fido2_data(
                struct crypt_device *cd,
                const char *json,
                char **ret_rp_id,
                void **ret_salt,
                size_t *ret_salt_size,
                void **ret_cid,
                size_t *ret_cid_size,
                Fido2EnrollFlags *ret_required);
