/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "crypt-util.h"
#include "homework.h"
#include "user-record.h"

int home_prepare_luks(UserRecord *h, bool already_activated, const char *force_image_path, char ***pkcs11_decrypted_passwords, HomeSetup *setup, UserRecord **ret_luks_home);

int home_activate_luks(UserRecord *h, char ***pkcs11_decrypted_passwords, UserRecord **ret_home);
int home_deactivate_luks(UserRecord *h);

int home_store_header_identity_luks(UserRecord *h, HomeSetup *setup, UserRecord *old_home);

int home_create_luks(UserRecord *h, char **pkcs11_decrypted_passwords, char **effective_passwords, UserRecord **ret_home);

int home_validate_update_luks(UserRecord *h, HomeSetup *setup);

int home_resize_luks(UserRecord *h, bool already_activated, char ***pkcs11_decrypted_passwords, HomeSetup *setup, UserRecord **ret_home);

int home_passwd_luks(UserRecord *h, HomeSetup *setup, char **pkcs11_decrypted_passwords, char **effective_passwords);

int home_lock_luks(UserRecord *h);
int home_unlock_luks(UserRecord *h, char ***pkcs11_decrypted_passwords);

static inline uint64_t luks_volume_key_size_convert(struct crypt_device *cd) {
        int k;

        assert(cd);

        /* Convert the "int" to uint64_t, which we usually use for byte sizes stored on disk. */

        k = crypt_get_volume_key_size(cd);
        if (k <= 0)
                return UINT64_MAX;

        return (uint64_t) k;
}
