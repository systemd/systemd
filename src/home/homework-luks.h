/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptsetup-util.h"
#include "homework.h"
#include "user-record.h"

int home_prepare_luks(UserRecord *h, bool already_activated, const char *force_image_path, PasswordCache *cache, HomeSetup *setup, UserRecord **ret_luks_home);

int home_activate_luks(UserRecord *h, PasswordCache *cache, UserRecord **ret_home);
int home_deactivate_luks(UserRecord *h);
int home_trim_luks(UserRecord *h);

int home_store_header_identity_luks(UserRecord *h, HomeSetup *setup, UserRecord *old_home);

int home_create_luks(UserRecord *h, PasswordCache *cache, char **effective_passwords, UserRecord **ret_home);

int home_validate_update_luks(UserRecord *h, HomeSetup *setup);

int home_resize_luks(UserRecord *h, bool already_activated, PasswordCache *cache, HomeSetup *setup, UserRecord **ret_home);

int home_passwd_luks(UserRecord *h, HomeSetup *setup, PasswordCache *cache, char **effective_passwords);

int home_lock_luks(UserRecord *h);
int home_unlock_luks(UserRecord *h, PasswordCache *cache);

static inline uint64_t luks_volume_key_size_convert(struct crypt_device *cd) {
        int k;

        assert(cd);

        /* Convert the "int" to uint64_t, which we usually use for byte sizes stored on disk. */

        k = crypt_get_volume_key_size(cd);
        if (k <= 0)
                return UINT64_MAX;

        return (uint64_t) k;
}

int run_fitrim(int root_fd);
int run_fitrim_by_path(const char *root_path);
int run_fallocate(int backing_fd, const struct stat *st);
int run_fallocate_by_path(const char *backing_path);
int run_mark_dirty(int fd, bool b);
int run_mark_dirty_by_path(const char *path, bool b);
