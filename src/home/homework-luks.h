/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptsetup-util.h"
#include "homework.h"
#include "user-record.h"

int home_setup_luks(UserRecord *h, HomeSetupFlags flags, const char *force_image_path, HomeSetup *setup, PasswordCache *cache, UserRecord **ret_luks_home);

int home_activate_luks(UserRecord *h, HomeSetupFlags flags, HomeSetup *setup, PasswordCache *cache, UserRecord **ret_home);
int home_deactivate_luks(UserRecord *h, HomeSetup *setup);
int home_trim_luks(UserRecord *h, HomeSetup *setup);

int home_store_header_identity_luks(UserRecord *h, HomeSetup *setup, UserRecord *old_home);

int home_create_luks(UserRecord *h, HomeSetup *setup, const PasswordCache *cache, char **effective_passwords, UserRecord **ret_home);

int home_get_state_luks(UserRecord *h, HomeSetup *setup);

int home_resize_luks(UserRecord *h, HomeSetupFlags flags, HomeSetup *setup, PasswordCache *cache, UserRecord **ret_home);

int home_passwd_luks(UserRecord *h, HomeSetupFlags flags, HomeSetup *setup, const PasswordCache *cache, char **effective_passwords);

int home_lock_luks(UserRecord *h, HomeSetup *setup);
int home_unlock_luks(UserRecord *h, HomeSetup *setup, const PasswordCache *cache);

int home_auto_shrink_luks(UserRecord *h, HomeSetup *setup, PasswordCache *cache);

static inline uint64_t luks_volume_key_size_convert(struct crypt_device *cd) {
        int k;

        assert(cd);

        /* Convert the "int" to uint64_t, which we usually use for byte sizes stored on disk. */

        k = sym_crypt_get_volume_key_size(cd);
        if (k <= 0)
                return UINT64_MAX;

        return (uint64_t) k;
}

int run_fitrim(int root_fd);
int run_fallocate(int backing_fd, const struct stat *st);
int run_fallocate_by_path(const char *backing_path);
int run_mark_dirty(int fd, bool b);
int run_mark_dirty_by_path(const char *path, bool b);

int wait_for_block_device_gone(HomeSetup *setup, usec_t timeout_usec);
