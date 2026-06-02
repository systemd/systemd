/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/fscrypt.h>
#include <sys/uio.h>

#include "homework-forward.h"

int home_setup_fscrypt(UserRecord *h, HomeSetup *setup, const PasswordCache *cache);

int home_create_fscrypt(UserRecord *h, HomeSetup *setup, char **effective_passwords, UserRecord **ret_home);

int home_passwd_fscrypt(UserRecord *h, HomeSetup *setup, const PasswordCache *cache, char **effective_passwords);

int home_flush_keyring_fscrypt(UserRecord *h);

int compute_fscrypt_key_identifier_v2(const struct iovec *key, uint8_t ret_identifier[static FSCRYPT_KEY_IDENTIFIER_SIZE]);
