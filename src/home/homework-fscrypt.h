/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "homework.h"
#include "user-record.h"

int home_setup_fscrypt(UserRecord *h, HomeSetup *setup, const PasswordCache *cache);

int home_create_fscrypt(UserRecord *h, HomeSetup *setup, char **effective_passwords, UserRecord **ret_home);

int home_passwd_fscrypt(UserRecord *h, HomeSetup *setup, const PasswordCache *cache, char **effective_passwords);
