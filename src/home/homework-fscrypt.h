/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "homework.h"
#include "user-record.h"

int home_prepare_fscrypt(UserRecord *h, bool already_activated, char ***pkcs11_decrypted_passwords, HomeSetup *setup);
int home_create_fscrypt(UserRecord *h, char **effective_passwords, UserRecord **ret_home);

int home_passwd_fscrypt(UserRecord *h, HomeSetup *setup, char **pkcs11_decrypted_passwords, char **effective_passwords);
