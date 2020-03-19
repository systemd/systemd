/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "homework.h"
#include "user-record.h"

int home_prepare_directory(UserRecord *h, bool already_activated, HomeSetup *setup);
int home_activate_directory(UserRecord *h, char ***pkcs11_decrypted_passwords, UserRecord **ret_home);
int home_create_directory_or_subvolume(UserRecord *h, UserRecord **ret_home);
int home_resize_directory(UserRecord *h, bool already_activated, char ***pkcs11_decrypted_passwords, HomeSetup *setup, UserRecord **ret_home);
