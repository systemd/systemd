/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "homework.h"
#include "user-record.h"

int home_setup_directory(UserRecord *h, HomeSetup *setup);
int home_activate_directory(UserRecord *h, HomeSetupFlags flags, HomeSetup *setup, PasswordCache *cache, UserRecord **ret_home);
int home_create_directory_or_subvolume(UserRecord *h, HomeSetup *setup, UserRecord **ret_home);
int home_resize_directory(UserRecord *h, HomeSetupFlags flags, HomeSetup *setup, PasswordCache *cache, UserRecord **ret_home);
