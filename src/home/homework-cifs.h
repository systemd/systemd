/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "homework.h"
#include "user-record.h"

int home_setup_cifs(UserRecord *h, HomeSetupFlags flags, HomeSetup *setup);

int home_activate_cifs(UserRecord *h, HomeSetupFlags flags, HomeSetup *setup, PasswordCache *cache, UserRecord **ret_home);

int home_create_cifs(UserRecord *h, HomeSetup *setup, UserRecord **ret_home);
