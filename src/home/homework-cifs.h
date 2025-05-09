/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct PasswordCache PasswordCache;
typedef struct HomeSetup HomeSetup;
typedef enum HomeSetupFlags HomeSetupFlags;

int home_setup_cifs(UserRecord *h, HomeSetupFlags flags, HomeSetup *setup);

int home_activate_cifs(UserRecord *h, HomeSetupFlags flags, HomeSetup *setup, PasswordCache *cache, UserRecord **ret_home);

int home_create_cifs(UserRecord *h, HomeSetup *setup, UserRecord **ret_home);
