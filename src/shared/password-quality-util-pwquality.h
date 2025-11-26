/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#if HAVE_PWQUALITY
int suggest_passwords(void);
int check_password_quality(const char *password, const char *old, const char *username, char **ret_error);
#endif

int dlopen_pwquality(void);
