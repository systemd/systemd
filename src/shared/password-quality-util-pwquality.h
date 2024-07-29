/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

#if HAVE_PWQUALITY
/* pwquality.h uses size_t but doesn't include sys/types.h on its own */
#include <sys/types.h>
#include <pwquality.h>

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(pwquality_check);
extern DLSYM_PROTOTYPE(pwquality_default_settings);
extern DLSYM_PROTOTYPE(pwquality_free_settings);
extern DLSYM_PROTOTYPE(pwquality_generate);
extern DLSYM_PROTOTYPE(pwquality_get_str_value);
extern DLSYM_PROTOTYPE(pwquality_read_config);
extern DLSYM_PROTOTYPE(pwquality_set_int_value);
extern DLSYM_PROTOTYPE(pwquality_strerror);

int dlopen_pwquality(void);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(pwquality_settings_t*, sym_pwquality_free_settings, NULL);

int suggest_passwords(void);
int check_password_quality(const char *password, const char *old, const char *username, char **ret_error);

#endif
