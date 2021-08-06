/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

#if HAVE_PWQUALITY
/* pwquality.h uses size_t but doesn't include sys/types.h on its own */
#include <sys/types.h>
#include <pwquality.h>

extern int (*sym_pwquality_check)(pwquality_settings_t *pwq, const char *password, const char *oldpassword, const char *user, void **auxerror);
extern pwquality_settings_t *(*sym_pwquality_default_settings)(void);
extern void (*sym_pwquality_free_settings)(pwquality_settings_t *pwq);
extern int (*sym_pwquality_generate)(pwquality_settings_t *pwq, int entropy_bits, char **password);
extern int (*sym_pwquality_get_str_value)(pwquality_settings_t *pwq, int setting, const char **value);
extern int (*sym_pwquality_read_config)(pwquality_settings_t *pwq, const char *cfgfile, void **auxerror);
extern int (*sym_pwquality_set_int_value)(pwquality_settings_t *pwq, int setting, int value);
extern const char* (*sym_pwquality_strerror)(char *buf, size_t len, int errcode, void *auxerror);

int dlopen_pwquality(void);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(pwquality_settings_t*, sym_pwquality_free_settings, NULL);

int suggest_passwords(void);
int check_password_quality(const char *password, const char *old, const char *username, char **ret_error);

#endif
