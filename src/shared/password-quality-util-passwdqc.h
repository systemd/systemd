/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

#if HAVE_PASSWDQC
#include <passwdqc.h>

extern void (*sym_passwdqc_params_reset)(passwdqc_params_t *params);
extern int (*sym_passwdqc_params_load)(passwdqc_params_t *params, char **reason, const char *pathname);
extern int (*sym_passwdqc_params_parse)(passwdqc_params_t *params, char **reason, int argc, const char *const *argv);
extern void (*sym_passwdqc_params_free)(passwdqc_params_t *params);
extern const char *(*sym_passwdqc_check)(const passwdqc_params_qc_t *params, const char *newpass, const char *oldpass, const struct passwd *pw);
extern char *(*sym_passwdqc_random)(const passwdqc_params_qc_t *params);

int dlopen_passwdqc(void);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(passwdqc_params_t*, sym_passwdqc_params_free, NULL);

int suggest_passwords(void);
int check_password_quality(const char *password, const char *old, const char *username, char **ret_error);

#endif
