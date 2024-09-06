/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

#if HAVE_PASSWDQC
#include <passwdqc.h>

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(passwdqc_params_reset);
extern DLSYM_PROTOTYPE(passwdqc_params_load);
extern DLSYM_PROTOTYPE(passwdqc_params_parse);
extern DLSYM_PROTOTYPE(passwdqc_params_free);
extern DLSYM_PROTOTYPE(passwdqc_check);
extern DLSYM_PROTOTYPE(passwdqc_random);

int dlopen_passwdqc(void);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(passwdqc_params_t*, sym_passwdqc_params_free, NULL);

int suggest_passwords(void);
int check_password_quality(const char *password, const char *old, const char *username, char **ret_error);

#endif
