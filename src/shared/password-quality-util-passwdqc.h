/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dlopen-note.h"
#include "forward.h"

#if HAVE_PASSWDQC
int suggest_passwords(void);
int check_password_quality(const char *password, const char *old, const char *username, char **ret_error);
#endif

int dlopen_passwdqc(int log_level) _dlopen_loader_;
