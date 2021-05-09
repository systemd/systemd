/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "creds-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "unit.h"

int unit_name_printf(const Unit *u, const char* text, char **ret);
int unit_full_printf_full(const Unit *u, const char *text, size_t max_length, char **ret);
static inline int unit_full_printf(const Unit *u, const char *text, char **ret) {
        return unit_full_printf_full(u, text, LONG_LINE_MAX, ret);
}
static inline int unit_path_printf(const Unit *u, const char *text, char **ret) {
        return unit_full_printf_full(u, text, PATH_MAX-1, ret);
}
static inline int unit_fd_printf(const Unit *u, const char *text, char **ret) {
        return unit_full_printf_full(u, text, FDNAME_MAX, ret);
}
static inline int unit_cred_printf(const Unit *u, const char *text, char **ret) {
        return unit_full_printf_full(u, text, CREDENTIAL_NAME_MAX, ret);
}
static inline int unit_env_printf(const Unit *u, const char *text, char **ret) {
        return unit_full_printf_full(u, text, sc_arg_max(), ret);
}
