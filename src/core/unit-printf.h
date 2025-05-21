/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int unit_name_printf(const Unit *u, const char* text, char **ret);
int unit_full_printf_full(const Unit *u, const char *text, size_t max_length, char **ret);
int unit_full_printf(const Unit *u, const char *text, char **ret);
int unit_path_printf(const Unit *u, const char *text, char **ret);
int unit_fd_printf(const Unit *u, const char *text, char **ret);
int unit_cred_printf(const Unit *u, const char *text, char **ret);
int unit_env_printf(const Unit *u, const char *text, char **ret);
