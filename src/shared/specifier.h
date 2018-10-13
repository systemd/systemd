/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "string-util.h"

typedef int (*SpecifierCallback)(char specifier, void *data, void *userdata, char **ret);

typedef struct Specifier {
        const char specifier;
        const SpecifierCallback lookup;
        void *data;
} Specifier;

int specifier_printf(const char *text, const Specifier table[], void *userdata, char **ret);

int specifier_string(char specifier, void *data, void *userdata, char **ret);

int specifier_machine_id(char specifier, void *data, void *userdata, char **ret);
int specifier_boot_id(char specifier, void *data, void *userdata, char **ret);
int specifier_host_name(char specifier, void *data, void *userdata, char **ret);
int specifier_kernel_release(char specifier, void *data, void *userdata, char **ret);

int specifier_group_name(char specifier, void *data, void *userdata, char **ret);
int specifier_group_id(char specifier, void *data, void *userdata, char **ret);
int specifier_user_name(char specifier, void *data, void *userdata, char **ret);
int specifier_user_id(char specifier, void *data, void *userdata, char **ret);
int specifier_user_home(char specifier, void *data, void *userdata, char **ret);
int specifier_user_shell(char specifier, void *data, void *userdata, char **ret);

int specifier_tmp_dir(char specifier, void *data, void *userdata, char **ret);
int specifier_var_tmp_dir(char specifier, void *data, void *userdata, char **ret);

static inline char* specifier_escape(const char *string) {
        return strreplace(string, "%", "%%");
}

int specifier_escape_strv(char **l, char ***ret);
