/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "string-util.h"

typedef int (*SpecifierCallback)(char specifier, const void *data, const void *userdata, char **ret);

typedef struct Specifier {
        const char specifier;
        const SpecifierCallback lookup;
        const void *data;
} Specifier;

int specifier_printf(const char *text, const Specifier table[], const void *userdata, char **ret);

int specifier_string(char specifier, const void *data, const void *userdata, char **ret);

int specifier_machine_id(char specifier, const void *data, const void *userdata, char **ret);
int specifier_boot_id(char specifier, const void *data, const void *userdata, char **ret);
int specifier_host_name(char specifier, const void *data, const void *userdata, char **ret);
int specifier_short_host_name(char specifier, const void *data, const void *userdata, char **ret);
int specifier_kernel_release(char specifier, const void *data, const void *userdata, char **ret);
int specifier_architecture(char specifier, const void *data, const void *userdata, char **ret);
int specifier_os_id(char specifier, const void *data, const void *userdata, char **ret);
int specifier_os_version_id(char specifier, const void *data, const void *userdata, char **ret);
int specifier_os_build_id(char specifier, const void *data, const void *userdata, char **ret);
int specifier_os_variant_id(char specifier, const void *data, const void *userdata, char **ret);

int specifier_group_name(char specifier, const void *data, const void *userdata, char **ret);
int specifier_group_id(char specifier, const void *data, const void *userdata, char **ret);
int specifier_user_name(char specifier, const void *data, const void *userdata, char **ret);
int specifier_user_id(char specifier, const void *data, const void *userdata, char **ret);
int specifier_user_home(char specifier, const void *data, const void *userdata, char **ret);
int specifier_user_shell(char specifier, const void *data, const void *userdata, char **ret);

int specifier_tmp_dir(char specifier, const void *data, const void *userdata, char **ret);
int specifier_var_tmp_dir(char specifier, const void *data, const void *userdata, char **ret);

/* Typically, in places where one of the above specifier is to be resolved the other similar ones are to be
 * resolved, too. Hence let's define common macros for the relevant array entries. */
#define COMMON_SYSTEM_SPECIFIERS                  \
        { 'm', specifier_machine_id,      NULL }, \
        { 'b', specifier_boot_id,         NULL }, \
        { 'H', specifier_host_name,       NULL }, \
        { 'l', specifier_short_host_name, NULL }, \
        { 'v', specifier_kernel_release,  NULL }, \
        { 'a', specifier_architecture,    NULL }, \
        { 'o', specifier_os_id,           NULL }, \
        { 'w', specifier_os_version_id,   NULL }, \
        { 'B', specifier_os_build_id,     NULL }, \
        { 'W', specifier_os_variant_id,   NULL }

#define COMMON_CREDS_SPECIFIERS                   \
        { 'g', specifier_group_name,      NULL }, \
        { 'G', specifier_group_id,        NULL }, \
        { 'U', specifier_user_id,         NULL }, \
        { 'u', specifier_user_name,       NULL }

#define COMMON_TMP_SPECIFIERS                     \
        { 'T', specifier_tmp_dir,         NULL }, \
        { 'V', specifier_var_tmp_dir,     NULL }

static inline char* specifier_escape(const char *string) {
        return strreplace(string, "%", "%%");
}

int specifier_escape_strv(char **l, char ***ret);
