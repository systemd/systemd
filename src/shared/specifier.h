/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "string-util.h"

typedef int (*SpecifierCallback)(char specifier, const void *data, const char *root, const void *userdata, char **ret);

typedef struct Specifier {
        const char specifier;
        const SpecifierCallback lookup;
        const void *data;
} Specifier;

int specifier_printf(const char *text, size_t max_length, const Specifier table[], const char *root, const void *userdata, char **ret);

int specifier_string(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_real_path(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_real_directory(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_id128(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_uuid(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_uint64(char specifier, const void *data, const char *root, const void *userdata, char **ret);

int specifier_machine_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_boot_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_hostname(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_short_hostname(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_pretty_hostname(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_kernel_release(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_architecture(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_version_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_build_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_variant_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_image_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_image_version(char specifier, const void *data, const char *root, const void *userdata, char **ret);

int specifier_group_name(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_group_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_user_name(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_user_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_user_home(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_user_shell(char specifier, const void *data, const char *root, const void *userdata, char **ret);

int specifier_tmp_dir(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_var_tmp_dir(char specifier, const void *data, const char *root, const void *userdata, char **ret);

/* Typically, in places where one of the above specifier is to be resolved the other similar ones are to be
 * resolved, too. Hence let's define common macros for the relevant array entries.
 *
 * COMMON_SYSTEM_SPECIFIERS:
 * %a: the native userspace architecture
 * %A: the OS image version, according to /etc/os-release
 * %b: the boot ID of the running system
 * %B: the OS build ID, according to /etc/os-release
 * %H: the hostname of the running system
 * %l: the short hostname of the running system
 * %q: the 'pretty' hostname as per /etc/machine-info
 * %m: the machine ID of the running system
 * %M: the OS image ID, according to /etc/os-release
 * %o: the OS ID according to /etc/os-release
 * %v: the kernel version
 * %w: the OS version ID, according to /etc/os-release
 * %W: the OS variant ID, according to /etc/os-release
 *
 * COMMON_CREDS_SPECIFIERS:
 * %g: the groupname of the running user
 * %G: the GID of the running user
 * %u: the username of the running user
 * %U: the UID of the running user
 *
 * COMMON_TMP_SPECIFIERS:
 * %T: the temporary directory (e.g. /tmp, or $TMPDIR, $TEMP, $TMP)
 * %V: the temporary directory for large, persistent stuff (e.g. /var/tmp, or $TMPDIR, $TEMP, $TMP)
 */

#define COMMON_SYSTEM_SPECIFIERS                   \
        { 'a', specifier_architecture,     NULL }, \
        { 'A', specifier_os_image_version, NULL }, \
        { 'b', specifier_boot_id,          NULL }, \
        { 'B', specifier_os_build_id,      NULL }, \
        { 'H', specifier_hostname,         NULL }, \
        { 'l', specifier_short_hostname,   NULL }, \
        { 'q', specifier_pretty_hostname,  NULL }, \
        { 'm', specifier_machine_id,       NULL }, \
        { 'M', specifier_os_image_id,      NULL }, \
        { 'o', specifier_os_id,            NULL }, \
        { 'v', specifier_kernel_release,   NULL }, \
        { 'w', specifier_os_version_id,    NULL }, \
        { 'W', specifier_os_variant_id,    NULL }

#define COMMON_CREDS_SPECIFIERS(scope)                           \
        { 'g', specifier_group_name,       INT_TO_PTR(scope) },  \
        { 'G', specifier_group_id,         INT_TO_PTR(scope) },  \
        { 'u', specifier_user_name,        INT_TO_PTR(scope) },  \
        { 'U', specifier_user_id,          INT_TO_PTR(scope) }

#define COMMON_TMP_SPECIFIERS                      \
        { 'T', specifier_tmp_dir,          NULL }, \
        { 'V', specifier_var_tmp_dir,      NULL }

static inline char* specifier_escape(const char *string) {
        return strreplace(string, "%", "%%");
}

int specifier_escape_strv(char **l, char ***ret);

/* A generic specifier table consisting of COMMON_SYSTEM_SPECIFIERS and COMMON_TMP_SPECIFIERS */
extern const Specifier system_and_tmp_specifier_table[];
