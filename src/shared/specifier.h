/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "string-util.h"

typedef enum SpecifierResultType {
        SPECIFIER_RESULT_STRING,       /* char*, needs to be freed. */
        SPECIFIER_RESULT_STRING_CONST, /* const char* */
        SPECIFIER_RESULT_UID,          /* uid_t */
        SPECIFIER_RESULT_GID,          /* gid_t */
        _SPECIFIER_RESULT_TYPE_MAX,
        _SPECIFIER_RESULT_TYPE_INVALID = -EINVAL,
} SpecifierResultType;

#define SPECIFIER_ARGUMENTS             \
        char specifier,                 \
        const void *data,               \
        const void *userdata,           \
        SpecifierResultType *ret_type,  \
        void **ret

typedef int (*SpecifierCallback)(SPECIFIER_ARGUMENTS);

typedef struct Specifier {
        const char specifier;
        const SpecifierCallback lookup;
        const void *data;
} Specifier;

int specifier_printf(const char *text, const Specifier table[], const void *userdata, char **ret);

#define SPECIFIER_PROTOTYPE(name) int specifier_##name(SPECIFIER_ARGUMENTS)

SPECIFIER_PROTOTYPE(string);

SPECIFIER_PROTOTYPE(machine_id);
SPECIFIER_PROTOTYPE(boot_id);
SPECIFIER_PROTOTYPE(host_name);
SPECIFIER_PROTOTYPE(short_host_name);
SPECIFIER_PROTOTYPE(kernel_release);
SPECIFIER_PROTOTYPE(architecture);
SPECIFIER_PROTOTYPE(os_id);
SPECIFIER_PROTOTYPE(os_version_id);
SPECIFIER_PROTOTYPE(os_build_id);
SPECIFIER_PROTOTYPE(os_variant_id);
SPECIFIER_PROTOTYPE(os_image_id);
SPECIFIER_PROTOTYPE(os_image_version);

SPECIFIER_PROTOTYPE(group_name);
SPECIFIER_PROTOTYPE(group_id);
SPECIFIER_PROTOTYPE(user_name);
SPECIFIER_PROTOTYPE(user_id);
SPECIFIER_PROTOTYPE(user_home);
SPECIFIER_PROTOTYPE(user_shell);

SPECIFIER_PROTOTYPE(tmp_dir);
SPECIFIER_PROTOTYPE(var_tmp_dir);

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

#define COMMON_SYSTEM_SPECIFIERS                  \
        { 'a', specifier_architecture,    NULL }, \
        { 'A', specifier_os_image_version,NULL }, \
        { 'b', specifier_boot_id,         NULL }, \
        { 'B', specifier_os_build_id,     NULL }, \
        { 'H', specifier_host_name,       NULL }, \
        { 'l', specifier_short_host_name, NULL }, \
        { 'm', specifier_machine_id,      NULL }, \
        { 'M', specifier_os_image_id,     NULL }, \
        { 'o', specifier_os_id,           NULL }, \
        { 'v', specifier_kernel_release,  NULL }, \
        { 'w', specifier_os_version_id,   NULL }, \
        { 'W', specifier_os_variant_id,   NULL }


#define COMMON_CREDS_SPECIFIERS                   \
        { 'g', specifier_group_name,      NULL }, \
        { 'G', specifier_group_id,        NULL }, \
        { 'u', specifier_user_name,       NULL }, \
        { 'U', specifier_user_id,         NULL }

#define COMMON_TMP_SPECIFIERS                     \
        { 'T', specifier_tmp_dir,         NULL }, \
        { 'V', specifier_var_tmp_dir,     NULL }

static inline char* specifier_escape(const char *string) {
        return strreplace(string, "%", "%%");
}

int specifier_escape_strv(char **l, char ***ret);
