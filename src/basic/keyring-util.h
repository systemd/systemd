/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/keyctl.h>         /* IWYU pragma: export */

#include "forward.h"

/* Like TAKE_PTR() but for key_serial_t, resetting them to -1 */
#define TAKE_KEY_SERIAL(key_serial) TAKE_GENERIC(key_serial, key_serial_t, -1)

int keyring_read(key_serial_t serial, void **ret, size_t *ret_size);
int keyring_describe(key_serial_t serial, char **ret);

/* One line of /proc/keys, see proc_keys_show() in the kernel. */
typedef struct ProcKeysEntry {
        key_serial_t serial;
        char flags[sizeof("IRDQUNi")]; /* '-' for unset */
        uint32_t perm;
        uid_t uid;
        gid_t gid;
        char *type;             /* truncated to nine characters by the kernel */
        char *description;      /* type specific, may contain spaces */
} ProcKeysEntry;

void proc_keys_entry_done(ProcKeysEntry *e);
int proc_keys_entry_parse(const char *line, ProcKeysEntry *ret);
bool proc_keys_entry_is_keyring(const ProcKeysEntry *e, const char *name);

int keyring_find_by_name(const char *name, uid_t owner, key_serial_t *ret);

int keyring_describe_full(
                key_serial_t serial,
                char **ret_type,
                uid_t *ret_uid,
                uint32_t *ret_perm,
                char **ret_description);
