/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/keyctl.h>         /* IWYU pragma: export */

#include "errno-util.h"
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
/* The stream carries /proc/keys formatted rows, split out so tests can feed one */
int keyring_find_by_name_from(FILE *f, const char *name, uid_t owner, key_serial_t *ret);

int keyring_list(key_serial_t keyring, key_serial_t **ret, size_t *ret_n);

int keyring_describe_full(
                key_serial_t serial,
                char **ret_type,
                uid_t *ret_uid,
                uint32_t *ret_perm,
                char **ret_description);
static inline int keyring_perm(key_serial_t serial, uint32_t *ret) {
        return keyring_describe_full(serial, /* ret_type= */ NULL, /* ret_uid= */ NULL, ret,
                                     /* ret_description= */ NULL);
}
static inline int keyring_description(key_serial_t serial, char **ret) {
        return keyring_describe_full(serial, /* ret_type= */ NULL, /* ret_uid= */ NULL, /* ret_perm= */ NULL,
                                     ret);
}

int keyring_add_asymmetric(
                key_serial_t keyring,
                const char *description,
                const struct iovec *der,
                key_serial_t *ret);

/* Both keyring_restrict() and keyring_set_perm() are complementary mechanisms to remove various ways to
 * alter a keyring.
 *
 * A keyring with the kernel-default mask can still be emptied, revoked or invalidated by root. The
 * permission mask can also still be changed.
 *
 * In order to meaningfully restrict a keyring both keyring_restrict() and keyring_set_perm() have to be
 * combined and used in the right order. Keyrings such as .dm-verity and .bpf must be restricted before
 * the kernel will use them. If SetAttr is dropped from the mask the mask itself is frozen.
 * Write is needed in case a restriction is chosen that still allows keys to be linked.
 *
 * Because restrictions need SetAttr a keyring must be restricted first and then the Write or SetAttr
 * permission must be removed. The other way around would make the keyring permanently unrestrictable. This
 * can be seen as "sealing the keyring".
 *
 * Note that once SetAttr is gone KEYCTL_RESTRICT_KEYRING and KEYCTL_SETPERM fail with -EACCES.
 * Note that KEY_POS_SEARCH should not be dropped so signature verification can still search the keyring.
 * Note that KEY_USR_VIEW is required to keep the keyring visible in /proc/keys and to use
 * KEYCTL_DESCRIBE.
 */

/* To restrict a keyring SetAttr permissions are needed. If @type is NULL the kernel refuses every link with
 * -EPERM. A keyring may only be restricted once. Another attempt to restrict it will fail with -EEXIST.
 * This also implies that setting a restriction is a one-way transition. */
static inline int keyring_restrict(key_serial_t keyring, const char *type, const char *restriction) {
        return RET_NERRNO(keyctl(KEYCTL_RESTRICT_KEYRING, keyring,
                                 (unsigned long) type, (unsigned long) restriction, 0));
}

/* Every operation other than KEYCTL_LINK is based on permission checks:
 *
 * - KEYCTL_UNLINK and KEYCTL_CLEAR require Write
 * - KEYCTL_REVOKE requires Write or SetAttr
 * - KEYCTL_INVALIDATE Search
 * - KEYCTL_SETPERM/CHOWN/SET_TIMEOUT SetAttr
 * - KEYCTL_READ Read
 * - searches require Search
 */
static inline int keyring_set_perm(key_serial_t serial, uint32_t perm) {
        return RET_NERRNO(keyctl(KEYCTL_SETPERM, serial, perm, 0, 0));
}

/* Removes one key from the keyring, requires Write on the keyring */
static inline int keyring_unlink_key(key_serial_t keyring, key_serial_t key) {
        return RET_NERRNO(keyctl(KEYCTL_UNLINK, key, keyring, 0, 0));
}

/* Resolves a KEY_SPEC_* ID to the serial, creating nothing */
static inline int keyring_resolve(key_serial_t id) {
        return RET_NERRNO(keyctl(KEYCTL_GET_KEYRING_ID, id, /* create= */ 0, 0, 0));
}
