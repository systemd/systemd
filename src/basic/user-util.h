/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <grp.h>
#if ENABLE_GSHADOW
#  include <gshadow.h>
#endif
#include <pwd.h>
#include <shadow.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include "string-util.h"

/* Users managed by systemd-homed. See https://systemd.io/UIDS-GIDS for details how this range fits into the rest of the world */
#define HOME_UID_MIN ((uid_t) 60001)
#define HOME_UID_MAX ((uid_t) 60513)

/* Users mapped from host into a container */
#define MAP_UID_MIN ((uid_t) 60514)
#define MAP_UID_MAX ((uid_t) 60577)

bool uid_is_valid(uid_t uid);

static inline bool gid_is_valid(gid_t gid) {
        return uid_is_valid((uid_t) gid);
}

int parse_uid(const char *s, uid_t* ret_uid);
int parse_uid_range(const char *s, uid_t *ret_lower, uid_t *ret_upper);

static inline int parse_gid(const char *s, gid_t *ret_gid) {
        return parse_uid(s, (uid_t*) ret_gid);
}

char* getlogname_malloc(void);
char* getusername_malloc(void);

const char* default_root_shell_at(int rfd);
const char* default_root_shell(const char *root);

bool is_nologin_shell(const char *shell);

static inline bool shell_is_placeholder(const char *shell) {
        return isempty(shell) || is_nologin_shell(shell);
}

typedef enum UserCredsFlags {
        USER_CREDS_PREFER_NSS           = 1 << 0,  /* if set, only synthesize user records if database lacks them. Normally we bypass the userdb entirely for the records we can synthesize */
        USER_CREDS_ALLOW_MISSING        = 1 << 1,  /* if a numeric UID string is resolved, be OK if there's no record for it */
        USER_CREDS_CLEAN                = 1 << 2,  /* try to clean up shell and home fields with invalid data */
        USER_CREDS_SUPPRESS_PLACEHOLDER = 1 << 3,  /* suppress home and/or shell fields if value is placeholder (root/empty/nologin) */
} UserCredsFlags;

int get_user_creds(const char **username, uid_t *ret_uid, gid_t *ret_gid, const char **ret_home, const char **ret_shell, UserCredsFlags flags);
int get_group_creds(const char **groupname, gid_t *ret_gid, UserCredsFlags flags);

char* uid_to_name(uid_t uid);
char* gid_to_name(gid_t gid);

int in_gid(gid_t gid);
int in_group(const char *name);

int merge_gid_lists(const gid_t *list1, size_t size1, const gid_t *list2, size_t size2, gid_t **result);
int getgroups_alloc(gid_t **ret);

int get_home_dir(char **ret);
int get_shell(char **ret);

int fully_set_uid_gid(uid_t uid, gid_t gid, const gid_t supplementary_gids[], size_t n_supplementary_gids);
static inline int reset_uid_gid(void) {
        return fully_set_uid_gid(0, 0, NULL, 0);
}

int take_etc_passwd_lock(const char *root);

#define UID_INVALID ((uid_t) -1)
#define GID_INVALID ((gid_t) -1)

#define UID_NOBODY ((uid_t) 65534U)
#define GID_NOBODY ((gid_t) 65534U)

/* If REMOUNT_IDMAPPING_HOST_ROOT is set for remount_idmap() we'll include a mapping here that maps the host
 * root user accessing the idmapped mount to the this user ID on the backing fs. This is the last valid UID in
 * the *signed* 32-bit range. You might wonder why precisely use this specific UID for this purpose? Well, we
 * definitely cannot use the first 0…65536 UIDs for that, since in most cases that's precisely the file range
 * we intend to map to some high UID range, and since UID mappings have to be bijective we thus cannot use
 * them at all. Furthermore the UID range beyond INT32_MAX (i.e. the range above the signed 32-bit range) is
 * icky, since many APIs cannot use it (example: setfsuid() returns the old UID as signed integer). Following
 * our usual logic of assigning a 16-bit UID range to each container, so that the upper 16-bit of a 32-bit UID
 * value indicate kind of a "container ID" and the lower 16-bit map directly to the intended user you can read
 * this specific UID as the "nobody" user of the container with ID 0x7FFF, which is kinda nice. */
#define UID_MAPPED_ROOT ((uid_t) (INT32_MAX-1))
#define GID_MAPPED_ROOT ((gid_t) (INT32_MAX-1))

#define ETC_PASSWD_LOCK_FILENAME ".pwd.lock"
#define ETC_PASSWD_LOCK_PATH "/etc/" ETC_PASSWD_LOCK_FILENAME

/* The following macros add 1 when converting things, since UID 0 is a valid UID, while the pointer
 * NULL is special */
#define PTR_TO_UID(p) ((uid_t) (((uintptr_t) (p))-1))
#define UID_TO_PTR(u) ((void*) (((uintptr_t) (u))+1))

#define PTR_TO_GID(p) ((gid_t) (((uintptr_t) (p))-1))
#define GID_TO_PTR(u) ((void*) (((uintptr_t) (u))+1))

static inline bool userns_supported(void) {
        return access("/proc/self/uid_map", F_OK) >= 0;
}

typedef enum ValidUserFlags {
        VALID_USER_RELAX         = 1 << 0,
        VALID_USER_WARN          = 1 << 1,
        VALID_USER_ALLOW_NUMERIC = 1 << 2,
} ValidUserFlags;

bool valid_user_group_name(const char *u, ValidUserFlags flags);
bool valid_gecos(const char *d);
char* mangle_gecos(const char *d);
bool valid_home(const char *p);
bool valid_shell(const char *p);

int maybe_setgroups(size_t size, const gid_t *list);

bool synthesize_nobody(void);

int fgetpwent_sane(FILE *stream, struct passwd **pw);
int fgetspent_sane(FILE *stream, struct spwd **sp);
int fgetgrent_sane(FILE *stream, struct group **gr);
int putpwent_sane(const struct passwd *pw, FILE *stream);
int putspent_sane(const struct spwd *sp, FILE *stream);
int putgrent_sane(const struct group *gr, FILE *stream);
#if ENABLE_GSHADOW
int fgetsgent_sane(FILE *stream, struct sgrp **sg);
int putsgent_sane(const struct sgrp *sg, FILE *stream);
#endif

int is_this_me(const char *username);

const char* get_home_root(void);

static inline bool hashed_password_is_locked_or_invalid(const char *password) {
        return password && password[0] != '$';
}

/* A locked *and* invalid password for "struct spwd"'s .sp_pwdp and "struct passwd"'s .pw_passwd field */
#define PASSWORD_LOCKED_AND_INVALID "!*"

/* A password indicating "look in shadow file, please!" for "struct passwd"'s .pw_passwd */
#define PASSWORD_SEE_SHADOW "x"

/* A password indicating "hey, no password required for login" */
#define PASSWORD_NONE ""

/* Used by sysusers to indicate that the password should be filled in by firstboot.
 * Also see https://github.com/systemd/systemd/pull/24680#pullrequestreview-1439464325.
 */
#define PASSWORD_UNPROVISIONED "!unprovisioned"

int getpwuid_malloc(uid_t uid, struct passwd **ret);
int getpwnam_malloc(const char *name, struct passwd **ret);

int getgrnam_malloc(const char *name, struct group **ret);
int getgrgid_malloc(gid_t gid, struct group **ret);
