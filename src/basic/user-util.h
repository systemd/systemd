/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <grp.h>
#include <gshadow.h>
#include <pwd.h>
#include <shadow.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

bool uid_is_valid(uid_t uid);

static inline bool gid_is_valid(gid_t gid) {
        return uid_is_valid((uid_t) gid);
}

int parse_uid(const char *s, uid_t* ret_uid);

static inline int parse_gid(const char *s, gid_t *ret_gid) {
        return parse_uid(s, (uid_t*) ret_gid);
}

char* getlogname_malloc(void);
char* getusername_malloc(void);

typedef enum UserCredsFlags {
        USER_CREDS_PREFER_NSS    = 1 << 0,  /* if set, only synthesize user records if database lacks them. Normally we bypass the userdb entirely for the records we can synthesize */
        USER_CREDS_ALLOW_MISSING = 1 << 1,  /* if a numeric UID string is resolved, be OK if there's no record for it */
        USER_CREDS_CLEAN         = 1 << 2,  /* try to clean up shell and home fields with invalid data */
} UserCredsFlags;

int get_user_creds(const char **username, uid_t *uid, gid_t *gid, const char **home, const char **shell, UserCredsFlags flags);
int get_group_creds(const char **groupname, gid_t *gid, UserCredsFlags flags);

char* uid_to_name(uid_t uid);
char* gid_to_name(gid_t gid);

int in_gid(gid_t gid);
int in_group(const char *name);

int get_home_dir(char **ret);
int get_shell(char **_ret);

int reset_uid_gid(void);

int take_etc_passwd_lock(const char *root);

#define UID_INVALID ((uid_t) -1)
#define GID_INVALID ((gid_t) -1)

#define UID_NOBODY ((uid_t) 65534U)
#define GID_NOBODY ((gid_t) 65534U)

#define ETC_PASSWD_LOCK_PATH "/etc/.pwd.lock"

static inline bool uid_is_dynamic(uid_t uid) {
        return DYNAMIC_UID_MIN <= uid && uid <= DYNAMIC_UID_MAX;
}

static inline bool gid_is_dynamic(gid_t gid) {
        return uid_is_dynamic((uid_t) gid);
}

static inline bool uid_is_system(uid_t uid) {
        return uid <= SYSTEM_UID_MAX;
}

static inline bool gid_is_system(gid_t gid) {
        return gid <= SYSTEM_GID_MAX;
}

/* The following macros add 1 when converting things, since UID 0 is a valid UID, while the pointer
 * NULL is special */
#define PTR_TO_UID(p) ((uid_t) (((uintptr_t) (p))-1))
#define UID_TO_PTR(u) ((void*) (((uintptr_t) (u))+1))

#define PTR_TO_GID(p) ((gid_t) (((uintptr_t) (p))-1))
#define GID_TO_PTR(u) ((void*) (((uintptr_t) (u))+1))

static inline bool userns_supported(void) {
        return access("/proc/self/uid_map", F_OK) >= 0;
}

bool valid_user_group_name(const char *u);
bool valid_user_group_name_or_id(const char *u);
bool valid_gecos(const char *d);
bool valid_home(const char *p);

static inline bool valid_shell(const char *p) {
        /* We have the same requirements, so just piggy-back on the home check.
         *
         * Let's ignore /etc/shells because this is only applicable to real and
         * not system users. It is also incompatible with the idea of empty /etc.
         */
        return valid_home(p);
}

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
