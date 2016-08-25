#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

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

int get_user_creds(const char **username, uid_t *uid, gid_t *gid, const char **home, const char **shell);
int get_user_creds_clean(const char **username, uid_t *uid, gid_t *gid, const char **home, const char **shell);
int get_group_creds(const char **groupname, gid_t *gid);

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

/* Let's pick a UIDs within the 16bit range, so that we are compatible with containers using 16bit
 * user namespacing. At least on Fedora normal users are allocated until UID 60000, hence do not
 * allocate from below this. Also stay away from the upper end of the range as that is often used
 * for overflow/nobody users. */
#define DYNAMIC_UID_MIN ((uid_t) UINT32_C(0x0000EF00))
#define DYNAMIC_UID_MAX ((uid_t) UINT32_C(0x0000FFEF))

static inline bool uid_is_dynamic(uid_t uid) {
        return DYNAMIC_UID_MIN <= uid && uid <= DYNAMIC_UID_MAX;
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
