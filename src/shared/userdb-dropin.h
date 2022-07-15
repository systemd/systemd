/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "def.h"
#include "group-record.h"
#include "user-record.h"
#include "userdb.h"

/* This could be put together with CONF_PATHS_NULSTR, with the exception of the /run/host/ part in the
 * middle, which we use here, but not otherwise. */
#define USERDB_DROPIN_DIR_NULSTR(n)             \
        "/etc/" n "\0"                          \
        "/run/" n "\0"                          \
        "/run/host/" n "\0"                     \
        "/usr/local/lib/" n "\0"                \
        "/usr/lib/" n "\0"                      \
        _CONF_PATHS_SPLIT_USR_NULSTR(n)

int dropin_user_record_by_name(const char *name, const char *path, UserDBFlags flags, UserRecord **ret);
int dropin_user_record_by_uid(uid_t uid, const char *path, UserDBFlags flags, UserRecord **ret);

int dropin_group_record_by_name(const char *name, const char *path, UserDBFlags flags, GroupRecord **ret);
int dropin_group_record_by_gid(gid_t gid, const char *path, UserDBFlags flags, GroupRecord **ret);
