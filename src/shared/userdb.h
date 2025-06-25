/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "group-record.h"
#include "user-record.h"

/* Inquire local services for user/group records */

typedef struct UserDBIterator UserDBIterator;

UserDBIterator *userdb_iterator_free(UserDBIterator *iterator);
DEFINE_TRIVIAL_CLEANUP_FUNC(UserDBIterator*, userdb_iterator_free);

typedef enum UserDBFlags {
        /* The main sources */
        USERDB_EXCLUDE_NSS               = 1 << 0,  /* don't do client-side nor server-side NSS */
        USERDB_EXCLUDE_VARLINK           = 1 << 1,  /* don't talk to any varlink services */
        USERDB_EXCLUDE_DROPIN            = 1 << 2,  /* don't load drop-in user/group definitions */

        /* Modifications */
        USERDB_SUPPRESS_SHADOW           = 1 << 3,  /* don't do client-side shadow calls (server side might happen though) */
        USERDB_EXCLUDE_DYNAMIC_USER      = 1 << 4,  /* exclude looking up in io.systemd.DynamicUser */
        USERDB_AVOID_MULTIPLEXER         = 1 << 5,  /* exclude looking up via io.systemd.Multiplexer */
        USERDB_DONT_SYNTHESIZE_INTRINSIC = 1 << 6,  /* don't synthesize root/nobody */
        USERDB_DONT_SYNTHESIZE_FOREIGN   = 1 << 7,  /* don't synthesize foreign UID records */

        /* Combinations */
        USERDB_NSS_ONLY = USERDB_EXCLUDE_VARLINK|USERDB_EXCLUDE_DROPIN|USERDB_DONT_SYNTHESIZE_INTRINSIC|USERDB_DONT_SYNTHESIZE_FOREIGN,
        USERDB_DROPIN_ONLY = USERDB_EXCLUDE_NSS|USERDB_EXCLUDE_VARLINK|USERDB_DONT_SYNTHESIZE_INTRINSIC|USERDB_DONT_SYNTHESIZE_FOREIGN,

        USERDB_PARSE_NUMERIC             = 1 << 8,  /* if a numeric UID is specified as name, parse it and look up by UID/GID */
        USERDB_SYNTHESIZE_NUMERIC        = 1 << 9,  /* synthesize system UID/GID even if it does not exist */
} UserDBFlags;

/* Well-known errors we'll return here:
 *
 *      -ESRCH: No such user/group
 *      -ELINK: Varlink logic turned off (and no other source available)
 * -EOPNOTSUPP: Enumeration not supported
 *  -ETIMEDOUT: Time-out
 */

int userdb_by_name(const char *name, const UserDBMatch *match, UserDBFlags flags, UserRecord **ret);
int userdb_by_uid(uid_t uid, const UserDBMatch *match, UserDBFlags flags, UserRecord **ret);
int userdb_all(const UserDBMatch *match, UserDBFlags flags, UserDBIterator **ret);
int userdb_iterator_get(UserDBIterator *iterator, const UserDBMatch *match, UserRecord **ret);

int groupdb_by_name(const char *name, const UserDBMatch *match, UserDBFlags flags, GroupRecord **ret);
int groupdb_by_gid(gid_t gid, const UserDBMatch *match, UserDBFlags flags, GroupRecord **ret);
int groupdb_all(const UserDBMatch *match, UserDBFlags flags, UserDBIterator **ret);
int groupdb_iterator_get(UserDBIterator *iterator, const UserDBMatch *match, GroupRecord **ret);

int membershipdb_by_user(const char *name, UserDBFlags flags, UserDBIterator **ret);
int membershipdb_by_group(const char *name, UserDBFlags flags, UserDBIterator **ret);
int membershipdb_all(UserDBFlags flags, UserDBIterator **ret);
int membershipdb_iterator_get(UserDBIterator *iterator, char **user, char **group);
int membershipdb_by_group_strv(const char *name, UserDBFlags flags, char ***ret);

int userdb_block_nss_systemd(int b);
