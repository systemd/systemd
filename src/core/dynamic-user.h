/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

/* Note that this object always allocates a pair of user and group under the same name, even if one of them isn't
 * used. This means, if you want to allocate a group and user pair, and they might have two different names, then you
 * need to allocated two of these objects. DynamicCreds below makes that easy. */
typedef struct DynamicUser {
        Manager *manager;
        unsigned n_ref;

        /* An AF_UNIX socket pair that contains a datagram containing both the numeric ID assigned, as well as a lock
         * file fd locking the user ID we picked. */
        int storage_socket[2];

        char name[];
} DynamicUser;

typedef struct DynamicCreds {
        /* A combination of a dynamic user and group */
        DynamicUser *user;
        DynamicUser *group;
} DynamicCreds;

int dynamic_user_serialize(Manager *m, FILE *f, FDSet *fds);
int dynamic_user_serialize_one(DynamicUser *d, const char *key, FILE *f, FDSet *fds);
void dynamic_user_deserialize_one(Manager *m, const char *value, FDSet *fds, DynamicUser **ret);
DynamicUser* dynamic_user_free(DynamicUser *d);
void dynamic_user_vacuum(Manager *m, bool close_user);

int dynamic_user_current(DynamicUser *d, uid_t *ret);
int dynamic_user_lookup_uid(Manager *m, uid_t uid, char **ret);
int dynamic_user_lookup_name(Manager *m, const char *name, uid_t *ret);

int dynamic_creds_make(Manager *m, const char *user, const char *group, DynamicCreds **ret);
int dynamic_creds_realize(DynamicCreds *creds, char **suggested_paths, uid_t *uid, gid_t *gid);

DynamicCreds *dynamic_creds_unref(DynamicCreds *creds);
DynamicCreds *dynamic_creds_destroy(DynamicCreds *creds);
void dynamic_creds_done(DynamicCreds *creds);
void dynamic_creds_close(DynamicCreds *creds);

DEFINE_TRIVIAL_CLEANUP_FUNC(DynamicCreds*, dynamic_creds_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(DynamicCreds*, dynamic_creds_destroy);

DynamicUser *dynamic_user_ref(DynamicUser *user);
