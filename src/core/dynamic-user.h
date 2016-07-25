#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

typedef struct DynamicUser DynamicUser;

typedef struct DynamicCreds {
        /* A combination of a dynamic user and group */
        DynamicUser *user;
        DynamicUser *group;
} DynamicCreds;

#include "manager.h"

/* Note that this object always allocates a pair of user and group under the same name, even if one of them isn't
 * used. This means, if you want to allocate a group and user pair, and they might have two different names, then you
 * need to allocated two of these objects. DynamicCreds below makes that easy. */
struct DynamicUser {
        int n_ref;
        Manager *manager;

        /* An AF_UNIX socket pair that contains a datagram containing both the numeric ID assigned, as well as a lock
         * file fd locking the user ID we picked. */
        int storage_socket[2];

        char name[];
};

int dynamic_user_acquire(Manager *m, const char *name, DynamicUser **ret);

int dynamic_user_realize(DynamicUser *d, uid_t *ret);
int dynamic_user_current(DynamicUser *d, uid_t *ret);

DynamicUser* dynamic_user_ref(DynamicUser *d);
DynamicUser* dynamic_user_unref(DynamicUser *d);
DynamicUser* dynamic_user_destroy(DynamicUser *d);

int dynamic_user_serialize(Manager *m, FILE *f, FDSet *fds);
void dynamic_user_deserialize_one(Manager *m, const char *value, FDSet *fds);
void dynamic_user_vacuum(Manager *m, bool close_user);

int dynamic_user_lookup_uid(Manager *m, uid_t uid, char **ret);
int dynamic_user_lookup_name(Manager *m, const char *name, uid_t *ret);

int dynamic_creds_acquire(DynamicCreds *creds, Manager *m, const char *user, const char *group);
int dynamic_creds_realize(DynamicCreds *creds, uid_t *uid, gid_t *gid);

void dynamic_creds_unref(DynamicCreds *creds);
void dynamic_creds_destroy(DynamicCreds *creds);
