/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "hashmap.h"

int name_to_uid_offline(const char *root, const char *user, uid_t *ret_uid, Hashmap **cache);
int name_to_gid_offline(const char *root, const char *group, gid_t *ret_gid, Hashmap **cache);
