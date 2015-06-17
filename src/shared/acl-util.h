/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#ifdef HAVE_ACL

#include <stdbool.h>
#include <sys/acl.h>
#include <acl/libacl.h>

#include "macro.h"

int acl_find_uid(acl_t acl, uid_t uid, acl_entry_t *entry);
int calc_acl_mask_if_needed(acl_t *acl_p);
int add_base_acls_if_needed(acl_t *acl_p, const char *path);
int acl_search_groups(const char* path, char ***ret_groups);
int parse_acl(const char *text, acl_t *acl_access, acl_t *acl_default, bool want_mask);
int acls_for_file(const char *path, acl_type_t type, acl_t new, acl_t *acl);

/* acl_free takes multiple argument types.
 * Multiple cleanup functions are necessary. */
DEFINE_TRIVIAL_CLEANUP_FUNC(acl_t, acl_free);
#define acl_free_charp acl_free
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, acl_free_charp);
#define acl_free_uid_tp acl_free
DEFINE_TRIVIAL_CLEANUP_FUNC(uid_t*, acl_free_uid_tp);
#define acl_free_gid_tp acl_free
DEFINE_TRIVIAL_CLEANUP_FUNC(gid_t*, acl_free_gid_tp);

#endif
