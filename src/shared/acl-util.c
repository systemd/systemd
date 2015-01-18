/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011,2013 Lennart Poettering

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

#include <assert.h>
#include <errno.h>
#include <stdbool.h>

#include "acl-util.h"
#include "util.h"
#include "strv.h"

int acl_find_uid(acl_t acl, uid_t uid, acl_entry_t *entry) {
        acl_entry_t i;
        int found;

        assert(acl);
        assert(entry);

        for (found = acl_get_entry(acl, ACL_FIRST_ENTRY, &i);
             found > 0;
             found = acl_get_entry(acl, ACL_NEXT_ENTRY, &i)) {

                acl_tag_t tag;
                uid_t *u;
                bool b;

                if (acl_get_tag_type(i, &tag) < 0)
                        return -errno;

                if (tag != ACL_USER)
                        continue;

                u = acl_get_qualifier(i);
                if (!u)
                        return -errno;

                b = *u == uid;
                acl_free(u);

                if (b) {
                        *entry = i;
                        return 1;
                }
        }

        if (found < 0)
                return -errno;

        return 0;
}

int calc_acl_mask_if_needed(acl_t *acl_p) {
        acl_entry_t i;
        int found;

        assert(acl_p);

        for (found = acl_get_entry(*acl_p, ACL_FIRST_ENTRY, &i);
             found > 0;
             found = acl_get_entry(*acl_p, ACL_NEXT_ENTRY, &i)) {

                acl_tag_t tag;

                if (acl_get_tag_type(i, &tag) < 0)
                        return -errno;

                if (tag == ACL_MASK)
                        return 0;
        }

        if (found < 0)
                return -errno;

        if (acl_calc_mask(acl_p) < 0)
                return -errno;

        return 0;
}

int search_acl_groups(char*** dst, const char* path, bool* belong) {
        acl_t acl;

        assert(path);
        assert(belong);

        acl = acl_get_file(path, ACL_TYPE_DEFAULT);
        if (acl) {
                acl_entry_t entry;
                int r;

                r = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
                while (r > 0) {
                        acl_tag_t tag;
                        gid_t *gid;
                        char *name;

                        r = acl_get_tag_type(entry, &tag);
                        if (r < 0)
                                break;

                        if (tag != ACL_GROUP)
                                goto next;

                        gid = acl_get_qualifier(entry);
                        if (!gid)
                                break;

                        if (in_gid(*gid) > 0) {
                                *belong = true;
                                break;
                        }

                        name = gid_to_name(*gid);
                        if (!name) {
                                acl_free(acl);
                                return log_oom();
                        }

                        r = strv_consume(dst, name);
                        if (r < 0) {
                                acl_free(acl);
                                return log_oom();
                        }

                next:
                        r = acl_get_entry(acl, ACL_NEXT_ENTRY, &entry);
                }

                acl_free(acl);
        }

        return 0;
}

int parse_acl(char *text, acl_t *acl_access, acl_t *acl_default, bool want_mask) {
        _cleanup_free_ char **a = NULL, **d = NULL; /* strings are not be freed */
        _cleanup_strv_free_ char **split;
        char **entry;
        int r = -EINVAL;
        _cleanup_(acl_freep) acl_t a_acl = NULL, d_acl = NULL;

        split = strv_split(text, ",");
        if (!split)
                return log_oom();

        STRV_FOREACH(entry, split) {
                char *p;

                p = startswith(*entry, "default:");
                if (!p)
                        p = startswith(*entry, "d:");

                if (p)
                        r = strv_push(&d, p);
                else
                        r = strv_push(&a, *entry);
        }
        if (r < 0)
                return r;

        if (!strv_isempty(a)) {
                _cleanup_free_ char *join;

                join = strv_join(a, ",");
                if (!join)
                        return -ENOMEM;

                a_acl = acl_from_text(join);
                if (!a_acl)
                        return -EINVAL;

                if (want_mask) {
                        r = calc_acl_mask_if_needed(&a_acl);
                        if (r < 0)
                                return r;
                }
        }

        if (!strv_isempty(d)) {
                _cleanup_free_ char *join;

                join = strv_join(d, ",");
                if (!join)
                        return -ENOMEM;

                d_acl = acl_from_text(join);
                if (!d_acl)
                        return -EINVAL;

                if (want_mask) {
                        r = calc_acl_mask_if_needed(&d_acl);
                        if (r < 0)
                                return r;
                }
        }

        *acl_access = a_acl;
        *acl_default = d_acl;
        a_acl = d_acl = NULL;
        return 0;
}

int acls_for_file(const char *path, acl_type_t type, acl_t new, acl_t *acl) {
        _cleanup_(acl_freep) acl_t old;
        acl_entry_t i;
        int found, r;

        old = acl_get_file(path, type);
        if (!old)
                return -errno;

        for (found = acl_get_entry(new, ACL_FIRST_ENTRY, &i);
             found > 0;
             found = acl_get_entry(new, ACL_NEXT_ENTRY, &i)) {

                acl_entry_t j;

                if (acl_create_entry(&old, &j) < 0)
                        return -errno;

                if (acl_copy_entry(j, i) < 0)
                        return -errno;
        }

        r = calc_acl_mask_if_needed(&old);
        if (r < 0)
                return r;

        *acl = old;
        old = NULL;
        return 0;
}
