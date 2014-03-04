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
#include <sys/acl.h>
#include <acl/libacl.h>
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
