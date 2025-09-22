/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "acl-util.h"
#include "fd-util.h"
#include "udev-acl.h"

#if HAVE_ACL
int devnode_acl(int fd, uid_t uid) {
        bool changed = false, found = false;
        int r;

        assert(fd >= 0);

        _cleanup_(acl_freep) acl_t acl = NULL;
        acl = acl_get_file(FORMAT_PROC_FD_PATH(fd), ACL_TYPE_ACCESS);
        if (!acl)
                return -errno;

        acl_entry_t entry;
        for (r = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
             r > 0;
             r = acl_get_entry(acl, ACL_NEXT_ENTRY, &entry)) {

                acl_tag_t tag;
                if (acl_get_tag_type(entry, &tag) < 0)
                        return -errno;

                if (tag != ACL_USER)
                        continue;

                if (uid > 0) {
                        uid_t *u = acl_get_qualifier(entry);
                        if (!u)
                                return -errno;

                        if (*u == uid) {
                                acl_permset_t permset;
                                if (acl_get_permset(entry, &permset) < 0)
                                        return -errno;

                                int rd = acl_get_perm(permset, ACL_READ);
                                if (rd < 0)
                                        return -errno;

                                int wt = acl_get_perm(permset, ACL_WRITE);
                                if (wt < 0)
                                        return -errno;

                                if (!rd || !wt) {
                                        if (acl_add_perm(permset, ACL_READ|ACL_WRITE) < 0)
                                                return -errno;

                                        changed = true;
                                }

                                found = true;
                                continue;
                        }
                }

                if (acl_delete_entry(acl, entry) < 0)
                        return -errno;

                changed = true;
        }
        if (r < 0)
                return -errno;

        if (!found && uid > 0) {
                if (acl_create_entry(&acl, &entry) < 0)
                        return -errno;

                if (acl_set_tag_type(entry, ACL_USER) < 0)
                        return -errno;

                if (acl_set_qualifier(entry, &uid) < 0)
                        return -errno;

                acl_permset_t permset;
                if (acl_get_permset(entry, &permset) < 0)
                        return -errno;

                if (acl_add_perm(permset, ACL_READ|ACL_WRITE) < 0)
                        return -errno;

                changed = true;
        }

        if (!changed)
                return 0;

        if (acl_calc_mask(&acl) < 0)
                return -errno;

        if (acl_set_file(FORMAT_PROC_FD_PATH(fd), ACL_TYPE_ACCESS, acl) < 0)
                return -errno;

        return 0;
}
#endif
