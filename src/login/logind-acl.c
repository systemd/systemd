/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <assert.h>
#include <sys/acl.h>
#include <acl/libacl.h>
#include <errno.h>
#include <string.h>

#include "logind-acl.h"
#include "util.h"
#include "acl-util.h"

static int flush_acl(acl_t acl) {
        acl_entry_t i;
        int found;
        bool changed = false;

        assert(acl);

        for (found = acl_get_entry(acl, ACL_FIRST_ENTRY, &i);
             found > 0;
             found = acl_get_entry(acl, ACL_NEXT_ENTRY, &i)) {

                acl_tag_t tag;

                if (acl_get_tag_type(i, &tag) < 0)
                        return -errno;

                if (tag != ACL_USER)
                        continue;

                if (acl_delete_entry(acl, i) < 0)
                        return -errno;

                changed = true;
        }

        if (found < 0)
                return -errno;

        return changed;
}

int devnode_acl(const char *path,
                bool flush,
                bool del, uid_t old_uid,
                bool add, uid_t new_uid) {

        acl_t acl;
        int r = 0;
        bool changed = false;

        assert(path);

        acl = acl_get_file(path, ACL_TYPE_ACCESS);
        if (!acl)
                return -errno;

        if (flush) {

                r = flush_acl(acl);
                if (r < 0)
                        goto finish;
                if (r > 0)
                        changed = true;

        } else if (del && old_uid > 0) {
                acl_entry_t entry;

                r = acl_find_uid(acl, old_uid, &entry);
                if (r < 0)
                        goto finish;

                if (r > 0) {
                        if (acl_delete_entry(acl, entry) < 0) {
                                r = -errno;
                                goto finish;
                        }

                        changed = true;
                }
        }

        if (add && new_uid > 0) {
                acl_entry_t entry;
                acl_permset_t permset;
                int rd, wt;

                r = acl_find_uid(acl, new_uid, &entry);
                if (r < 0)
                        goto finish;

                if (r == 0) {
                        if (acl_create_entry(&acl, &entry) < 0) {
                                r = -errno;
                                goto finish;
                        }

                        if (acl_set_tag_type(entry, ACL_USER) < 0 ||
                            acl_set_qualifier(entry, &new_uid) < 0) {
                                r = -errno;
                                goto finish;
                        }
                }

                if (acl_get_permset(entry, &permset) < 0) {
                        r = -errno;
                        goto finish;
                }

                rd = acl_get_perm(permset, ACL_READ);
                if (rd < 0) {
                        r = -errno;
                        goto finish;
                }

                wt = acl_get_perm(permset, ACL_WRITE);
                if (wt < 0) {
                        r = -errno;
                        goto finish;
                }

                if (!rd || !wt) {

                        if (acl_add_perm(permset, ACL_READ|ACL_WRITE) < 0) {
                                r = -errno;
                                goto finish;
                        }

                        changed = true;
                }
        }

        if (!changed)
                goto finish;

        if (acl_calc_mask(&acl) < 0) {
                r = -errno;
                goto finish;
        }

        if (acl_set_file(path, ACL_TYPE_ACCESS, acl) < 0) {
                r = -errno;
                goto finish;
        }

        r = 0;

finish:
        acl_free(acl);

        return r;
}

int devnode_acl_all(struct udev *udev,
                    const char *seat,
                    bool flush,
                    bool del, uid_t old_uid,
                    bool add, uid_t new_uid) {

        struct udev_list_entry *item = NULL, *first = NULL;
        struct udev_enumerate *e;
        int r;

        assert(udev);

        if (isempty(seat))
                seat = "seat0";

        e = udev_enumerate_new(udev);
        if (!e)
                return -ENOMEM;

        /* We can only match by one tag in libudev. We choose
         * "uaccess" for that. If we could match for two tags here we
         * could add the seat name as second match tag, but this would
         * be hardly optimizable in libudev, and hence checking the
         * second tag manually in our loop is a good solution. */

        r = udev_enumerate_add_match_tag(e, "uaccess");
        if (r < 0)
                goto finish;

        r = udev_enumerate_scan_devices(e);
        if (r < 0)
                goto finish;

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                struct udev_device *d;
                const char *node, *sn;

                d = udev_device_new_from_syspath(udev, udev_list_entry_get_name(item));
                if (!d) {
                        r = -ENOMEM;
                        goto finish;
                }

                sn = udev_device_get_property_value(d, "ID_SEAT");
                if (isempty(sn))
                        sn = "seat0";

                if (!streq(seat, sn)) {
                        udev_device_unref(d);
                        continue;
                }

                node = udev_device_get_devnode(d);
                if (!node) {
                        /* In case people mistag devices with nodes, we need to ignore this */
                        udev_device_unref(d);
                        continue;
                }

                log_debug("Fixing up %s for seat %s...", node, sn);

                r = devnode_acl(node, flush, del, old_uid, add, new_uid);
                udev_device_unref(d);

                if (r < 0)
                        goto finish;
        }

finish:
        if (e)
                udev_enumerate_unref(e);

        return r;
}
