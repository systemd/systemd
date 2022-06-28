/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "sd-device.h"

#include "acl-util.h"
#include "alloc-util.h"
#include "device-util.h"
#include "devnode-acl.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "set.h"
#include "string-util.h"
#include "util.h"

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

        _cleanup_(acl_freep) acl_t acl = NULL;
        int r;
        bool changed = false;

        assert(path);

        acl = acl_get_file(path, ACL_TYPE_ACCESS);
        if (!acl)
                return -errno;

        if (flush) {

                r = flush_acl(acl);
                if (r < 0)
                        return r;
                if (r > 0)
                        changed = true;

        } else if (del && old_uid > 0) {
                acl_entry_t entry;

                r = acl_find_uid(acl, old_uid, &entry);
                if (r < 0)
                        return r;

                if (r > 0) {
                        if (acl_delete_entry(acl, entry) < 0)
                                return -errno;

                        changed = true;
                }
        }

        if (add && new_uid > 0) {
                acl_entry_t entry;
                acl_permset_t permset;
                int rd, wt;

                r = acl_find_uid(acl, new_uid, &entry);
                if (r < 0)
                        return r;

                if (r == 0) {
                        if (acl_create_entry(&acl, &entry) < 0)
                                return -errno;

                        if (acl_set_tag_type(entry, ACL_USER) < 0 ||
                            acl_set_qualifier(entry, &new_uid) < 0)
                                return -errno;
                }

                if (acl_get_permset(entry, &permset) < 0)
                        return -errno;

                rd = acl_get_perm(permset, ACL_READ);
                if (rd < 0)
                        return -errno;

                wt = acl_get_perm(permset, ACL_WRITE);
                if (wt < 0)
                        return -errno;

                if (!rd || !wt) {

                        if (acl_add_perm(permset, ACL_READ|ACL_WRITE) < 0)
                                return -errno;

                        changed = true;
                }
        }

        if (!changed)
                return 0;

        if (acl_calc_mask(&acl) < 0)
                return -errno;

        if (acl_set_file(path, ACL_TYPE_ACCESS, acl) < 0)
                return -errno;

        return 0;
}

int devnode_acl_all(const char *seat,
                    bool flush,
                    bool del, uid_t old_uid,
                    bool add, uid_t new_uid) {

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_set_free_ Set *nodes = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        sd_device *d;
        char *n;
        int r;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        if (isempty(seat))
                seat = "seat0";

        /* We can only match by one tag in libudev. We choose
         * "uaccess" for that. If we could match for two tags here we
         * could add the seat name as second match tag, but this would
         * be hardly optimizable in libudev, and hence checking the
         * second tag manually in our loop is a good solution. */
        r = sd_device_enumerator_add_match_tag(e, "uaccess");
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                const char *node, *sn;

                /* Make sure the tag is still in place */
                if (sd_device_has_current_tag(d, "uaccess") <= 0)
                        continue;

                if (sd_device_get_property_value(d, "ID_SEAT", &sn) < 0 || isempty(sn))
                        sn = "seat0";

                if (!streq(seat, sn))
                        continue;

                /* In case people mistag devices with nodes, we need to ignore this */
                if (sd_device_get_devname(d, &node) < 0)
                        continue;

                log_device_debug(d, "Found udev node %s for seat %s", node, seat);
                r = set_put_strdup_full(&nodes, &path_hash_ops_free, node);
                if (r < 0)
                        return r;
        }

        /* udev exports "dead" device nodes to allow module on-demand loading,
         * these devices are not known to the kernel at this moment */
        dir = opendir("/run/udev/static_node-tags/uaccess");
        if (dir) {
                FOREACH_DIRENT(de, dir, return -errno) {
                        r = readlinkat_malloc(dirfd(dir), de->d_name, &n);
                        if (r == -ENOENT)
                                continue;
                        if (r < 0) {
                                log_debug_errno(r,
                                                "Unable to read symlink '/run/udev/static_node-tags/uaccess/%s', ignoring: %m",
                                                de->d_name);
                                continue;
                        }

                        log_debug("Found static node %s for seat %s", n, seat);
                        r = set_ensure_consume(&nodes, &path_hash_ops_free, n);
                        if (r < 0)
                                return r;
                }
        }

        r = 0;
        SET_FOREACH(n, nodes) {
                int k;

                log_debug("Changing ACLs at %s for seat %s (uid "UID_FMT"%s"UID_FMT"%s%s)",
                          n, seat, old_uid, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), new_uid,
                          del ? " del" : "", add ? " add" : "");

                k = devnode_acl(n, flush, del, old_uid, add, new_uid);
                if (k == -ENOENT)
                        log_debug("Device %s disappeared while setting ACLs", n);
                else if (k < 0 && r == 0)
                        r = k;
        }

        return r;
}
