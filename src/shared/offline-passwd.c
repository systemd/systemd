/* SPDX-License-Identifier: LGPL-2.1+ */

#include "fd-util.h"
#include "offline-passwd.h"
#include "path-util.h"
#include "user-util.h"

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(uid_gid_hash_ops, char, string_hash_func, string_compare_func, free);

int name_to_uid_offline(
                const char *root,
                const char *user,
                uid_t *ret_uid,
                Hashmap **cache) {

        void *found;
        int r;

        assert(user);
        assert(ret_uid);
        assert(cache);

        if (!*cache) {
                _cleanup_(hashmap_freep) Hashmap *uid_by_name = NULL;
                _cleanup_fclose_ FILE *f = NULL;
                struct passwd *pw;
                const char *passwd_path;

                passwd_path = prefix_roota(root, "/etc/passwd");
                f = fopen(passwd_path, "re");
                if (!f)
                        return errno == ENOENT ? -ESRCH : -errno;

                uid_by_name = hashmap_new(&uid_gid_hash_ops);
                if (!uid_by_name)
                        return -ENOMEM;

                while ((r = fgetpwent_sane(f, &pw)) > 0) {
                        _cleanup_free_ char *n = NULL;

                        n = strdup(pw->pw_name);
                        if (!n)
                                return -ENOMEM;

                        r = hashmap_put(uid_by_name, n, UID_TO_PTR(pw->pw_uid));
                        if (r == -EEXIST) {
                                log_warning_errno(r, "Duplicate entry in %s for %s: %m", passwd_path, pw->pw_name);
                                continue;
                        }
                        if (r < 0)
                                return r;

                        TAKE_PTR(n);
                }

                *cache = TAKE_PTR(uid_by_name);
        }

        found = hashmap_get(*cache, user);
        if (!found)
                return -ESRCH;

        *ret_uid = PTR_TO_UID(found);
        return 0;
}

int name_to_gid_offline(
                const char *root,
                const char *group,
                gid_t *ret_gid,
                Hashmap **cache) {

        void *found;
        int r;

        assert(group);
        assert(ret_gid);
        assert(cache);

        if (!*cache) {
                _cleanup_(hashmap_freep) Hashmap *gid_by_name = NULL;
                _cleanup_fclose_ FILE *f = NULL;
                struct group *gr;
                const char *group_path;

                group_path = prefix_roota(root, "/etc/group");
                f = fopen(group_path, "re");
                if (!f)
                        return errno == ENOENT ? -ESRCH : -errno;

                gid_by_name = hashmap_new(&uid_gid_hash_ops);
                if (!gid_by_name)
                        return -ENOMEM;

                while ((r = fgetgrent_sane(f, &gr)) > 0) {
                        _cleanup_free_ char *n = NULL;

                        n = strdup(gr->gr_name);
                        if (!n)
                                return -ENOMEM;

                        r = hashmap_put(gid_by_name, n, GID_TO_PTR(gr->gr_gid));
                        if (r == -EEXIST) {
                                log_warning_errno(r, "Duplicate entry in %s for %s: %m", group_path, gr->gr_name);
                                continue;
                        }
                        if (r < 0)
                                return r;

                        TAKE_PTR(n);
                }

                *cache = TAKE_PTR(gid_by_name);
        }

        found = hashmap_get(*cache, group);
        if (!found)
                return -ESRCH;

        *ret_gid = PTR_TO_GID(found);
        return 0;
}
