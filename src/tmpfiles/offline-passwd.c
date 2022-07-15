/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "chase-symlinks.h"
#include "fd-util.h"
#include "offline-passwd.h"
#include "path-util.h"
#include "user-util.h"

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(uid_gid_hash_ops, char, string_hash_func, string_compare_func, free);

static int open_passwd_file(const char *root, const char *fname, FILE **ret_file) {
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -1;

        fd = chase_symlinks_and_open(fname, root, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC, &p);
        if (fd < 0)
                return fd;

        FILE *f = fdopen(fd, "r");
        if (!f)
                return -errno;

        TAKE_FD(fd);

        log_debug("Reading %s entries from %s...", basename(fname), p);

        *ret_file = f;
        return 0;
}

static int populate_uid_cache(const char *root, Hashmap **ret) {
        _cleanup_(hashmap_freep) Hashmap *cache = NULL;
        int r;

        cache = hashmap_new(&uid_gid_hash_ops);
        if (!cache)
                return -ENOMEM;

        /* The directory list is hardcoded here: /etc is the standard, and rpm-ostree uses /usr/lib. This
         * could be made configurable, but I don't see the point right now. */

        FOREACH_STRING(fname, "/etc/passwd", "/usr/lib/passwd") {
                _cleanup_fclose_ FILE *f = NULL;

                r = open_passwd_file(root, fname, &f);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                struct passwd *pw;
                while ((r = fgetpwent_sane(f, &pw)) > 0) {
                        _cleanup_free_ char *n = NULL;

                        n = strdup(pw->pw_name);
                        if (!n)
                                return -ENOMEM;

                        r = hashmap_put(cache, n, UID_TO_PTR(pw->pw_uid));
                        if (IN_SET(r, 0 -EEXIST))
                                continue;
                        if (r < 0)
                                return r;
                        TAKE_PTR(n);
                }
        }

        *ret = TAKE_PTR(cache);
        return 0;
}

static int populate_gid_cache(const char *root, Hashmap **ret) {
        _cleanup_(hashmap_freep) Hashmap *cache = NULL;
        int r;

        cache = hashmap_new(&uid_gid_hash_ops);
        if (!cache)
                return -ENOMEM;

        FOREACH_STRING(fname, "/etc/group", "/usr/lib/group") {
                _cleanup_fclose_ FILE *f = NULL;

                r = open_passwd_file(root, fname, &f);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                struct group *gr;
                while ((r = fgetgrent_sane(f, &gr)) > 0) {
                        _cleanup_free_ char *n = NULL;

                        n = strdup(gr->gr_name);
                        if (!n)
                                return -ENOMEM;

                        r = hashmap_put(cache, n, GID_TO_PTR(gr->gr_gid));
                        if (IN_SET(r, 0, -EEXIST))
                                continue;
                        if (r < 0)
                                return r;
                        TAKE_PTR(n);
                }
        }

        *ret = TAKE_PTR(cache);
        return 0;
}

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
                r = populate_uid_cache(root, cache);
                if (r < 0)
                        return r;
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
                r = populate_gid_cache(root, cache);
                if (r < 0)
                        return r;
        }

        found = hashmap_get(*cache, group);
        if (!found)
                return -ESRCH;

        *ret_gid = PTR_TO_GID(found);
        return 0;
}
