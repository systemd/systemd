/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <getopt.h>
#include <grp.h>
#include <gshadow.h>
#include <pwd.h>
#include <shadow.h>
#include <utmp.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "copy.h"
#include "def.h"
#include "fd-util.h"
#include "fileio-label.h"
#include "formats-util.h"
#include "hashmap.h"
#include "path-util.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "uid-range.h"
#include "user-util.h"
#include "utf8.h"
#include "util.h"

typedef enum ItemType {
        ADD_USER = 'u',
        ADD_GROUP = 'g',
        ADD_MEMBER = 'm',
        ADD_RANGE = 'r',
} ItemType;
typedef struct Item {
        ItemType type;

        char *name;
        char *uid_path;
        char *gid_path;
        char *description;
        char *home;

        gid_t gid;
        uid_t uid;

        bool gid_set:1;
        bool uid_set:1;

        bool todo_user:1;
        bool todo_group:1;
} Item;

static char *arg_root = NULL;

static const char conf_file_dirs[] = CONF_PATHS_NULSTR("sysusers.d");

static Hashmap *users = NULL, *groups = NULL;
static Hashmap *todo_uids = NULL, *todo_gids = NULL;
static Hashmap *members = NULL;

static Hashmap *database_uid = NULL, *database_user = NULL;
static Hashmap *database_gid = NULL, *database_group = NULL;

static uid_t search_uid = UID_INVALID;
static UidRange *uid_range = NULL;
static unsigned n_uid_range = 0;

static int load_user_database(void) {
        _cleanup_fclose_ FILE *f = NULL;
        const char *passwd_path;
        struct passwd *pw;
        int r;

        passwd_path = prefix_roota(arg_root, "/etc/passwd");
        f = fopen(passwd_path, "re");
        if (!f)
                return errno == ENOENT ? 0 : -errno;

        r = hashmap_ensure_allocated(&database_user, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&database_uid, NULL);
        if (r < 0)
                return r;

        errno = 0;
        while ((pw = fgetpwent(f))) {
                char *n;
                int k, q;

                n = strdup(pw->pw_name);
                if (!n)
                        return -ENOMEM;

                k = hashmap_put(database_user, n, UID_TO_PTR(pw->pw_uid));
                if (k < 0 && k != -EEXIST) {
                        free(n);
                        return k;
                }

                q = hashmap_put(database_uid, UID_TO_PTR(pw->pw_uid), n);
                if (q < 0 && q != -EEXIST) {
                        if (k < 0)
                                free(n);
                        return q;
                }

                if (q < 0 && k < 0)
                        free(n);

                errno = 0;
        }
        if (!IN_SET(errno, 0, ENOENT))
                return -errno;

        return 0;
}

static int load_group_database(void) {
        _cleanup_fclose_ FILE *f = NULL;
        const char *group_path;
        struct group *gr;
        int r;

        group_path = prefix_roota(arg_root, "/etc/group");
        f = fopen(group_path, "re");
        if (!f)
                return errno == ENOENT ? 0 : -errno;

        r = hashmap_ensure_allocated(&database_group, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&database_gid, NULL);
        if (r < 0)
                return r;

        errno = 0;
        while ((gr = fgetgrent(f))) {
                char *n;
                int k, q;

                n = strdup(gr->gr_name);
                if (!n)
                        return -ENOMEM;

                k = hashmap_put(database_group, n, GID_TO_PTR(gr->gr_gid));
                if (k < 0 && k != -EEXIST) {
                        free(n);
                        return k;
                }

                q = hashmap_put(database_gid, GID_TO_PTR(gr->gr_gid), n);
                if (q < 0 && q != -EEXIST) {
                        if (k < 0)
                                free(n);
                        return q;
                }

                if (q < 0 && k < 0)
                        free(n);

                errno = 0;
        }
        if (!IN_SET(errno, 0, ENOENT))
                return -errno;

        return 0;
}

static int make_backup(const char *target, const char *x) {
        _cleanup_close_ int src = -1;
        _cleanup_fclose_ FILE *dst = NULL;
        char *backup, *temp;
        struct timespec ts[2];
        struct stat st;
        int r;

        src = open(x, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (src < 0) {
                if (errno == ENOENT) /* No backup necessary... */
                        return 0;

                return -errno;
        }

        if (fstat(src, &st) < 0)
                return -errno;

        r = fopen_temporary_label(target, x, &dst, &temp);
        if (r < 0)
                return r;

        r = copy_bytes(src, fileno(dst), (uint64_t) -1, true);
        if (r < 0)
                goto fail;

        /* Don't fail on chmod() or chown(). If it stays owned by us
         * and/or unreadable by others, then it isn't too bad... */

        backup = strjoina(x, "-");

        /* Copy over the access mask */
        if (fchmod(fileno(dst), st.st_mode & 07777) < 0)
                log_warning_errno(errno, "Failed to change mode on %s: %m", backup);

        if (fchown(fileno(dst), st.st_uid, st.st_gid)< 0)
                log_warning_errno(errno, "Failed to change ownership of %s: %m", backup);

        ts[0] = st.st_atim;
        ts[1] = st.st_mtim;
        if (futimens(fileno(dst), ts) < 0)
                log_warning_errno(errno, "Failed to fix access and modification time of %s: %m", backup);

        if (rename(temp, backup) < 0)
                goto fail;

        return 0;

fail:
        unlink(temp);
        return r;
}

static int putgrent_with_members(const struct group *gr, FILE *group) {
        char **a;

        assert(gr);
        assert(group);

        a = hashmap_get(members, gr->gr_name);
        if (a) {
                _cleanup_strv_free_ char **l = NULL;
                bool added = false;
                char **i;

                l = strv_copy(gr->gr_mem);
                if (!l)
                        return -ENOMEM;

                STRV_FOREACH(i, a) {
                        if (strv_find(l, *i))
                                continue;

                        if (strv_extend(&l, *i) < 0)
                                return -ENOMEM;

                        added = true;
                }

                if (added) {
                        struct group t;

                        strv_uniq(l);
                        strv_sort(l);

                        t = *gr;
                        t.gr_mem = l;

                        errno = 0;
                        if (putgrent(&t, group) != 0)
                                return errno > 0 ? -errno : -EIO;

                        return 1;
                }
        }

        errno = 0;
        if (putgrent(gr, group) != 0)
                return errno > 0 ? -errno : -EIO;

        return 0;
}

static int putsgent_with_members(const struct sgrp *sg, FILE *gshadow) {
        char **a;

        assert(sg);
        assert(gshadow);

        a = hashmap_get(members, sg->sg_namp);
        if (a) {
                _cleanup_strv_free_ char **l = NULL;
                bool added = false;
                char **i;

                l = strv_copy(sg->sg_mem);
                if (!l)
                        return -ENOMEM;

                STRV_FOREACH(i, a) {
                        if (strv_find(l, *i))
                                continue;

                        if (strv_extend(&l, *i) < 0)
                                return -ENOMEM;

                        added = true;
                }

                if (added) {
                        struct sgrp t;

                        strv_uniq(l);
                        strv_sort(l);

                        t = *sg;
                        t.sg_mem = l;

                        errno = 0;
                        if (putsgent(&t, gshadow) != 0)
                                return errno > 0 ? -errno : -EIO;

                        return 1;
                }
        }

        errno = 0;
        if (putsgent(sg, gshadow) != 0)
                return errno > 0 ? -errno : -EIO;

        return 0;
}

static int sync_rights(FILE *from, FILE *to) {
        struct stat st;

        if (fstat(fileno(from), &st) < 0)
                return -errno;

        if (fchmod(fileno(to), st.st_mode & 07777) < 0)
                return -errno;

        if (fchown(fileno(to), st.st_uid, st.st_gid) < 0)
                return -errno;

        return 0;
}

static int rename_and_apply_smack(const char *temp_path, const char *dest_path) {
        int r = 0;
        if (rename(temp_path, dest_path) < 0)
                return -errno;

#ifdef SMACK_RUN_LABEL
        r = mac_smack_apply(dest_path, SMACK_ATTR_ACCESS, SMACK_FLOOR_LABEL);
        if (r < 0)
                return r;
#endif
        return r;
}

static int write_files(void) {

        _cleanup_fclose_ FILE *passwd = NULL, *group = NULL, *shadow = NULL, *gshadow = NULL;
        _cleanup_free_ char *passwd_tmp = NULL, *group_tmp = NULL, *shadow_tmp = NULL, *gshadow_tmp = NULL;
        const char *passwd_path = NULL, *group_path = NULL, *shadow_path = NULL, *gshadow_path = NULL;
        bool group_changed = false;
        Iterator iterator;
        Item *i;
        int r;

        if (hashmap_size(todo_gids) > 0 || hashmap_size(members) > 0) {
                _cleanup_fclose_ FILE *original = NULL;

                /* First we update the actual group list file */
                group_path = prefix_roota(arg_root, "/etc/group");
                r = fopen_temporary_label("/etc/group", group_path, &group, &group_tmp);
                if (r < 0)
                        goto finish;

                original = fopen(group_path, "re");
                if (original) {
                        struct group *gr;

                        r = sync_rights(original, group);
                        if (r < 0)
                                goto finish;

                        errno = 0;
                        while ((gr = fgetgrent(original))) {
                                /* Safety checks against name and GID
                                 * collisions. Normally, this should
                                 * be unnecessary, but given that we
                                 * look at the entries anyway here,
                                 * let's make an extra verification
                                 * step that we don't generate
                                 * duplicate entries. */

                                i = hashmap_get(groups, gr->gr_name);
                                if (i && i->todo_group) {
                                        log_error("%s: Group \"%s\" already exists.", group_path, gr->gr_name);
                                        r = -EEXIST;
                                        goto finish;
                                }

                                if (hashmap_contains(todo_gids, GID_TO_PTR(gr->gr_gid))) {
                                        log_error("%s: Detected collision for GID " GID_FMT ".", group_path, gr->gr_gid);
                                        r = -EEXIST;
                                        goto finish;
                                }

                                r = putgrent_with_members(gr, group);
                                if (r < 0)
                                        goto finish;
                                if (r > 0)
                                        group_changed = true;

                                errno = 0;
                        }
                        if (!IN_SET(errno, 0, ENOENT)) {
                                r = -errno;
                                goto finish;
                        }

                } else if (errno != ENOENT) {
                        r = -errno;
                        goto finish;
                } else if (fchmod(fileno(group), 0644) < 0) {
                        r = -errno;
                        goto finish;
                }

                HASHMAP_FOREACH(i, todo_gids, iterator) {
                        struct group n = {
                                .gr_name = i->name,
                                .gr_gid = i->gid,
                                .gr_passwd = (char*) "x",
                        };

                        r = putgrent_with_members(&n, group);
                        if (r < 0)
                                goto finish;

                        group_changed = true;
                }

                r = fflush_and_check(group);
                if (r < 0)
                        goto finish;

                if (original) {
                        fclose(original);
                        original = NULL;
                }

                /* OK, now also update the shadow file for the group list */
                gshadow_path = prefix_roota(arg_root, "/etc/gshadow");
                r = fopen_temporary_label("/etc/gshadow", gshadow_path, &gshadow, &gshadow_tmp);
                if (r < 0)
                        goto finish;

                original = fopen(gshadow_path, "re");
                if (original) {
                        struct sgrp *sg;

                        r = sync_rights(original, gshadow);
                        if (r < 0)
                                goto finish;

                        errno = 0;
                        while ((sg = fgetsgent(original))) {

                                i = hashmap_get(groups, sg->sg_namp);
                                if (i && i->todo_group) {
                                        log_error("%s: Group \"%s\" already exists.", gshadow_path, sg->sg_namp);
                                        r = -EEXIST;
                                        goto finish;
                                }

                                r = putsgent_with_members(sg, gshadow);
                                if (r < 0)
                                        goto finish;
                                if (r > 0)
                                        group_changed = true;

                                errno = 0;
                        }
                        if (!IN_SET(errno, 0, ENOENT)) {
                                r = -errno;
                                goto finish;
                        }

                } else if (errno != ENOENT) {
                        r = -errno;
                        goto finish;
                } else if (fchmod(fileno(gshadow), 0000) < 0) {
                        r = -errno;
                        goto finish;
                }

                HASHMAP_FOREACH(i, todo_gids, iterator) {
                        struct sgrp n = {
                                .sg_namp = i->name,
                                .sg_passwd = (char*) "!!",
                        };

                        r = putsgent_with_members(&n, gshadow);
                        if (r < 0)
                                goto finish;

                        group_changed = true;
                }

                r = fflush_and_check(gshadow);
                if (r < 0)
                        goto finish;
        }

        if (hashmap_size(todo_uids) > 0) {
                _cleanup_fclose_ FILE *original = NULL;
                long lstchg;

                /* First we update the user database itself */
                passwd_path = prefix_roota(arg_root, "/etc/passwd");
                r = fopen_temporary_label("/etc/passwd", passwd_path, &passwd, &passwd_tmp);
                if (r < 0)
                        goto finish;

                original = fopen(passwd_path, "re");
                if (original) {
                        struct passwd *pw;

                        r = sync_rights(original, passwd);
                        if (r < 0)
                                goto finish;

                        errno = 0;
                        while ((pw = fgetpwent(original))) {

                                i = hashmap_get(users, pw->pw_name);
                                if (i && i->todo_user) {
                                        log_error("%s: User \"%s\" already exists.", passwd_path, pw->pw_name);
                                        r = -EEXIST;
                                        goto finish;
                                }

                                if (hashmap_contains(todo_uids, UID_TO_PTR(pw->pw_uid))) {
                                        log_error("%s: Detected collision for UID " UID_FMT ".", passwd_path, pw->pw_uid);
                                        r = -EEXIST;
                                        goto finish;
                                }

                                errno = 0;
                                if (putpwent(pw, passwd) < 0) {
                                        r = errno ? -errno : -EIO;
                                        goto finish;
                                }

                                errno = 0;
                        }
                        if (!IN_SET(errno, 0, ENOENT)) {
                                r = -errno;
                                goto finish;
                        }

                } else if (errno != ENOENT) {
                        r = -errno;
                        goto finish;
                } else if (fchmod(fileno(passwd), 0644) < 0) {
                        r = -errno;
                        goto finish;
                }

                HASHMAP_FOREACH(i, todo_uids, iterator) {
                        struct passwd n = {
                                .pw_name = i->name,
                                .pw_uid = i->uid,
                                .pw_gid = i->gid,
                                .pw_gecos = i->description,

                                /* "x" means the password is stored in
                                 * the shadow file */
                                .pw_passwd = (char*) "x",

                                /* We default to the root directory as home */
                                .pw_dir = i->home ? i->home : (char*) "/",

                                /* Initialize the shell to nologin,
                                 * with one exception: for root we
                                 * patch in something special */
                                .pw_shell = i->uid == 0 ? (char*) "/bin/sh" : (char*) "/sbin/nologin",
                        };

                        errno = 0;
                        if (putpwent(&n, passwd) != 0) {
                                r = errno ? -errno : -EIO;
                                goto finish;
                        }
                }

                r = fflush_and_check(passwd);
                if (r < 0)
                        goto finish;

                if (original) {
                        fclose(original);
                        original = NULL;
                }

                /* The we update the shadow database */
                shadow_path = prefix_roota(arg_root, "/etc/shadow");
                r = fopen_temporary_label("/etc/shadow", shadow_path, &shadow, &shadow_tmp);
                if (r < 0)
                        goto finish;

                lstchg = (long) (now(CLOCK_REALTIME) / USEC_PER_DAY);

                original = fopen(shadow_path, "re");
                if (original) {
                        struct spwd *sp;

                        r = sync_rights(original, shadow);
                        if (r < 0)
                                goto finish;

                        errno = 0;
                        while ((sp = fgetspent(original))) {

                                i = hashmap_get(users, sp->sp_namp);
                                if (i && i->todo_user) {
                                        /* we will update the existing entry */
                                        sp->sp_lstchg = lstchg;

                                        /* only the /etc/shadow stage is left, so we can
                                         * safely remove the item from the todo set */
                                        i->todo_user = false;
                                        hashmap_remove(todo_uids, UID_TO_PTR(i->uid));
                                }

                                errno = 0;
                                if (putspent(sp, shadow) < 0) {
                                        r = errno ? -errno : -EIO;
                                        goto finish;
                                }

                                errno = 0;
                        }
                        if (!IN_SET(errno, 0, ENOENT)) {
                                r = -errno;
                                goto finish;
                        }
                } else if (errno != ENOENT) {
                        r = -errno;
                        goto finish;
                } else if (fchmod(fileno(shadow), 0000) < 0) {
                        r = -errno;
                        goto finish;
                }

                HASHMAP_FOREACH(i, todo_uids, iterator) {
                        struct spwd n = {
                                .sp_namp = i->name,
                                .sp_pwdp = (char*) "!!",
                                .sp_lstchg = lstchg,
                                .sp_min = -1,
                                .sp_max = -1,
                                .sp_warn = -1,
                                .sp_inact = -1,
                                .sp_expire = -1,
                                .sp_flag = (unsigned long) -1, /* this appears to be what everybody does ... */
                        };

                        errno = 0;
                        if (putspent(&n, shadow) != 0) {
                                r = errno ? -errno : -EIO;
                                goto finish;
                        }
                }

                r = fflush_and_check(shadow);
                if (r < 0)
                        goto finish;
        }

        /* Make a backup of the old files */
        if (group_changed) {
                if (group) {
                        r = make_backup("/etc/group", group_path);
                        if (r < 0)
                                goto finish;
                }
                if (gshadow) {
                        r = make_backup("/etc/gshadow", gshadow_path);
                        if (r < 0)
                                goto finish;
                }
        }

        if (passwd) {
                r = make_backup("/etc/passwd", passwd_path);
                if (r < 0)
                        goto finish;
        }
        if (shadow) {
                r = make_backup("/etc/shadow", shadow_path);
                if (r < 0)
                        goto finish;
        }

        /* And make the new files count */
        if (group_changed) {
                if (group) {
                        r = rename_and_apply_smack(group_tmp, group_path);
                        if (r < 0)
                                goto finish;

                        group_tmp = mfree(group_tmp);
                }
                if (gshadow) {
                        r = rename_and_apply_smack(gshadow_tmp, gshadow_path);
                        if (r < 0)
                                goto finish;

                        gshadow_tmp = mfree(gshadow_tmp);
                }
        }

        if (passwd) {
                r = rename_and_apply_smack(passwd_tmp, passwd_path);
                if (r < 0)
                        goto finish;

                passwd_tmp = mfree(passwd_tmp);
        }
        if (shadow) {
                r = rename_and_apply_smack(shadow_tmp, shadow_path);
                if (r < 0)
                        goto finish;

                shadow_tmp = mfree(shadow_tmp);
        }

        r = 0;

finish:
        if (passwd_tmp)
                unlink(passwd_tmp);
        if (shadow_tmp)
                unlink(shadow_tmp);
        if (group_tmp)
                unlink(group_tmp);
        if (gshadow_tmp)
                unlink(gshadow_tmp);

        return r;
}

static int uid_is_ok(uid_t uid, const char *name) {
        struct passwd *p;
        struct group *g;
        const char *n;
        Item *i;

        /* Let's see if we already have assigned the UID a second time */
        if (hashmap_get(todo_uids, UID_TO_PTR(uid)))
                return 0;

        /* Try to avoid using uids that are already used by a group
         * that doesn't have the same name as our new user. */
        i = hashmap_get(todo_gids, GID_TO_PTR(uid));
        if (i && !streq(i->name, name))
                return 0;

        /* Let's check the files directly */
        if (hashmap_contains(database_uid, UID_TO_PTR(uid)))
                return 0;

        n = hashmap_get(database_gid, GID_TO_PTR(uid));
        if (n && !streq(n, name))
                return 0;

        /* Let's also check via NSS, to avoid UID clashes over LDAP and such, just in case */
        if (!arg_root) {
                errno = 0;
                p = getpwuid(uid);
                if (p)
                        return 0;
                if (!IN_SET(errno, 0, ENOENT))
                        return -errno;

                errno = 0;
                g = getgrgid((gid_t) uid);
                if (g) {
                        if (!streq(g->gr_name, name))
                                return 0;
                } else if (!IN_SET(errno, 0, ENOENT))
                        return -errno;
        }

        return 1;
}

static int root_stat(const char *p, struct stat *st) {
        const char *fix;

        fix = prefix_roota(arg_root, p);
        if (stat(fix, st) < 0)
                return -errno;

        return 0;
}

static int read_id_from_file(Item *i, uid_t *_uid, gid_t *_gid) {
        struct stat st;
        bool found_uid = false, found_gid = false;
        uid_t uid = 0;
        gid_t gid = 0;

        assert(i);

        /* First, try to get the gid directly */
        if (_gid && i->gid_path && root_stat(i->gid_path, &st) >= 0) {
                gid = st.st_gid;
                found_gid = true;
        }

        /* Then, try to get the uid directly */
        if ((_uid || (_gid && !found_gid))
            && i->uid_path
            && root_stat(i->uid_path, &st) >= 0) {

                uid = st.st_uid;
                found_uid = true;

                /* If we need the gid, but had no success yet, also derive it from the uid path */
                if (_gid && !found_gid) {
                        gid = st.st_gid;
                        found_gid = true;
                }
        }

        /* If that didn't work yet, then let's reuse the gid as uid */
        if (_uid && !found_uid && i->gid_path) {

                if (found_gid) {
                        uid = (uid_t) gid;
                        found_uid = true;
                } else if (root_stat(i->gid_path, &st) >= 0) {
                        uid = (uid_t) st.st_gid;
                        found_uid = true;
                }
        }

        if (_uid) {
                if (!found_uid)
                        return 0;

                *_uid = uid;
        }

        if (_gid) {
                if (!found_gid)
                        return 0;

                *_gid = gid;
        }

        return 1;
}

static int add_user(Item *i) {
        void *z;
        int r;

        assert(i);

        /* Check the database directly */
        z = hashmap_get(database_user, i->name);
        if (z) {
                log_debug("User %s already exists.", i->name);
                i->uid = PTR_TO_UID(z);
                i->uid_set = true;
                return 0;
        }

        if (!arg_root) {
                struct passwd *p;

                /* Also check NSS */
                errno = 0;
                p = getpwnam(i->name);
                if (p) {
                        log_debug("User %s already exists.", i->name);
                        i->uid = p->pw_uid;
                        i->uid_set = true;

                        r = free_and_strdup(&i->description, p->pw_gecos);
                        if (r < 0)
                                return log_oom();

                        return 0;
                }
                if (!IN_SET(errno, 0, ENOENT))
                        return log_error_errno(errno, "Failed to check if user %s already exists: %m", i->name);
        }

        /* Try to use the suggested numeric uid */
        if (i->uid_set) {
                r = uid_is_ok(i->uid, i->name);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify uid " UID_FMT ": %m", i->uid);
                if (r == 0) {
                        log_debug("Suggested user ID " UID_FMT " for %s already used.", i->uid, i->name);
                        i->uid_set = false;
                }
        }

        /* If that didn't work, try to read it from the specified path */
        if (!i->uid_set) {
                uid_t c;

                if (read_id_from_file(i, &c, NULL) > 0) {

                        if (c <= 0 || !uid_range_contains(uid_range, n_uid_range, c))
                                log_debug("User ID " UID_FMT " of file not suitable for %s.", c, i->name);
                        else {
                                r = uid_is_ok(c, i->name);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to verify uid " UID_FMT ": %m", i->uid);
                                else if (r > 0) {
                                        i->uid = c;
                                        i->uid_set = true;
                                } else
                                        log_debug("User ID " UID_FMT " of file for %s is already used.", c, i->name);
                        }
                }
        }

        /* Otherwise, try to reuse the group ID */
        if (!i->uid_set && i->gid_set) {
                r = uid_is_ok((uid_t) i->gid, i->name);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify uid " UID_FMT ": %m", i->uid);
                if (r > 0) {
                        i->uid = (uid_t) i->gid;
                        i->uid_set = true;
                }
        }

        /* And if that didn't work either, let's try to find a free one */
        if (!i->uid_set) {
                for (;;) {
                        r = uid_range_next_lower(uid_range, n_uid_range, &search_uid);
                        if (r < 0) {
                                log_error("No free user ID available for %s.", i->name);
                                return r;
                        }

                        r = uid_is_ok(search_uid, i->name);
                        if (r < 0)
                                return log_error_errno(r, "Failed to verify uid " UID_FMT ": %m", i->uid);
                        else if (r > 0)
                                break;
                }

                i->uid_set = true;
                i->uid = search_uid;
        }

        r = hashmap_ensure_allocated(&todo_uids, NULL);
        if (r < 0)
                return log_oom();

        r = hashmap_put(todo_uids, UID_TO_PTR(i->uid), i);
        if (r < 0)
                return log_oom();

        i->todo_user = true;
        log_info("Creating user %s (%s) with uid " UID_FMT " and gid " GID_FMT ".", i->name, strna(i->description), i->uid, i->gid);

        return 0;
}

static int gid_is_ok(gid_t gid) {
        struct group *g;
        struct passwd *p;

        if (hashmap_get(todo_gids, GID_TO_PTR(gid)))
                return 0;

        /* Avoid reusing gids that are already used by a different user */
        if (hashmap_get(todo_uids, UID_TO_PTR(gid)))
                return 0;

        if (hashmap_contains(database_gid, GID_TO_PTR(gid)))
                return 0;

        if (hashmap_contains(database_uid, UID_TO_PTR(gid)))
                return 0;

        if (!arg_root) {
                errno = 0;
                g = getgrgid(gid);
                if (g)
                        return 0;
                if (!IN_SET(errno, 0, ENOENT))
                        return -errno;

                errno = 0;
                p = getpwuid((uid_t) gid);
                if (p)
                        return 0;
                if (!IN_SET(errno, 0, ENOENT))
                        return -errno;
        }

        return 1;
}

static int add_group(Item *i) {
        void *z;
        int r;

        assert(i);

        /* Check the database directly */
        z = hashmap_get(database_group, i->name);
        if (z) {
                log_debug("Group %s already exists.", i->name);
                i->gid = PTR_TO_GID(z);
                i->gid_set = true;
                return 0;
        }

        /* Also check NSS */
        if (!arg_root) {
                struct group *g;

                errno = 0;
                g = getgrnam(i->name);
                if (g) {
                        log_debug("Group %s already exists.", i->name);
                        i->gid = g->gr_gid;
                        i->gid_set = true;
                        return 0;
                }
                if (!IN_SET(errno, 0, ENOENT))
                        return log_error_errno(errno, "Failed to check if group %s already exists: %m", i->name);
        }

        /* Try to use the suggested numeric gid */
        if (i->gid_set) {
                r = gid_is_ok(i->gid);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify gid " GID_FMT ": %m", i->gid);
                if (r == 0) {
                        log_debug("Suggested group ID " GID_FMT " for %s already used.", i->gid, i->name);
                        i->gid_set = false;
                }
        }

        /* Try to reuse the numeric uid, if there's one */
        if (!i->gid_set && i->uid_set) {
                r = gid_is_ok((gid_t) i->uid);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify gid " GID_FMT ": %m", i->gid);
                if (r > 0) {
                        i->gid = (gid_t) i->uid;
                        i->gid_set = true;
                }
        }

        /* If that didn't work, try to read it from the specified path */
        if (!i->gid_set) {
                gid_t c;

                if (read_id_from_file(i, NULL, &c) > 0) {

                        if (c <= 0 || !uid_range_contains(uid_range, n_uid_range, c))
                                log_debug("Group ID " GID_FMT " of file not suitable for %s.", c, i->name);
                        else {
                                r = gid_is_ok(c);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to verify gid " GID_FMT ": %m", i->gid);
                                else if (r > 0) {
                                        i->gid = c;
                                        i->gid_set = true;
                                } else
                                        log_debug("Group ID " GID_FMT " of file for %s already used.", c, i->name);
                        }
                }
        }

        /* And if that didn't work either, let's try to find a free one */
        if (!i->gid_set) {
                for (;;) {
                        /* We look for new GIDs in the UID pool! */
                        r = uid_range_next_lower(uid_range, n_uid_range, &search_uid);
                        if (r < 0) {
                                log_error("No free group ID available for %s.", i->name);
                                return r;
                        }

                        r = gid_is_ok(search_uid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to verify gid " GID_FMT ": %m", i->gid);
                        else if (r > 0)
                                break;
                }

                i->gid_set = true;
                i->gid = search_uid;
        }

        r = hashmap_ensure_allocated(&todo_gids, NULL);
        if (r < 0)
                return log_oom();

        r = hashmap_put(todo_gids, GID_TO_PTR(i->gid), i);
        if (r < 0)
                return log_oom();

        i->todo_group = true;
        log_info("Creating group %s with gid " GID_FMT ".", i->name, i->gid);

        return 0;
}

static int process_item(Item *i) {
        int r;

        assert(i);

        switch (i->type) {

        case ADD_USER:
                r = add_group(i);
                if (r < 0)
                        return r;

                return add_user(i);

        case ADD_GROUP: {
                Item *j;

                j = hashmap_get(users, i->name);
                if (j) {
                        /* There's already user to be created for this
                         * name, let's process that in one step */

                        if (i->gid_set) {
                                j->gid = i->gid;
                                j->gid_set = true;
                        }

                        if (i->gid_path) {
                                r = free_and_strdup(&j->gid_path, i->gid_path);
                                if (r < 0)
                                        return log_oom();
                        }

                        return 0;
                }

                return add_group(i);
        }

        default:
                assert_not_reached("Unknown item type");
        }
}

static void item_free(Item *i) {

        if (!i)
                return;

        free(i->name);
        free(i->uid_path);
        free(i->gid_path);
        free(i->description);
        free(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Item*, item_free);

static int add_implicit(void) {
        char *g, **l;
        Iterator iterator;
        int r;

        /* Implicitly create additional users and groups, if they were listed in "m" lines */

        HASHMAP_FOREACH_KEY(l, g, members, iterator) {
                Item *i;
                char **m;

                i = hashmap_get(groups, g);
                if (!i) {
                        _cleanup_(item_freep) Item *j = NULL;

                        r = hashmap_ensure_allocated(&groups, &string_hash_ops);
                        if (r < 0)
                                return log_oom();

                        j = new0(Item, 1);
                        if (!j)
                                return log_oom();

                        j->type = ADD_GROUP;
                        j->name = strdup(g);
                        if (!j->name)
                                return log_oom();

                        r = hashmap_put(groups, j->name, j);
                        if (r < 0)
                                return log_oom();

                        log_debug("Adding implicit group '%s' due to m line", j->name);
                        j = NULL;
                }

                STRV_FOREACH(m, l) {

                        i = hashmap_get(users, *m);
                        if (!i) {
                                _cleanup_(item_freep) Item *j = NULL;

                                r = hashmap_ensure_allocated(&users, &string_hash_ops);
                                if (r < 0)
                                        return log_oom();

                                j = new0(Item, 1);
                                if (!j)
                                        return log_oom();

                                j->type = ADD_USER;
                                j->name = strdup(*m);
                                if (!j->name)
                                        return log_oom();

                                r = hashmap_put(users, j->name, j);
                                if (r < 0)
                                        return log_oom();

                                log_debug("Adding implicit user '%s' due to m line", j->name);
                                j = NULL;
                        }
                }
        }

        return 0;
}

static bool item_equal(Item *a, Item *b) {
        assert(a);
        assert(b);

        if (a->type != b->type)
                return false;

        if (!streq_ptr(a->name, b->name))
                return false;

        if (!streq_ptr(a->uid_path, b->uid_path))
                return false;

        if (!streq_ptr(a->gid_path, b->gid_path))
                return false;

        if (!streq_ptr(a->description, b->description))
                return false;

        if (a->uid_set != b->uid_set)
                return false;

        if (a->uid_set && a->uid != b->uid)
                return false;

        if (a->gid_set != b->gid_set)
                return false;

        if (a->gid_set && a->gid != b->gid)
                return false;

        if (!streq_ptr(a->home, b->home))
                return false;

        return true;
}

static bool valid_user_group_name(const char *u) {
        const char *i;
        long sz;

        if (isempty(u))
                return false;

        if (!(u[0] >= 'a' && u[0] <= 'z') &&
            !(u[0] >= 'A' && u[0] <= 'Z') &&
            u[0] != '_')
                return false;

        for (i = u+1; *i; i++) {
                if (!(*i >= 'a' && *i <= 'z') &&
                    !(*i >= 'A' && *i <= 'Z') &&
                    !(*i >= '0' && *i <= '9') &&
                    *i != '_' &&
                    *i != '-')
                        return false;
        }

        sz = sysconf(_SC_LOGIN_NAME_MAX);
        assert_se(sz > 0);

        if ((size_t) (i-u) > (size_t) sz)
                return false;

        if ((size_t) (i-u) > UT_NAMESIZE - 1)
                return false;

        return true;
}

static bool valid_gecos(const char *d) {

        if (!d)
                return false;

        if (!utf8_is_valid(d))
                return false;

        if (string_has_cc(d, NULL))
                return false;

        /* Colons are used as field separators, and hence not OK */
        if (strchr(d, ':'))
                return false;

        return true;
}

static bool valid_home(const char *p) {

        if (isempty(p))
                return false;

        if (!utf8_is_valid(p))
                return false;

        if (string_has_cc(p, NULL))
                return false;

        if (!path_is_absolute(p))
                return false;

        if (!path_is_safe(p))
                return false;

        /* Colons are used as field separators, and hence not OK */
        if (strchr(p, ':'))
                return false;

        return true;
}

static int parse_line(const char *fname, unsigned line, const char *buffer) {

        static const Specifier specifier_table[] = {
                { 'm', specifier_machine_id, NULL },
                { 'b', specifier_boot_id, NULL },
                { 'H', specifier_host_name, NULL },
                { 'v', specifier_kernel_release, NULL },
                {}
        };

        _cleanup_free_ char *action = NULL, *name = NULL, *id = NULL, *resolved_name = NULL, *resolved_id = NULL, *description = NULL, *home = NULL;
        _cleanup_(item_freep) Item *i = NULL;
        Item *existing;
        Hashmap *h;
        int r;
        const char *p;

        assert(fname);
        assert(line >= 1);
        assert(buffer);

        /* Parse columns */
        p = buffer;
        r = extract_many_words(&p, NULL, EXTRACT_QUOTES, &action, &name, &id, &description, &home, NULL);
        if (r < 0) {
                log_error("[%s:%u] Syntax error.", fname, line);
                return r;
        }
        if (r < 2) {
                log_error("[%s:%u] Missing action and name columns.", fname, line);
                return -EINVAL;
        }
        if (!isempty(p)) {
                log_error("[%s:%u] Trailing garbage.", fname, line);
                return -EINVAL;
        }

        /* Verify action */
        if (strlen(action) != 1) {
                log_error("[%s:%u] Unknown modifier '%s'", fname, line, action);
                return -EINVAL;
        }

        if (!IN_SET(action[0], ADD_USER, ADD_GROUP, ADD_MEMBER, ADD_RANGE)) {
                log_error("[%s:%u] Unknown command type '%c'.", fname, line, action[0]);
                return -EBADMSG;
        }

        /* Verify name */
        if (isempty(name) || streq(name, "-"))
                name = mfree(name);

        if (name) {
                r = specifier_printf(name, specifier_table, NULL, &resolved_name);
                if (r < 0) {
                        log_error("[%s:%u] Failed to replace specifiers: %s", fname, line, name);
                        return r;
                }

                if (!valid_user_group_name(resolved_name)) {
                        log_error("[%s:%u] '%s' is not a valid user or group name.", fname, line, resolved_name);
                        return -EINVAL;
                }
        }

        /* Verify id */
        if (isempty(id) || streq(id, "-"))
                id = mfree(id);

        if (id) {
                r = specifier_printf(id, specifier_table, NULL, &resolved_id);
                if (r < 0) {
                        log_error("[%s:%u] Failed to replace specifiers: %s", fname, line, name);
                        return r;
                }
        }

        /* Verify description */
        if (isempty(description) || streq(description, "-"))
                description = mfree(description);

        if (description) {
                if (!valid_gecos(description)) {
                        log_error("[%s:%u] '%s' is not a valid GECOS field.", fname, line, description);
                        return -EINVAL;
                }
        }

        /* Verify home */
        if (isempty(home) || streq(home, "-"))
                home = mfree(home);

        if (home) {
                if (!valid_home(home)) {
                        log_error("[%s:%u] '%s' is not a valid home directory field.", fname, line, home);
                        return -EINVAL;
                }
        }

        switch (action[0]) {

        case ADD_RANGE:
                if (resolved_name) {
                        log_error("[%s:%u] Lines of type 'r' don't take a name field.", fname, line);
                        return -EINVAL;
                }

                if (!resolved_id) {
                        log_error("[%s:%u] Lines of type 'r' require a ID range in the third field.", fname, line);
                        return -EINVAL;
                }

                if (description) {
                        log_error("[%s:%u] Lines of type 'r' don't take a GECOS field.", fname, line);
                        return -EINVAL;
                }

                if (home) {
                        log_error("[%s:%u] Lines of type 'r' don't take a home directory field.", fname, line);
                        return -EINVAL;
                }

                r = uid_range_add_str(&uid_range, &n_uid_range, resolved_id);
                if (r < 0) {
                        log_error("[%s:%u] Invalid UID range %s.", fname, line, resolved_id);
                        return -EINVAL;
                }

                return 0;

        case ADD_MEMBER: {
                char **l;

                /* Try to extend an existing member or group item */
                if (!name) {
                        log_error("[%s:%u] Lines of type 'm' require a user name in the second field.", fname, line);
                        return -EINVAL;
                }

                if (!resolved_id) {
                        log_error("[%s:%u] Lines of type 'm' require a group name in the third field.", fname, line);
                        return -EINVAL;
                }

                if (!valid_user_group_name(resolved_id)) {
                        log_error("[%s:%u] '%s' is not a valid user or group name.", fname, line, resolved_id);
                        return -EINVAL;
                }

                if (description) {
                        log_error("[%s:%u] Lines of type 'm' don't take a GECOS field.", fname, line);
                        return -EINVAL;
                }

                if (home) {
                        log_error("[%s:%u] Lines of type 'm' don't take a home directory field.", fname, line);
                        return -EINVAL;
                }

                r = hashmap_ensure_allocated(&members, &string_hash_ops);
                if (r < 0)
                        return log_oom();

                l = hashmap_get(members, resolved_id);
                if (l) {
                        /* A list for this group name already exists, let's append to it */
                        r = strv_push(&l, resolved_name);
                        if (r < 0)
                                return log_oom();

                        resolved_name = NULL;

                        assert_se(hashmap_update(members, resolved_id, l) >= 0);
                } else {
                        /* No list for this group name exists yet, create one */

                        l = new0(char *, 2);
                        if (!l)
                                return -ENOMEM;

                        l[0] = resolved_name;
                        l[1] = NULL;

                        r = hashmap_put(members, resolved_id, l);
                        if (r < 0) {
                                free(l);
                                return log_oom();
                        }

                        resolved_id = resolved_name = NULL;
                }

                return 0;
        }

        case ADD_USER:
                if (!name) {
                        log_error("[%s:%u] Lines of type 'u' require a user name in the second field.", fname, line);
                        return -EINVAL;
                }

                r = hashmap_ensure_allocated(&users, &string_hash_ops);
                if (r < 0)
                        return log_oom();

                i = new0(Item, 1);
                if (!i)
                        return log_oom();

                if (resolved_id) {
                        if (path_is_absolute(resolved_id)) {
                                i->uid_path = resolved_id;
                                resolved_id = NULL;

                                path_kill_slashes(i->uid_path);
                        } else {
                                r = parse_uid(resolved_id, &i->uid);
                                if (r < 0) {
                                        log_error("Failed to parse UID: %s", id);
                                        return -EBADMSG;
                                }

                                i->uid_set = true;
                        }
                }

                i->description = description;
                description = NULL;

                i->home = home;
                home = NULL;

                h = users;
                break;

        case ADD_GROUP:
                if (!name) {
                        log_error("[%s:%u] Lines of type 'g' require a user name in the second field.", fname, line);
                        return -EINVAL;
                }

                if (description) {
                        log_error("[%s:%u] Lines of type 'g' don't take a GECOS field.", fname, line);
                        return -EINVAL;
                }

                if (home) {
                        log_error("[%s:%u] Lines of type 'g' don't take a home directory field.", fname, line);
                        return -EINVAL;
                }

                r = hashmap_ensure_allocated(&groups, &string_hash_ops);
                if (r < 0)
                        return log_oom();

                i = new0(Item, 1);
                if (!i)
                        return log_oom();

                if (resolved_id) {
                        if (path_is_absolute(resolved_id)) {
                                i->gid_path = resolved_id;
                                resolved_id = NULL;

                                path_kill_slashes(i->gid_path);
                        } else {
                                r = parse_gid(resolved_id, &i->gid);
                                if (r < 0) {
                                        log_error("Failed to parse GID: %s", id);
                                        return -EBADMSG;
                                }

                                i->gid_set = true;
                        }
                }

                h = groups;
                break;

        default:
                return -EBADMSG;
        }

        i->type = action[0];
        i->name = resolved_name;
        resolved_name = NULL;

        existing = hashmap_get(h, i->name);
        if (existing) {

                /* Two identical items are fine */
                if (!item_equal(existing, i))
                        log_warning("Two or more conflicting lines for %s configured, ignoring.", i->name);

                return 0;
        }

        r = hashmap_put(h, i->name, i);
        if (r < 0)
                return log_oom();

        i = NULL;
        return 0;
}

static int read_config_file(const char *fn, bool ignore_enoent) {
        _cleanup_fclose_ FILE *rf = NULL;
        FILE *f = NULL;
        char line[LINE_MAX];
        unsigned v = 0;
        int r = 0;

        assert(fn);

        if (streq(fn, "-"))
                f = stdin;
        else {
                r = search_and_fopen_nulstr(fn, "re", arg_root, conf_file_dirs, &rf);
                if (r < 0) {
                        if (ignore_enoent && r == -ENOENT)
                                return 0;

                        return log_error_errno(r, "Failed to open '%s', ignoring: %m", fn);
                }

                f = rf;
        }

        FOREACH_LINE(line, f, break) {
                char *l;
                int k;

                v++;

                l = strstrip(line);
                if (*l == '#' || *l == 0)
                        continue;

                k = parse_line(fn, v, l);
                if (k < 0 && r == 0)
                        r = k;
        }

        if (ferror(f)) {
                log_error_errno(errno, "Failed to read from file %s: %m", fn);
                if (r == 0)
                        r = -EIO;
        }

        return r;
}

static void free_database(Hashmap *by_name, Hashmap *by_id) {
        char *name;

        for (;;) {
                name = hashmap_first(by_id);
                if (!name)
                        break;

                hashmap_remove(by_name, name);

                hashmap_steal_first_key(by_id);
                free(name);
        }

        while ((name = hashmap_steal_first_key(by_name)))
                free(name);

        hashmap_free(by_name);
        hashmap_free(by_id);
}

static void help(void) {
        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Creates system user accounts.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --root=PATH            Operate on an alternate filesystem root\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_ROOT,
        };

        static const struct option options[] = {
                { "help",    no_argument,       NULL, 'h'         },
                { "version", no_argument,       NULL, ARG_VERSION },
                { "root",    required_argument, NULL, ARG_ROOT    },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_ROOT:
                        r = parse_path_argument_and_warn(optarg, true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

int main(int argc, char *argv[]) {

        _cleanup_close_ int lock = -1;
        Iterator iterator;
        int r, k;
        Item *i;
        char *n;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        r = mac_selinux_init();
        if (r < 0) {
                log_error_errno(r, "SELinux setup failed: %m");
                goto finish;
        }

        if (optind < argc) {
                int j;

                for (j = optind; j < argc; j++) {
                        k = read_config_file(argv[j], false);
                        if (k < 0 && r == 0)
                                r = k;
                }
        } else {
                _cleanup_strv_free_ char **files = NULL;
                char **f;

                r = conf_files_list_nulstr(&files, ".conf", arg_root, conf_file_dirs);
                if (r < 0) {
                        log_error_errno(r, "Failed to enumerate sysusers.d files: %m");
                        goto finish;
                }

                STRV_FOREACH(f, files) {
                        k = read_config_file(*f, true);
                        if (k < 0 && r == 0)
                                r = k;
                }
        }

        if (!uid_range) {
                /* Default to default range of 1..SYSTEMD_UID_MAX */
                r = uid_range_add(&uid_range, &n_uid_range, 1, SYSTEM_UID_MAX);
                if (r < 0) {
                        log_oom();
                        goto finish;
                }
        }

        r = add_implicit();
        if (r < 0)
                goto finish;

        lock = take_etc_passwd_lock(arg_root);
        if (lock < 0) {
                log_error_errno(lock, "Failed to take lock: %m");
                goto finish;
        }

        r = load_user_database();
        if (r < 0) {
                log_error_errno(r, "Failed to load user database: %m");
                goto finish;
        }

        r = load_group_database();
        if (r < 0) {
                log_error_errno(r, "Failed to read group database: %m");
                goto finish;
        }

        HASHMAP_FOREACH(i, groups, iterator)
                process_item(i);

        HASHMAP_FOREACH(i, users, iterator)
                process_item(i);

        r = write_files();
        if (r < 0)
                log_error_errno(r, "Failed to write files: %m");

finish:
        while ((i = hashmap_steal_first(groups)))
                item_free(i);

        while ((i = hashmap_steal_first(users)))
                item_free(i);

        while ((n = hashmap_first_key(members))) {
                strv_free(hashmap_steal_first(members));
                free(n);
        }

        hashmap_free(groups);
        hashmap_free(users);
        hashmap_free(members);
        hashmap_free(todo_uids);
        hashmap_free(todo_gids);

        free_database(database_user, database_uid);
        free_database(database_group, database_gid);

        free(arg_root);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
