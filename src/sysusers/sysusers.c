/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>
#include <utmp.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "copy.h"
#include "def.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "main-func.h"
#include "pager.h"
#include "path-util.h"
#include "pretty-print.h"
#include "set.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util-label.h"
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
        char *shell;

        gid_t gid;
        uid_t uid;

        bool gid_set:1;

        /* When set the group with the specified gid must exist
         * and the check if a uid clashes with the gid is skipped.
         */
        bool id_set_strict:1;

        bool uid_set:1;

        bool todo_user:1;
        bool todo_group:1;
} Item;

static char *arg_root = NULL;
static bool arg_cat_config = false;
static const char *arg_replace = NULL;
static bool arg_inline = false;
static PagerFlags arg_pager_flags = 0;

static OrderedHashmap *users = NULL, *groups = NULL;
static OrderedHashmap *todo_uids = NULL, *todo_gids = NULL;
static OrderedHashmap *members = NULL;

static Hashmap *database_by_uid = NULL, *database_by_username = NULL;
static Hashmap *database_by_gid = NULL, *database_by_groupname = NULL;
static Set *database_users = NULL, *database_groups = NULL;

static uid_t search_uid = UID_INVALID;
static UidRange *uid_range = NULL;
static unsigned n_uid_range = 0;

STATIC_DESTRUCTOR_REGISTER(groups, ordered_hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(users, ordered_hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(members, ordered_hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(todo_uids, ordered_hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(todo_gids, ordered_hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(database_by_uid, hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(database_by_username, hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(database_users, set_free_freep);
STATIC_DESTRUCTOR_REGISTER(database_by_gid, hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(database_by_groupname, hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(database_groups, set_free_freep);
STATIC_DESTRUCTOR_REGISTER(uid_range, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);

static int load_user_database(void) {
        _cleanup_fclose_ FILE *f = NULL;
        const char *passwd_path;
        struct passwd *pw;
        int r;

        passwd_path = prefix_roota(arg_root, "/etc/passwd");
        f = fopen(passwd_path, "re");
        if (!f)
                return errno == ENOENT ? 0 : -errno;

        r = hashmap_ensure_allocated(&database_by_username, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&database_by_uid, NULL);
        if (r < 0)
                return r;

        r = set_ensure_allocated(&database_users, NULL);
        if (r < 0)
                return r;

        while ((r = fgetpwent_sane(f, &pw)) > 0) {
                char *n;
                int k, q;

                n = strdup(pw->pw_name);
                if (!n)
                        return -ENOMEM;

                k = set_put(database_users, n);
                if (k < 0) {
                        free(n);
                        return k;
                }

                k = hashmap_put(database_by_username, n, UID_TO_PTR(pw->pw_uid));
                if (k < 0 && k != -EEXIST)
                        return k;

                q = hashmap_put(database_by_uid, UID_TO_PTR(pw->pw_uid), n);
                if (q < 0 && q != -EEXIST)
                        return q;
        }
        return r;
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

        r = hashmap_ensure_allocated(&database_by_groupname, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&database_by_gid, NULL);
        if (r < 0)
                return r;

        r = set_ensure_allocated(&database_groups, NULL);
        if (r < 0)
                return r;

        while ((r = fgetgrent_sane(f, &gr)) > 0) {
                char *n;
                int k, q;

                n = strdup(gr->gr_name);
                if (!n)
                        return -ENOMEM;

                k = set_put(database_groups, n);
                if (k < 0) {
                        free(n);
                        return k;
                }

                k = hashmap_put(database_by_groupname, n, GID_TO_PTR(gr->gr_gid));
                if (k < 0 && k != -EEXIST)
                        return k;

                q = hashmap_put(database_by_gid, GID_TO_PTR(gr->gr_gid), n);
                if (q < 0 && q != -EEXIST)
                        return q;
        }
        return r;
}

static int make_backup(const char *target, const char *x) {
        _cleanup_close_ int src = -1;
        _cleanup_fclose_ FILE *dst = NULL;
        _cleanup_free_ char *temp = NULL;
        char *backup;
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

        r = copy_bytes(src, fileno(dst), (uint64_t) -1, COPY_REFLINK);
        if (r < 0)
                goto fail;

        /* Don't fail on chmod() or chown(). If it stays owned by us
         * and/or unreadable by others, then it isn't too bad... */

        backup = strjoina(x, "-");

        /* Copy over the access mask */
        r = fchmod_and_chown(fileno(dst), st.st_mode & 07777, st.st_uid, st.st_gid);
        if (r < 0)
                log_warning_errno(r, "Failed to change access mode or ownership of %s: %m", backup);

        ts[0] = st.st_atim;
        ts[1] = st.st_mtim;
        if (futimens(fileno(dst), ts) < 0)
                log_warning_errno(errno, "Failed to fix access and modification time of %s: %m", backup);

        r = fflush_sync_and_check(dst);
        if (r < 0)
                goto fail;

        if (rename(temp, backup) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        (void) unlink(temp);
        return r;
}

static int putgrent_with_members(const struct group *gr, FILE *group) {
        char **a;

        assert(gr);
        assert(group);

        a = ordered_hashmap_get(members, gr->gr_name);
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
                        int r;

                        strv_uniq(l);
                        strv_sort(l);

                        t = *gr;
                        t.gr_mem = l;

                        r = putgrent_sane(&t, group);
                        return r < 0 ? r : 1;
                }
        }

        return putgrent_sane(gr, group);
}

#if ENABLE_GSHADOW
static int putsgent_with_members(const struct sgrp *sg, FILE *gshadow) {
        char **a;

        assert(sg);
        assert(gshadow);

        a = ordered_hashmap_get(members, sg->sg_namp);
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
                        int r;

                        strv_uniq(l);
                        strv_sort(l);

                        t = *sg;
                        t.sg_mem = l;

                        r = putsgent_sane(&t, gshadow);
                        return r < 0 ? r : 1;
                }
        }

        return putsgent_sane(sg, gshadow);
}
#endif

static int sync_rights(FILE *from, FILE *to) {
        struct stat st;

        if (fstat(fileno(from), &st) < 0)
                return -errno;

        return fchmod_and_chown(fileno(to), st.st_mode & 07777, st.st_uid, st.st_gid);
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

static const char* default_shell(uid_t uid) {
        return uid == 0 ? "/bin/sh" : NOLOGIN;
}

static int write_temporary_passwd(const char *passwd_path, FILE **tmpfile, char **tmpfile_path) {
        _cleanup_fclose_ FILE *original = NULL, *passwd = NULL;
        _cleanup_(unlink_and_freep) char *passwd_tmp = NULL;
        struct passwd *pw = NULL;
        Iterator iterator;
        Item *i;
        int r;

        if (ordered_hashmap_size(todo_uids) == 0)
                return 0;

        r = fopen_temporary_label("/etc/passwd", passwd_path, &passwd, &passwd_tmp);
        if (r < 0)
                return r;

        original = fopen(passwd_path, "re");
        if (original) {

                r = sync_rights(original, passwd);
                if (r < 0)
                        return r;

                while ((r = fgetpwent_sane(original, &pw)) > 0) {

                        i = ordered_hashmap_get(users, pw->pw_name);
                        if (i && i->todo_user)
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: User \"%s\" already exists.",
                                                       passwd_path, pw->pw_name);

                        if (ordered_hashmap_contains(todo_uids, UID_TO_PTR(pw->pw_uid)))
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: Detected collision for UID " UID_FMT ".",
                                                       passwd_path, pw->pw_uid);

                        /* Make sure we keep the NIS entries (if any) at the end. */
                        if (IN_SET(pw->pw_name[0], '+', '-'))
                                break;

                        r = putpwent_sane(pw, passwd);
                        if (r < 0)
                                return r;
                }
                if (r < 0)
                        return r;

        } else {
                if (errno != ENOENT)
                        return -errno;
                if (fchmod(fileno(passwd), 0644) < 0)
                        return -errno;
        }

        ORDERED_HASHMAP_FOREACH(i, todo_uids, iterator) {
                struct passwd n = {
                        .pw_name = i->name,
                        .pw_uid = i->uid,
                        .pw_gid = i->gid,
                        .pw_gecos = i->description,

                        /* "x" means the password is stored in the shadow file */
                        .pw_passwd = (char*) "x",

                        /* We default to the root directory as home */
                        .pw_dir = i->home ?: (char*) "/",

                        /* Initialize the shell to nologin, with one exception:
                         * for root we patch in something special */
                        .pw_shell = i->shell ?: (char*) default_shell(i->uid),
                };

                r = putpwent_sane(&n, passwd);
                if (r < 0)
                        return r;
        }

        /* Append the remaining NIS entries if any */
        while (pw) {
                r = putpwent_sane(pw, passwd);
                if (r < 0)
                        return r;

                r = fgetpwent_sane(original, &pw);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
        }

        r = fflush_and_check(passwd);
        if (r < 0)
                return r;

        *tmpfile = TAKE_PTR(passwd);
        *tmpfile_path = TAKE_PTR(passwd_tmp);

        return 0;
}

static int write_temporary_shadow(const char *shadow_path, FILE **tmpfile, char **tmpfile_path) {
        _cleanup_fclose_ FILE *original = NULL, *shadow = NULL;
        _cleanup_(unlink_and_freep) char *shadow_tmp = NULL;
        struct spwd *sp = NULL;
        Iterator iterator;
        long lstchg;
        Item *i;
        int r;

        if (ordered_hashmap_size(todo_uids) == 0)
                return 0;

        r = fopen_temporary_label("/etc/shadow", shadow_path, &shadow, &shadow_tmp);
        if (r < 0)
                return r;

        lstchg = (long) (now(CLOCK_REALTIME) / USEC_PER_DAY);

        original = fopen(shadow_path, "re");
        if (original) {

                r = sync_rights(original, shadow);
                if (r < 0)
                        return r;

                while ((r = fgetspent_sane(original, &sp)) > 0) {

                        i = ordered_hashmap_get(users, sp->sp_namp);
                        if (i && i->todo_user) {
                                /* we will update the existing entry */
                                sp->sp_lstchg = lstchg;

                                /* only the /etc/shadow stage is left, so we can
                                 * safely remove the item from the todo set */
                                i->todo_user = false;
                                ordered_hashmap_remove(todo_uids, UID_TO_PTR(i->uid));
                        }

                        /* Make sure we keep the NIS entries (if any) at the end. */
                        if (IN_SET(sp->sp_namp[0], '+', '-'))
                                break;

                        r = putspent_sane(sp, shadow);
                        if (r < 0)
                                return r;
                }
                if (r < 0)
                        return r;

        } else {
                if (errno != ENOENT)
                        return -errno;
                if (fchmod(fileno(shadow), 0000) < 0)
                        return -errno;
        }

        ORDERED_HASHMAP_FOREACH(i, todo_uids, iterator) {
                struct spwd n = {
                        .sp_namp = i->name,
                        .sp_pwdp = (char*) "!!", /* lock this password, and make it invalid */
                        .sp_lstchg = lstchg,
                        .sp_min = -1,
                        .sp_max = -1,
                        .sp_warn = -1,
                        .sp_inact = -1,
                        .sp_expire = i->uid == 0 ? -1 : 1, /* lock account as a whole, unless this is root */
                        .sp_flag = (unsigned long) -1, /* this appears to be what everybody does ... */
                };

                r = putspent_sane(&n, shadow);
                if (r < 0)
                        return r;
        }

        /* Append the remaining NIS entries if any */
        while (sp) {
                r = putspent_sane(sp, shadow);
                if (r < 0)
                        return r;

                r = fgetspent_sane(original, &sp);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
        }
        if (!IN_SET(errno, 0, ENOENT))
                return -errno;

        r = fflush_sync_and_check(shadow);
        if (r < 0)
                return r;

        *tmpfile = TAKE_PTR(shadow);
        *tmpfile_path = TAKE_PTR(shadow_tmp);

        return 0;
}

static int write_temporary_group(const char *group_path, FILE **tmpfile, char **tmpfile_path) {
        _cleanup_fclose_ FILE *original = NULL, *group = NULL;
        _cleanup_(unlink_and_freep) char *group_tmp = NULL;
        bool group_changed = false;
        struct group *gr = NULL;
        Iterator iterator;
        Item *i;
        int r;

        if (ordered_hashmap_size(todo_gids) == 0 && ordered_hashmap_size(members) == 0)
                return 0;

        r = fopen_temporary_label("/etc/group", group_path, &group, &group_tmp);
        if (r < 0)
                return r;

        original = fopen(group_path, "re");
        if (original) {

                r = sync_rights(original, group);
                if (r < 0)
                        return r;

                while ((r = fgetgrent_sane(original, &gr)) > 0) {
                        /* Safety checks against name and GID collisions. Normally,
                         * this should be unnecessary, but given that we look at the
                         * entries anyway here, let's make an extra verification
                         * step that we don't generate duplicate entries. */

                        i = ordered_hashmap_get(groups, gr->gr_name);
                        if (i && i->todo_group)
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: Group \"%s\" already exists.",
                                                       group_path, gr->gr_name);

                        if (ordered_hashmap_contains(todo_gids, GID_TO_PTR(gr->gr_gid)))
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: Detected collision for GID " GID_FMT ".",
                                                       group_path, gr->gr_gid);

                        /* Make sure we keep the NIS entries (if any) at the end. */
                        if (IN_SET(gr->gr_name[0], '+', '-'))
                                break;

                        r = putgrent_with_members(gr, group);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                group_changed = true;
                }
                if (r < 0)
                        return r;

        } else {
                if (errno != ENOENT)
                        return -errno;
                if (fchmod(fileno(group), 0644) < 0)
                        return -errno;
        }

        ORDERED_HASHMAP_FOREACH(i, todo_gids, iterator) {
                struct group n = {
                        .gr_name = i->name,
                        .gr_gid = i->gid,
                        .gr_passwd = (char*) "x",
                };

                r = putgrent_with_members(&n, group);
                if (r < 0)
                        return r;

                group_changed = true;
        }

        /* Append the remaining NIS entries if any */
        while (gr) {
                r = putgrent_sane(gr, group);
                if (r < 0)
                        return r;

                r = fgetgrent_sane(original, &gr);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
        }

        r = fflush_sync_and_check(group);
        if (r < 0)
                return r;

        if (group_changed) {
                *tmpfile = TAKE_PTR(group);
                *tmpfile_path = TAKE_PTR(group_tmp);
        }
        return 0;
}

static int write_temporary_gshadow(const char * gshadow_path, FILE **tmpfile, char **tmpfile_path) {
#if ENABLE_GSHADOW
        _cleanup_fclose_ FILE *original = NULL, *gshadow = NULL;
        _cleanup_(unlink_and_freep) char *gshadow_tmp = NULL;
        bool group_changed = false;
        Iterator iterator;
        Item *i;
        int r;

        if (ordered_hashmap_size(todo_gids) == 0 && ordered_hashmap_size(members) == 0)
                return 0;

        r = fopen_temporary_label("/etc/gshadow", gshadow_path, &gshadow, &gshadow_tmp);
        if (r < 0)
                return r;

        original = fopen(gshadow_path, "re");
        if (original) {
                struct sgrp *sg;

                r = sync_rights(original, gshadow);
                if (r < 0)
                        return r;

                while ((r = fgetsgent_sane(original, &sg)) > 0) {

                        i = ordered_hashmap_get(groups, sg->sg_namp);
                        if (i && i->todo_group)
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: Group \"%s\" already exists.",
                                                       gshadow_path, sg->sg_namp);

                        r = putsgent_with_members(sg, gshadow);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                group_changed = true;
                }
                if (r < 0)
                        return r;

        } else {
                if (errno != ENOENT)
                        return -errno;
                if (fchmod(fileno(gshadow), 0000) < 0)
                        return -errno;
        }

        ORDERED_HASHMAP_FOREACH(i, todo_gids, iterator) {
                struct sgrp n = {
                        .sg_namp = i->name,
                        .sg_passwd = (char*) "!!",
                };

                r = putsgent_with_members(&n, gshadow);
                if (r < 0)
                        return r;

                group_changed = true;
        }

        r = fflush_sync_and_check(gshadow);
        if (r < 0)
                return r;

        if (group_changed) {
                *tmpfile = TAKE_PTR(gshadow);
                *tmpfile_path = TAKE_PTR(gshadow_tmp);
        }
        return 0;
#else
        return 0;
#endif
}

static int write_files(void) {
        _cleanup_fclose_ FILE *passwd = NULL, *group = NULL, *shadow = NULL, *gshadow = NULL;
        _cleanup_(unlink_and_freep) char *passwd_tmp = NULL, *group_tmp = NULL, *shadow_tmp = NULL, *gshadow_tmp = NULL;
        const char *passwd_path = NULL, *group_path = NULL, *shadow_path = NULL, *gshadow_path = NULL;
        int r;

        passwd_path = prefix_roota(arg_root, "/etc/passwd");
        shadow_path = prefix_roota(arg_root, "/etc/shadow");
        group_path = prefix_roota(arg_root, "/etc/group");
        gshadow_path = prefix_roota(arg_root, "/etc/gshadow");

        r = write_temporary_group(group_path, &group, &group_tmp);
        if (r < 0)
                return r;

        r = write_temporary_gshadow(gshadow_path, &gshadow, &gshadow_tmp);
        if (r < 0)
                return r;

        r = write_temporary_passwd(passwd_path, &passwd, &passwd_tmp);
        if (r < 0)
                return r;

        r = write_temporary_shadow(shadow_path, &shadow, &shadow_tmp);
        if (r < 0)
                return r;

        /* Make a backup of the old files */
        if (group) {
                r = make_backup("/etc/group", group_path);
                if (r < 0)
                        return r;
        }
        if (gshadow) {
                r = make_backup("/etc/gshadow", gshadow_path);
                if (r < 0)
                        return r;
        }

        if (passwd) {
                r = make_backup("/etc/passwd", passwd_path);
                if (r < 0)
                        return r;
        }
        if (shadow) {
                r = make_backup("/etc/shadow", shadow_path);
                if (r < 0)
                        return r;
        }

        /* And make the new files count */
        if (group) {
                r = rename_and_apply_smack(group_tmp, group_path);
                if (r < 0)
                        return r;

                group_tmp = mfree(group_tmp);
        }
        if (gshadow) {
                r = rename_and_apply_smack(gshadow_tmp, gshadow_path);
                if (r < 0)
                        return r;

                gshadow_tmp = mfree(gshadow_tmp);
        }

        if (passwd) {
                r = rename_and_apply_smack(passwd_tmp, passwd_path);
                if (r < 0)
                        return r;

                passwd_tmp = mfree(passwd_tmp);
        }
        if (shadow) {
                r = rename_and_apply_smack(shadow_tmp, shadow_path);
                if (r < 0)
                        return r;

                shadow_tmp = mfree(shadow_tmp);
        }

        return 0;
}

static int uid_is_ok(uid_t uid, const char *name, bool check_with_gid) {
        struct passwd *p;
        struct group *g;
        const char *n;
        Item *i;

        /* Let's see if we already have assigned the UID a second time */
        if (ordered_hashmap_get(todo_uids, UID_TO_PTR(uid)))
                return 0;

        /* Try to avoid using uids that are already used by a group
         * that doesn't have the same name as our new user. */
        if (check_with_gid) {
                i = ordered_hashmap_get(todo_gids, GID_TO_PTR(uid));
                if (i && !streq(i->name, name))
                        return 0;
        }

        /* Let's check the files directly */
        if (hashmap_contains(database_by_uid, UID_TO_PTR(uid)))
                return 0;

        if (check_with_gid) {
                n = hashmap_get(database_by_gid, GID_TO_PTR(uid));
                if (n && !streq(n, name))
                        return 0;
        }

        /* Let's also check via NSS, to avoid UID clashes over LDAP and such, just in case */
        if (!arg_root) {
                errno = 0;
                p = getpwuid(uid);
                if (p)
                        return 0;
                if (!IN_SET(errno, 0, ENOENT))
                        return -errno;

                if (check_with_gid) {
                        errno = 0;
                        g = getgrgid((gid_t) uid);
                        if (g) {
                                if (!streq(g->gr_name, name))
                                        return 0;
                        } else if (!IN_SET(errno, 0, ENOENT))
                                return -errno;
                }
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
        z = hashmap_get(database_by_username, i->name);
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
                r = uid_is_ok(i->uid, i->name, !i->id_set_strict);
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
                                r = uid_is_ok(c, i->name, true);
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
                r = uid_is_ok((uid_t) i->gid, i->name, true);
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
                        if (r < 0)
                                return log_error_errno(r, "No free user ID available for %s.", i->name);

                        r = uid_is_ok(search_uid, i->name, true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to verify uid " UID_FMT ": %m", i->uid);
                        else if (r > 0)
                                break;
                }

                i->uid_set = true;
                i->uid = search_uid;
        }

        r = ordered_hashmap_ensure_allocated(&todo_uids, NULL);
        if (r < 0)
                return log_oom();

        r = ordered_hashmap_put(todo_uids, UID_TO_PTR(i->uid), i);
        if (r < 0)
                return log_oom();

        i->todo_user = true;
        log_info("Creating user %s (%s) with uid " UID_FMT " and gid " GID_FMT ".", i->name, strna(i->description), i->uid, i->gid);

        return 0;
}

static int gid_is_ok(gid_t gid) {
        struct group *g;
        struct passwd *p;

        if (ordered_hashmap_get(todo_gids, GID_TO_PTR(gid)))
                return 0;

        /* Avoid reusing gids that are already used by a different user */
        if (ordered_hashmap_get(todo_uids, UID_TO_PTR(gid)))
                return 0;

        if (hashmap_contains(database_by_gid, GID_TO_PTR(gid)))
                return 0;

        if (hashmap_contains(database_by_uid, UID_TO_PTR(gid)))
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
        z = hashmap_get(database_by_groupname, i->name);
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
                if (i->id_set_strict) {
                        /* If we require the gid to already exist we can return here:
                         * r > 0: means the gid does not exist -> fail
                         * r == 0: means the gid exists -> nothing more to do.
                         */
                        if (r > 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to create %s: please create GID %d",
                                                       i->name, i->gid);
                        if (r == 0)
                                return 0;
                }
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
                        if (r < 0)
                                return log_error_errno(r, "No free group ID available for %s.", i->name);

                        r = gid_is_ok(search_uid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to verify gid " GID_FMT ": %m", i->gid);
                        else if (r > 0)
                                break;
                }

                i->gid_set = true;
                i->gid = search_uid;
        }

        r = ordered_hashmap_ensure_allocated(&todo_gids, NULL);
        if (r < 0)
                return log_oom();

        r = ordered_hashmap_put(todo_gids, GID_TO_PTR(i->gid), i);
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

        case ADD_USER: {
                Item *j;

                j = ordered_hashmap_get(groups, i->name);
                if (j && j->todo_group) {
                        /* When the group with the same name is already in queue,
                         * use the information about the group and do not create
                         * duplicated group entry. */
                        i->gid_set = j->gid_set;
                        i->gid = j->gid;
                        i->id_set_strict = true;
                } else {
                        r = add_group(i);
                        if (r < 0)
                                return r;
                }

                return add_user(i);
        }

        case ADD_GROUP:
                return add_group(i);

        default:
                assert_not_reached("Unknown item type");
        }
}

static Item* item_free(Item *i) {
        if (!i)
                return NULL;

        free(i->name);
        free(i->uid_path);
        free(i->gid_path);
        free(i->description);
        free(i->home);
        free(i->shell);
        return mfree(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Item*, item_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(item_hash_ops, char, string_hash_func, string_compare_func, Item, item_free);

static int add_implicit(void) {
        char *g, **l;
        Iterator iterator;
        int r;

        /* Implicitly create additional users and groups, if they were listed in "m" lines */
        ORDERED_HASHMAP_FOREACH_KEY(l, g, members, iterator) {
                char **m;

                STRV_FOREACH(m, l)
                        if (!ordered_hashmap_get(users, *m)) {
                                _cleanup_(item_freep) Item *j = NULL;

                                r = ordered_hashmap_ensure_allocated(&users, &item_hash_ops);
                                if (r < 0)
                                        return log_oom();

                                j = new0(Item, 1);
                                if (!j)
                                        return log_oom();

                                j->type = ADD_USER;
                                j->name = strdup(*m);
                                if (!j->name)
                                        return log_oom();

                                r = ordered_hashmap_put(users, j->name, j);
                                if (r < 0)
                                        return log_oom();

                                log_debug("Adding implicit user '%s' due to m line", j->name);
                                j = NULL;
                        }

                if (!(ordered_hashmap_get(users, g) ||
                      ordered_hashmap_get(groups, g))) {
                        _cleanup_(item_freep) Item *j = NULL;

                        r = ordered_hashmap_ensure_allocated(&groups, &item_hash_ops);
                        if (r < 0)
                                return log_oom();

                        j = new0(Item, 1);
                        if (!j)
                                return log_oom();

                        j->type = ADD_GROUP;
                        j->name = strdup(g);
                        if (!j->name)
                                return log_oom();

                        r = ordered_hashmap_put(groups, j->name, j);
                        if (r < 0)
                                return log_oom();

                        log_debug("Adding implicit group '%s' due to m line", j->name);
                        j = NULL;
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

        if (!streq_ptr(a->shell, b->shell))
                return false;

        return true;
}

static int parse_line(const char *fname, unsigned line, const char *buffer) {

        static const Specifier specifier_table[] = {
                { 'm', specifier_machine_id,     NULL },
                { 'b', specifier_boot_id,        NULL },
                { 'H', specifier_host_name,      NULL },
                { 'v', specifier_kernel_release, NULL },
                { 'T', specifier_tmp_dir,        NULL },
                { 'V', specifier_var_tmp_dir,    NULL },
                {}
        };

        _cleanup_free_ char *action = NULL,
                *name = NULL, *resolved_name = NULL,
                *id = NULL, *resolved_id = NULL,
                *description = NULL, *resolved_description = NULL,
                *home = NULL, *resolved_home = NULL,
                *shell = NULL, *resolved_shell = NULL;
        _cleanup_(item_freep) Item *i = NULL;
        Item *existing;
        OrderedHashmap *h;
        int r;
        const char *p;

        assert(fname);
        assert(line >= 1);
        assert(buffer);

        /* Parse columns */
        p = buffer;
        r = extract_many_words(&p, NULL, EXTRACT_UNQUOTE,
                               &action, &name, &id, &description, &home, &shell, NULL);
        if (r < 0)
                return log_error_errno(r, "[%s:%u] Syntax error.", fname, line);
        if (r < 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "[%s:%u] Missing action and name columns.", fname, line);
        if (!isempty(p))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "[%s:%u] Trailing garbage.", fname, line);

        /* Verify action */
        if (strlen(action) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "[%s:%u] Unknown modifier '%s'", fname, line, action);

        if (!IN_SET(action[0], ADD_USER, ADD_GROUP, ADD_MEMBER, ADD_RANGE))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "[%s:%u] Unknown command type '%c'.", fname, line, action[0]);

        /* Verify name */
        if (empty_or_dash(name))
                name = mfree(name);

        if (name) {
                r = specifier_printf(name, specifier_table, NULL, &resolved_name);
                if (r < 0)
                        log_error_errno(r, "[%s:%u] Failed to replace specifiers: %s", fname, line, name);

                if (!valid_user_group_name(resolved_name))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] '%s' is not a valid user or group name.",
                                               fname, line, resolved_name);
        }

        /* Verify id */
        if (empty_or_dash(id))
                id = mfree(id);

        if (id) {
                r = specifier_printf(id, specifier_table, NULL, &resolved_id);
                if (r < 0)
                        return log_error_errno(r, "[%s:%u] Failed to replace specifiers: %s",
                                               fname, line, name);
        }

        /* Verify description */
        if (empty_or_dash(description))
                description = mfree(description);

        if (description) {
                r = specifier_printf(description, specifier_table, NULL, &resolved_description);
                if (r < 0)
                        return log_error_errno(r, "[%s:%u] Failed to replace specifiers: %s",
                                               fname, line, description);

                if (!valid_gecos(resolved_description))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] '%s' is not a valid GECOS field.",
                                               fname, line, resolved_description);
        }

        /* Verify home */
        if (empty_or_dash(home))
                home = mfree(home);

        if (home) {
                r = specifier_printf(home, specifier_table, NULL, &resolved_home);
                if (r < 0)
                        return log_error_errno(r, "[%s:%u] Failed to replace specifiers: %s",
                                               fname, line, home);

                if (!valid_home(resolved_home))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] '%s' is not a valid home directory field.",
                                               fname, line, resolved_home);
        }

        /* Verify shell */
        if (empty_or_dash(shell))
                shell = mfree(shell);

        if (shell) {
                r = specifier_printf(shell, specifier_table, NULL, &resolved_shell);
                if (r < 0)
                        return log_error_errno(r, "[%s:%u] Failed to replace specifiers: %s",
                                               fname, line, shell);

                if (!valid_shell(resolved_shell))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] '%s' is not a valid login shell field.",
                                               fname, line, resolved_shell);
        }

        switch (action[0]) {

        case ADD_RANGE:
                if (resolved_name)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] Lines of type 'r' don't take a name field.",
                                               fname, line);

                if (!resolved_id)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] Lines of type 'r' require a ID range in the third field.",
                                               fname, line);

                if (description || home || shell)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] Lines of type '%c' don't take a %s field.",
                                               fname, line, action[0],
                                               description ? "GECOS" : home ? "home directory" : "login shell");

                r = uid_range_add_str(&uid_range, &n_uid_range, resolved_id);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] Invalid UID range %s.", fname, line, resolved_id);

                return 0;

        case ADD_MEMBER: {
                /* Try to extend an existing member or group item */
                if (!name)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] Lines of type 'm' require a user name in the second field.",
                                               fname, line);

                if (!resolved_id)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] Lines of type 'm' require a group name in the third field.",
                                               fname, line);

                if (!valid_user_group_name(resolved_id))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] '%s' is not a valid user or group name.",
                                               fname, line, resolved_id);

                if (description || home || shell)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] Lines of type '%c' don't take a %s field.",
                                               fname, line, action[0],
                                               description ? "GECOS" : home ? "home directory" : "login shell");

                r = string_strv_ordered_hashmap_put(&members, resolved_id, resolved_name);
                if (r < 0)
                        return log_error_errno(r, "Failed to store mapping for %s: %m", resolved_id);

                return 0;
        }

        case ADD_USER:
                if (!name)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] Lines of type 'u' require a user name in the second field.",
                                               fname, line);

                r = ordered_hashmap_ensure_allocated(&users, &item_hash_ops);
                if (r < 0)
                        return log_oom();

                i = new0(Item, 1);
                if (!i)
                        return log_oom();

                if (resolved_id) {
                        if (path_is_absolute(resolved_id)) {
                                i->uid_path = TAKE_PTR(resolved_id);
                                path_simplify(i->uid_path, false);
                        } else {
                                _cleanup_free_ char *uid = NULL, *gid = NULL;
                                if (split_pair(resolved_id, ":", &uid, &gid) == 0) {
                                        r = parse_gid(gid, &i->gid);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to parse GID: '%s': %m", id);
                                        i->gid_set = true;
                                        i->id_set_strict = true;
                                        free_and_replace(resolved_id, uid);
                                }
                                if (!streq(resolved_id, "-")) {
                                        r = parse_uid(resolved_id, &i->uid);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to parse UID: '%s': %m", id);
                                        i->uid_set = true;
                                }
                        }
                }

                i->description = TAKE_PTR(resolved_description);
                i->home = TAKE_PTR(resolved_home);
                i->shell = TAKE_PTR(resolved_shell);

                h = users;
                break;

        case ADD_GROUP:
                if (!name)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] Lines of type 'g' require a user name in the second field.",
                                               fname, line);

                if (description || home || shell)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] Lines of type '%c' don't take a %s field.",
                                               fname, line, action[0],
                                               description ? "GECOS" : home ? "home directory" : "login shell");

                r = ordered_hashmap_ensure_allocated(&groups, &item_hash_ops);
                if (r < 0)
                        return log_oom();

                i = new0(Item, 1);
                if (!i)
                        return log_oom();

                if (resolved_id) {
                        if (path_is_absolute(resolved_id)) {
                                i->gid_path = TAKE_PTR(resolved_id);
                                path_simplify(i->gid_path, false);
                        } else {
                                r = parse_gid(resolved_id, &i->gid);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse GID: '%s': %m", id);

                                i->gid_set = true;
                        }
                }

                h = groups;
                break;

        default:
                return -EBADMSG;
        }

        i->type = action[0];
        i->name = TAKE_PTR(resolved_name);

        existing = ordered_hashmap_get(h, i->name);
        if (existing) {
                /* Two identical items are fine */
                if (!item_equal(existing, i))
                        log_warning("Two or more conflicting lines for %s configured, ignoring.", i->name);

                return 0;
        }

        r = ordered_hashmap_put(h, i->name, i);
        if (r < 0)
                return log_oom();

        i = NULL;
        return 0;
}

static int read_config_file(const char *fn, bool ignore_enoent) {
        _cleanup_fclose_ FILE *rf = NULL;
        FILE *f = NULL;
        unsigned v = 0;
        int r = 0;

        assert(fn);

        if (streq(fn, "-"))
                f = stdin;
        else {
                r = search_and_fopen(fn, "re", arg_root, (const char**) CONF_PATHS_STRV("sysusers.d"), &rf);
                if (r < 0) {
                        if (ignore_enoent && r == -ENOENT)
                                return 0;

                        return log_error_errno(r, "Failed to open '%s', ignoring: %m", fn);
                }

                f = rf;
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *l;
                int k;

                k = read_line(f, LONG_LINE_MAX, &line);
                if (k < 0)
                        return log_error_errno(k, "Failed to read '%s': %m", fn);
                if (k == 0)
                        break;

                v++;

                l = strstrip(line);
                if (IN_SET(*l, 0, '#'))
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

static int cat_config(void) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        r = conf_files_list_with_replacement(arg_root, CONF_PATHS_STRV("sysusers.d"), arg_replace, &files, NULL);
        if (r < 0)
                return r;

        (void) pager_open(arg_pager_flags);

        return cat_files(NULL, files, 0);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-sysusers.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Creates system user accounts.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --cat-config           Show configuration files\n"
               "     --root=PATH            Operate on an alternate filesystem root\n"
               "     --replace=PATH         Treat arguments as replacement for PATH\n"
               "     --inline               Treat arguments as configuration lines\n"
               "     --no-pager             Do not pipe output into a pager\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_CAT_CONFIG,
                ARG_ROOT,
                ARG_REPLACE,
                ARG_INLINE,
                ARG_NO_PAGER,
        };

        static const struct option options[] = {
                { "help",       no_argument,       NULL, 'h'            },
                { "version",    no_argument,       NULL, ARG_VERSION    },
                { "cat-config", no_argument,       NULL, ARG_CAT_CONFIG },
                { "root",       required_argument, NULL, ARG_ROOT       },
                { "replace",    required_argument, NULL, ARG_REPLACE    },
                { "inline",     no_argument,       NULL, ARG_INLINE     },
                { "no-pager",   no_argument,       NULL, ARG_NO_PAGER   },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_CAT_CONFIG:
                        arg_cat_config = true;
                        break;

                case ARG_ROOT:
                        r = parse_path_argument_and_warn(optarg, true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_REPLACE:
                        if (!path_is_absolute(optarg) ||
                            !endswith(optarg, ".conf"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "The argument to --replace= must an absolute path to a config file");

                        arg_replace = optarg;
                        break;

                case ARG_INLINE:
                        arg_inline = true;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (arg_replace && arg_cat_config)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --replace= is not supported with --cat-config");

        if (arg_replace && optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "When --replace= is given, some configuration items must be specified");

        return 1;
}

static int parse_arguments(char **args) {
        char **arg;
        unsigned pos = 1;
        int r;

        STRV_FOREACH(arg, args) {
                if (arg_inline)
                        /* Use (argument):n, where n==1 for the first positional arg */
                        r = parse_line("(argument)", pos, *arg);
                else
                        r = read_config_file(*arg, false);
                if (r < 0)
                        return r;

                pos++;
        }

        return 0;
}

static int read_config_files(char **args) {
        _cleanup_strv_free_ char **files = NULL;
        _cleanup_free_ char *p = NULL;
        char **f;
        int r;

        r = conf_files_list_with_replacement(arg_root, CONF_PATHS_STRV("sysusers.d"), arg_replace, &files, &p);
        if (r < 0)
                return r;

        STRV_FOREACH(f, files)
                if (p && path_equal(*f, p)) {
                        log_debug("Parsing arguments at position \"%s\"…", *f);

                        r = parse_arguments(args);
                        if (r < 0)
                                return r;
                } else {
                        log_debug("Reading config file \"%s\"…", *f);

                        /* Just warn, ignore result otherwise */
                        (void) read_config_file(*f, true);
                }

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_close_ int lock = -1;
        Iterator iterator;
        Item *i;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup_service();

        if (arg_cat_config)
                return cat_config();

        umask(0022);

        r = mac_selinux_init();
        if (r < 0)
                return log_error_errno(r, "SELinux setup failed: %m");

        /* If command line arguments are specified along with --replace, read all
         * configuration files and insert the positional arguments at the specified
         * place. Otherwise, if command line arguments are specified, execute just
         * them, and finally, without --replace= or any positional arguments, just
         * read configuration and execute it.
         */
        if (arg_replace || optind >= argc)
                r = read_config_files(argv + optind);
        else
                r = parse_arguments(argv + optind);
        if (r < 0)
                return r;

        /* Let's tell nss-systemd not to synthesize the "root" and "nobody" entries for it, so that our detection
         * whether the names or UID/GID area already used otherwise doesn't get confused. After all, even though
         * nss-systemd synthesizes these users/groups, they should still appear in /etc/passwd and /etc/group, as the
         * synthesizing logic is merely supposed to be fallback for cases where we run with a completely unpopulated
         * /etc. */
        if (setenv("SYSTEMD_NSS_BYPASS_SYNTHETIC", "1", 1) < 0)
                return log_error_errno(errno, "Failed to set SYSTEMD_NSS_BYPASS_SYNTHETIC environment variable: %m");

        if (!uid_range) {
                /* Default to default range of 1..SYSTEM_UID_MAX */
                r = uid_range_add(&uid_range, &n_uid_range, 1, SYSTEM_UID_MAX);
                if (r < 0)
                        return log_oom();
        }

        r = add_implicit();
        if (r < 0)
                return r;

        lock = take_etc_passwd_lock(arg_root);
        if (lock < 0)
                return log_error_errno(lock, "Failed to take /etc/passwd lock: %m");

        r = load_user_database();
        if (r < 0)
                return log_error_errno(r, "Failed to load user database: %m");

        r = load_group_database();
        if (r < 0)
                return log_error_errno(r, "Failed to read group database: %m");

        ORDERED_HASHMAP_FOREACH(i, groups, iterator)
                (void) process_item(i);

        ORDERED_HASHMAP_FOREACH(i, users, iterator)
                (void) process_item(i);

        r = write_files();
        if (r < 0)
                return log_error_errno(r, "Failed to write files: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
