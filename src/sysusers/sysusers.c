/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <utmp.h>

#include "alloc-util.h"
#include "chase-symlinks.h"
#include "conf-files.h"
#include "copy.h"
#include "creds-util.h"
#include "def.h"
#include "dissect-image.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "libcrypt-util.h"
#include "main-func.h"
#include "memory-util.h"
#include "mount-util.h"
#include "nscd-flush.h"
#include "pager.h"
#include "parse-argument.h"
#include "path-util.h"
#include "pretty-print.h"
#include "selinux-util.h"
#include "set.h"
#include "smack-util.h"
#include "specifier.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "sync-util.h"
#include "tmpfile-util-label.h"
#include "uid-alloc-range.h"
#include "uid-range.h"
#include "user-util.h"
#include "utf8.h"
#include "util.h"

typedef enum ItemType {
        ADD_USER =   'u',
        ADD_GROUP =  'g',
        ADD_MEMBER = 'm',
        ADD_RANGE =  'r',
} ItemType;

static inline const char* item_type_to_string(ItemType t) {
        switch (t) {
        case ADD_USER:
                return "user";
        case ADD_GROUP:
                return "group";
        case ADD_MEMBER:
                return "member";
        case ADD_RANGE:
                return "range";
        default:
                assert_not_reached();
        }
}

typedef struct Item {
        ItemType type;

        char *name;
        char *group_name;
        char *uid_path;
        char *gid_path;
        char *description;
        char *home;
        char *shell;

        gid_t gid;
        uid_t uid;

        bool gid_set:1;

        /* When set the group with the specified GID must exist
         * and the check if a UID clashes with the GID is skipped.
         */
        bool id_set_strict:1;

        bool uid_set:1;

        bool todo_user:1;
        bool todo_group:1;
} Item;

static char *arg_root = NULL;
static char *arg_image = NULL;
static bool arg_cat_config = false;
static const char *arg_replace = NULL;
static bool arg_dry_run = false;
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

static UGIDAllocationRange login_defs = {};
static bool login_defs_need_warning = false;

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
STATIC_DESTRUCTOR_REGISTER(uid_range, uid_range_freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);

static int errno_is_not_exists(int code) {
        /* See getpwnam(3) and getgrnam(3): those codes and others can be returned if the user or group are
         * not found. */
        return IN_SET(code, 0, ENOENT, ESRCH, EBADF, EPERM);
}

static void maybe_emit_login_defs_warning(void) {
        if (!login_defs_need_warning)
                return;

        if (login_defs.system_alloc_uid_min != SYSTEM_ALLOC_UID_MIN ||
            login_defs.system_uid_max != SYSTEM_UID_MAX)
                log_warning("login.defs specifies UID allocation range "UID_FMT"–"UID_FMT
                            " that is different than the built-in defaults ("UID_FMT"–"UID_FMT")",
                            login_defs.system_alloc_uid_min, login_defs.system_uid_max,
                            (uid_t) SYSTEM_ALLOC_UID_MIN, (uid_t) SYSTEM_UID_MAX);
        if (login_defs.system_alloc_gid_min != SYSTEM_ALLOC_GID_MIN ||
            login_defs.system_gid_max != SYSTEM_GID_MAX)
                log_warning("login.defs specifies GID allocation range "GID_FMT"–"GID_FMT
                            " that is different than the built-in defaults ("GID_FMT"–"GID_FMT")",
                            login_defs.system_alloc_gid_min, login_defs.system_gid_max,
                            (gid_t) SYSTEM_ALLOC_GID_MIN, (gid_t) SYSTEM_GID_MAX);

        login_defs_need_warning = false;
}

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
        _cleanup_(unlink_and_freep) char *dst_tmp = NULL;
        _cleanup_fclose_ FILE *dst = NULL;
        _cleanup_close_ int src = -1;
        const char *backup;
        struct stat st;
        int r;

        assert(target);
        assert(x);

        src = open(x, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (src < 0) {
                if (errno == ENOENT) /* No backup necessary... */
                        return 0;

                return -errno;
        }

        if (fstat(src, &st) < 0)
                return -errno;

        r = fopen_temporary_label(
                        target,   /* The path for which to the look up the label */
                        x,        /* Where we want the file actually to end up */
                        &dst,     /* The temporary file we write to */
                        &dst_tmp);
        if (r < 0)
                return r;

        r = copy_bytes(src, fileno(dst), UINT64_MAX, COPY_REFLINK);
        if (r < 0)
                return r;

        backup = strjoina(x, "-");

        /* Copy over the access mask. Don't fail on chmod() or chown(). If it stays owned by us and/or
         * unreadable by others, then it isn't too bad... */
        r = fchmod_and_chown_with_fallback(fileno(dst), dst_tmp, st.st_mode & 07777, st.st_uid, st.st_gid);
        if (r < 0)
                log_warning_errno(r, "Failed to change access mode or ownership of %s: %m", backup);

        if (futimens(fileno(dst), (const struct timespec[2]) { st.st_atim, st.st_mtim }) < 0)
                log_warning_errno(errno, "Failed to fix access and modification time of %s: %m", backup);

        r = fsync_full(fileno(dst));
        if (r < 0)
                return r;

        if (rename(dst_tmp, backup) < 0)
                return errno;

        dst_tmp = mfree(dst_tmp); /* disable the unlink_and_freep() hook now that the file has been renamed */
        return 0;
}

static int putgrent_with_members(const struct group *gr, FILE *group) {
        char **a;

        assert(gr);
        assert(group);

        a = ordered_hashmap_get(members, gr->gr_name);
        if (a) {
                _cleanup_strv_free_ char **l = NULL;
                bool added = false;

                l = strv_copy(gr->gr_mem);
                if (!l)
                        return -ENOMEM;

                STRV_FOREACH(i, a) {
                        if (strv_contains(l, *i))
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

                l = strv_copy(sg->sg_mem);
                if (!l)
                        return -ENOMEM;

                STRV_FOREACH(i, a) {
                        if (strv_contains(l, *i))
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

static const char* pick_shell(const Item *i) {
        if (i->type != ADD_USER)
                return NULL;
        if (i->shell)
                return i->shell;
        if (i->uid_set && i->uid == 0)
                return default_root_shell(arg_root);
        return NOLOGIN;
}

static int write_temporary_passwd(const char *passwd_path, FILE **tmpfile, char **tmpfile_path) {
        _cleanup_fclose_ FILE *original = NULL, *passwd = NULL;
        _cleanup_(unlink_and_freep) char *passwd_tmp = NULL;
        struct passwd *pw = NULL;
        Item *i;
        int r;

        if (ordered_hashmap_isempty(todo_uids))
                return 0;

        if (arg_dry_run) {
                log_info("Would write /etc/passwd%s", special_glyph(SPECIAL_GLYPH_ELLIPSIS));
                return 0;
        }

        r = fopen_temporary_label("/etc/passwd", passwd_path, &passwd, &passwd_tmp);
        if (r < 0)
                return log_debug_errno(r, "Failed to open temporary copy of %s: %m", passwd_path);

        original = fopen(passwd_path, "re");
        if (original) {

                /* Allow fallback path for when /proc is not mounted. On any normal system /proc will be
                 * mounted, but e.g. when 'dnf --installroot' is used, it might not be. There is no security
                 * relevance here, since the environment is ultimately trusted, and not requiring /proc makes
                 * it easier to depend on sysusers in packaging scripts and suchlike. */
                r = copy_rights_with_fallback(fileno(original), fileno(passwd), passwd_tmp);
                if (r < 0)
                        return log_debug_errno(r, "Failed to copy permissions from %s to %s: %m",
                                               passwd_path, passwd_tmp);

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
                                return log_debug_errno(r, "Failed to add existing user \"%s\" to temporary passwd file: %m",
                                                       pw->pw_name);
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to read %s: %m", passwd_path);

        } else {
                if (errno != ENOENT)
                        return log_debug_errno(errno, "Failed to open %s: %m", passwd_path);
                if (fchmod(fileno(passwd), 0644) < 0)
                        return log_debug_errno(errno, "Failed to fchmod %s: %m", passwd_tmp);
        }

        ORDERED_HASHMAP_FOREACH(i, todo_uids) {
                _cleanup_free_ char *creds_shell = NULL, *cn = NULL;

                struct passwd n = {
                        .pw_name = i->name,
                        .pw_uid = i->uid,
                        .pw_gid = i->gid,
                        .pw_gecos = (char*) strempty(i->description),

                        /* "x" means the password is stored in the shadow file */
                        .pw_passwd = (char*) PASSWORD_SEE_SHADOW,

                        /* We default to the root directory as home */
                        .pw_dir = i->home ?: (char*) "/",

                        /* Initialize the shell to nologin, with one exception:
                         * for root we patch in something special */
                        .pw_shell = (char*) pick_shell(i),
                };

                /* Try to pick up the shell for this account via the credentials logic */
                cn = strjoin("passwd.shell.", i->name);
                if (!cn)
                        return -ENOMEM;

                r = read_credential(cn, (void**) &creds_shell, NULL);
                if (r < 0)
                        log_debug_errno(r, "Couldn't read credential '%s', ignoring: %m", cn);
                else
                        n.pw_shell = creds_shell;

                r = putpwent_sane(&n, passwd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add new user \"%s\" to temporary passwd file: %m",
                                               pw->pw_name);
        }

        /* Append the remaining NIS entries if any */
        while (pw) {
                r = putpwent_sane(pw, passwd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add existing user \"%s\" to temporary passwd file: %m",
                                               pw->pw_name);

                r = fgetpwent_sane(original, &pw);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read %s: %m", passwd_path);
                if (r == 0)
                        break;
        }

        r = fflush_sync_and_check(passwd);
        if (r < 0)
                return log_debug_errno(r, "Failed to flush %s: %m", passwd_tmp);

        *tmpfile = TAKE_PTR(passwd);
        *tmpfile_path = TAKE_PTR(passwd_tmp);

        return 0;
}

static usec_t epoch_or_now(void) {
        uint64_t epoch;

        if (getenv_uint64_secure("SOURCE_DATE_EPOCH", &epoch) >= 0) {
                if (epoch > UINT64_MAX/USEC_PER_SEC) /* Overflow check */
                        return USEC_INFINITY;
                return (usec_t) epoch * USEC_PER_SEC;
        }

        return now(CLOCK_REALTIME);
}

static int write_temporary_shadow(const char *shadow_path, FILE **tmpfile, char **tmpfile_path) {
        _cleanup_fclose_ FILE *original = NULL, *shadow = NULL;
        _cleanup_(unlink_and_freep) char *shadow_tmp = NULL;
        struct spwd *sp = NULL;
        long lstchg;
        Item *i;
        int r;

        if (ordered_hashmap_isempty(todo_uids))
                return 0;

        if (arg_dry_run) {
                log_info("Would write /etc/shadow%s", special_glyph(SPECIAL_GLYPH_ELLIPSIS));
                return 0;
        }

        r = fopen_temporary_label("/etc/shadow", shadow_path, &shadow, &shadow_tmp);
        if (r < 0)
                return log_debug_errno(r, "Failed to open temporary copy of %s: %m", shadow_path);

        lstchg = (long) (epoch_or_now() / USEC_PER_DAY);

        original = fopen(shadow_path, "re");
        if (original) {

                r = copy_rights_with_fallback(fileno(original), fileno(shadow), shadow_tmp);
                if (r < 0)
                        return log_debug_errno(r, "Failed to copy permissions from %s to %s: %m",
                                               shadow_path, shadow_tmp);

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
                                return log_debug_errno(r, "Failed to add existing user \"%s\" to temporary shadow file: %m",
                                                       sp->sp_namp);

                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to read %s: %m", shadow_path);

        } else {
                if (errno != ENOENT)
                        return log_debug_errno(errno, "Failed to open %s: %m", shadow_path);
                if (fchmod(fileno(shadow), 0000) < 0)
                        return log_debug_errno(errno, "Failed to fchmod %s: %m", shadow_tmp);
        }

        ORDERED_HASHMAP_FOREACH(i, todo_uids) {
                _cleanup_(erase_and_freep) char *creds_password = NULL;
                bool is_hashed;

                struct spwd n = {
                        .sp_namp = i->name,
                        .sp_pwdp = (char*) PASSWORD_LOCKED_AND_INVALID,
                        .sp_lstchg = lstchg,
                        .sp_min = -1,
                        .sp_max = -1,
                        .sp_warn = -1,
                        .sp_inact = -1,
                        .sp_expire = -1,
                        .sp_flag = ULONG_MAX, /* this appears to be what everybody does ... */
                };

                r = get_credential_user_password(i->name, &creds_password, &is_hashed);
                if (r < 0)
                        log_debug_errno(r, "Couldn't read password credential for user '%s', ignoring: %m", i->name);

                if (creds_password && !is_hashed) {
                        _cleanup_(erase_and_freep) char* plaintext_password = TAKE_PTR(creds_password);
                        r = hash_password(plaintext_password, &creds_password);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to hash password: %m");
                }

                if (creds_password)
                        n.sp_pwdp = creds_password;

                r = putspent_sane(&n, shadow);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add new user \"%s\" to temporary shadow file: %m",
                                               sp->sp_namp);
        }

        /* Append the remaining NIS entries if any */
        while (sp) {
                r = putspent_sane(sp, shadow);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add existing user \"%s\" to temporary shadow file: %m",
                                               sp->sp_namp);

                r = fgetspent_sane(original, &sp);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read %s: %m", shadow_path);
                if (r == 0)
                        break;
        }
        if (!IN_SET(errno, 0, ENOENT))
                return -errno;

        r = fflush_sync_and_check(shadow);
        if (r < 0)
                return log_debug_errno(r, "Failed to flush %s: %m", shadow_tmp);

        *tmpfile = TAKE_PTR(shadow);
        *tmpfile_path = TAKE_PTR(shadow_tmp);

        return 0;
}

static int write_temporary_group(const char *group_path, FILE **tmpfile, char **tmpfile_path) {
        _cleanup_fclose_ FILE *original = NULL, *group = NULL;
        _cleanup_(unlink_and_freep) char *group_tmp = NULL;
        bool group_changed = false;
        struct group *gr = NULL;
        Item *i;
        int r;

        if (ordered_hashmap_isempty(todo_gids) && ordered_hashmap_isempty(members))
                return 0;

        if (arg_dry_run) {
                log_info("Would write /etc/group%s", special_glyph(SPECIAL_GLYPH_ELLIPSIS));
                return 0;
        }

        r = fopen_temporary_label("/etc/group", group_path, &group, &group_tmp);
        if (r < 0)
                return log_error_errno(r, "Failed to open temporary copy of %s: %m", group_path);

        original = fopen(group_path, "re");
        if (original) {

                r = copy_rights_with_fallback(fileno(original), fileno(group), group_tmp);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy permissions from %s to %s: %m",
                                               group_path, group_tmp);

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
                                return log_error_errno(r, "Failed to add existing group \"%s\" to temporary group file: %m",
                                                       gr->gr_name);
                        if (r > 0)
                                group_changed = true;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s: %m", group_path);

        } else {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open %s: %m", group_path);
                if (fchmod(fileno(group), 0644) < 0)
                        return log_error_errno(errno, "Failed to fchmod %s: %m", group_tmp);
        }

        ORDERED_HASHMAP_FOREACH(i, todo_gids) {
                struct group n = {
                        .gr_name = i->name,
                        .gr_gid = i->gid,
                        .gr_passwd = (char*) PASSWORD_SEE_SHADOW,
                };

                r = putgrent_with_members(&n, group);
                if (r < 0)
                        return log_error_errno(r, "Failed to add new group \"%s\" to temporary group file: %m",
                                               gr->gr_name);

                group_changed = true;
        }

        /* Append the remaining NIS entries if any */
        while (gr) {
                r = putgrent_sane(gr, group);
                if (r < 0)
                        return log_error_errno(r, "Failed to add existing group \"%s\" to temporary group file: %m",
                                               gr->gr_name);

                r = fgetgrent_sane(original, &gr);
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s: %m", group_path);
                if (r == 0)
                        break;
        }

        r = fflush_sync_and_check(group);
        if (r < 0)
                return log_error_errno(r, "Failed to flush %s: %m", group_tmp);

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
        Item *i;
        int r;

        if (ordered_hashmap_isempty(todo_gids) && ordered_hashmap_isempty(members))
                return 0;

        if (arg_dry_run) {
                log_info("Would write /etc/gshadow%s", special_glyph(SPECIAL_GLYPH_ELLIPSIS));
                return 0;
        }

        r = fopen_temporary_label("/etc/gshadow", gshadow_path, &gshadow, &gshadow_tmp);
        if (r < 0)
                return log_error_errno(r, "Failed to open temporary copy of %s: %m", gshadow_path);

        original = fopen(gshadow_path, "re");
        if (original) {
                struct sgrp *sg;

                r = copy_rights_with_fallback(fileno(original), fileno(gshadow), gshadow_tmp);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy permissions from %s to %s: %m",
                                               gshadow_path, gshadow_tmp);

                while ((r = fgetsgent_sane(original, &sg)) > 0) {

                        i = ordered_hashmap_get(groups, sg->sg_namp);
                        if (i && i->todo_group)
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: Group \"%s\" already exists.",
                                                       gshadow_path, sg->sg_namp);

                        r = putsgent_with_members(sg, gshadow);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add existing group \"%s\" to temporary gshadow file: %m",
                                                       sg->sg_namp);
                        if (r > 0)
                                group_changed = true;
                }
                if (r < 0)
                        return r;

        } else {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open %s: %m", gshadow_path);
                if (fchmod(fileno(gshadow), 0000) < 0)
                        return log_error_errno(errno, "Failed to fchmod %s: %m", gshadow_tmp);
        }

        ORDERED_HASHMAP_FOREACH(i, todo_gids) {
                struct sgrp n = {
                        .sg_namp = i->name,
                        .sg_passwd = (char*) PASSWORD_LOCKED_AND_INVALID,
                };

                r = putsgent_with_members(&n, gshadow);
                if (r < 0)
                        return log_error_errno(r, "Failed to add new group \"%s\" to temporary gshadow file: %m",
                                               n.sg_namp);

                group_changed = true;
        }

        r = fflush_sync_and_check(gshadow);
        if (r < 0)
                return log_error_errno(r, "Failed to flush %s: %m", gshadow_tmp);

        if (group_changed) {
                *tmpfile = TAKE_PTR(gshadow);
                *tmpfile_path = TAKE_PTR(gshadow_tmp);
        }
#endif
        return 0;
}

static int write_files(void) {
        _cleanup_fclose_ FILE *passwd = NULL, *group = NULL, *shadow = NULL, *gshadow = NULL;
        _cleanup_(unlink_and_freep) char *passwd_tmp = NULL, *group_tmp = NULL, *shadow_tmp = NULL, *gshadow_tmp = NULL;
        const char *passwd_path, *shadow_path, *group_path, *gshadow_path;
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
                        return log_error_errno(r, "Failed to make backup %s: %m", group_path);
        }
        if (gshadow) {
                r = make_backup("/etc/gshadow", gshadow_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to make backup %s: %m", gshadow_path);
        }

        if (passwd) {
                r = make_backup("/etc/passwd", passwd_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to make backup %s: %m", passwd_path);
        }
        if (shadow) {
                r = make_backup("/etc/shadow", shadow_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to make backup %s: %m", shadow_path);
        }

        /* And make the new files count */
        if (group) {
                r = rename_and_apply_smack_floor_label(group_tmp, group_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to rename %s to %s: %m",
                                               group_tmp, group_path);
                group_tmp = mfree(group_tmp);

                if (!arg_root && !arg_image)
                        (void) nscd_flush_cache(STRV_MAKE("group"));
        }
        if (gshadow) {
                r = rename_and_apply_smack_floor_label(gshadow_tmp, gshadow_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to rename %s to %s: %m",
                                               gshadow_tmp, gshadow_path);

                gshadow_tmp = mfree(gshadow_tmp);
        }

        if (passwd) {
                r = rename_and_apply_smack_floor_label(passwd_tmp, passwd_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to rename %s to %s: %m",
                                               passwd_tmp, passwd_path);

                passwd_tmp = mfree(passwd_tmp);

                if (!arg_root && !arg_image)
                        (void) nscd_flush_cache(STRV_MAKE("passwd"));
        }
        if (shadow) {
                r = rename_and_apply_smack_floor_label(shadow_tmp, shadow_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to rename %s to %s: %m",
                                               shadow_tmp, shadow_path);

                shadow_tmp = mfree(shadow_tmp);
        }

        return 0;
}

static int uid_is_ok(uid_t uid, const char *name, bool check_with_gid) {

        /* Let's see if we already have assigned the UID a second time */
        if (ordered_hashmap_get(todo_uids, UID_TO_PTR(uid)))
                return 0;

        /* Try to avoid using uids that are already used by a group
         * that doesn't have the same name as our new user. */
        if (check_with_gid) {
                Item *i;

                i = ordered_hashmap_get(todo_gids, GID_TO_PTR(uid));
                if (i && !streq(i->name, name))
                        return 0;
        }

        /* Let's check the files directly */
        if (hashmap_contains(database_by_uid, UID_TO_PTR(uid)))
                return 0;

        if (check_with_gid) {
                const char *n;

                n = hashmap_get(database_by_gid, GID_TO_PTR(uid));
                if (n && !streq(n, name))
                        return 0;
        }

        /* Let's also check via NSS, to avoid UID clashes over LDAP and such, just in case */
        if (!arg_root) {
                struct passwd *p;
                struct group *g;

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
        return RET_NERRNO(stat(fix, st));
}

static int read_id_from_file(Item *i, uid_t *ret_uid, gid_t *ret_gid) {
        struct stat st;
        bool found_uid = false, found_gid = false;
        uid_t uid = 0;
        gid_t gid = 0;

        assert(i);

        /* First, try to get the GID directly */
        if (ret_gid && i->gid_path && root_stat(i->gid_path, &st) >= 0) {
                gid = st.st_gid;
                found_gid = true;
        }

        /* Then, try to get the UID directly */
        if ((ret_uid || (ret_gid && !found_gid))
            && i->uid_path
            && root_stat(i->uid_path, &st) >= 0) {

                uid = st.st_uid;
                found_uid = true;

                /* If we need the gid, but had no success yet, also derive it from the UID path */
                if (ret_gid && !found_gid) {
                        gid = st.st_gid;
                        found_gid = true;
                }
        }

        /* If that didn't work yet, then let's reuse the GID as UID */
        if (ret_uid && !found_uid && i->gid_path) {

                if (found_gid) {
                        uid = (uid_t) gid;
                        found_uid = true;
                } else if (root_stat(i->gid_path, &st) >= 0) {
                        uid = (uid_t) st.st_gid;
                        found_uid = true;
                }
        }

        if (ret_uid) {
                if (!found_uid)
                        return 0;

                *ret_uid = uid;
        }

        if (ret_gid) {
                if (!found_gid)
                        return 0;

                *ret_gid = gid;
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
                if (!errno_is_not_exists(errno))
                        return log_error_errno(errno, "Failed to check if user %s already exists: %m", i->name);
        }

        /* Try to use the suggested numeric UID */
        if (i->uid_set) {
                r = uid_is_ok(i->uid, i->name, !i->id_set_strict);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify UID " UID_FMT ": %m", i->uid);
                if (r == 0) {
                        log_info("Suggested user ID " UID_FMT " for %s already used.", i->uid, i->name);
                        i->uid_set = false;
                }
        }

        /* If that didn't work, try to read it from the specified path */
        if (!i->uid_set) {
                uid_t c;

                if (read_id_from_file(i, &c, NULL) > 0) {

                        if (c <= 0 || !uid_range_contains(uid_range, c))
                                log_debug("User ID " UID_FMT " of file not suitable for %s.", c, i->name);
                        else {
                                r = uid_is_ok(c, i->name, true);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to verify UID " UID_FMT ": %m", i->uid);
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
                        return log_error_errno(r, "Failed to verify UID " UID_FMT ": %m", i->uid);
                if (r > 0) {
                        i->uid = (uid_t) i->gid;
                        i->uid_set = true;
                }
        }

        /* And if that didn't work either, let's try to find a free one */
        if (!i->uid_set) {
                maybe_emit_login_defs_warning();

                for (;;) {
                        r = uid_range_next_lower(uid_range, &search_uid);
                        if (r < 0)
                                return log_error_errno(r, "No free user ID available for %s.", i->name);

                        r = uid_is_ok(search_uid, i->name, true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to verify UID " UID_FMT ": %m", i->uid);
                        else if (r > 0)
                                break;
                }

                i->uid_set = true;
                i->uid = search_uid;
        }

        r = ordered_hashmap_ensure_put(&todo_uids, NULL, UID_TO_PTR(i->uid), i);
        if (r == -EEXIST)
                return log_error_errno(r, "Requested user %s with UID " UID_FMT " and gid" GID_FMT " to be created is duplicated "
                                       "or conflicts with another user.", i->name, i->uid, i->gid);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_error_errno(r, "Failed to store user %s with UID " UID_FMT " and GID " GID_FMT " to be created: %m",
                                       i->name, i->uid, i->gid);

        i->todo_user = true;
        log_info("Creating user '%s' (%s) with UID " UID_FMT " and GID " GID_FMT ".",
                 i->name, strna(i->description), i->uid, i->gid);

        return 0;
}

static int gid_is_ok(gid_t gid, const char *groupname, bool check_with_uid) {
        struct group *g;
        struct passwd *p;
        Item *user;
        char *username;

        assert(groupname);

        if (ordered_hashmap_get(todo_gids, GID_TO_PTR(gid)))
                return 0;

        /* Avoid reusing gids that are already used by a different user */
        if (check_with_uid) {
                user = ordered_hashmap_get(todo_uids, UID_TO_PTR(gid));
                if (user && !streq(user->name, groupname))
                        return 0;
        }

        if (hashmap_contains(database_by_gid, GID_TO_PTR(gid)))
                return 0;

        if (check_with_uid) {
                username = hashmap_get(database_by_uid, UID_TO_PTR(gid));
                if (username && !streq(username, groupname))
                        return 0;
        }

        if (!arg_root) {
                errno = 0;
                g = getgrgid(gid);
                if (g)
                        return 0;
                if (!IN_SET(errno, 0, ENOENT))
                        return -errno;

                if (check_with_uid) {
                        errno = 0;
                        p = getpwuid((uid_t) gid);
                        if (p)
                                return 0;
                        if (!IN_SET(errno, 0, ENOENT))
                                return -errno;
                }
        }

        return 1;
}

static int get_gid_by_name(const char *name, gid_t *gid) {
        void *z;

        assert(gid);

        /* Check the database directly */
        z = hashmap_get(database_by_groupname, name);
        if (z) {
                *gid = PTR_TO_GID(z);
                return 0;
        }

        /* Also check NSS */
        if (!arg_root) {
                struct group *g;

                errno = 0;
                g = getgrnam(name);
                if (g) {
                        *gid = g->gr_gid;
                        return 0;
                }
                if (!errno_is_not_exists(errno))
                        return log_error_errno(errno, "Failed to check if group %s already exists: %m", name);
        }

        return -ENOENT;
}

static int add_group(Item *i) {
        int r;

        assert(i);

        r = get_gid_by_name(i->name, &i->gid);
        if (r != -ENOENT) {
                if (r < 0)
                        return r;
                log_debug("Group %s already exists.", i->name);
                i->gid_set = true;
                return 0;
        }

        /* Try to use the suggested numeric GID */
        if (i->gid_set) {
                r = gid_is_ok(i->gid, i->name, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify GID " GID_FMT ": %m", i->gid);
                if (i->id_set_strict) {
                        /* If we require the GID to already exist we can return here:
                         * r > 0: means the GID does not exist -> fail
                         * r == 0: means the GID exists -> nothing more to do.
                         */
                        if (r > 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to create %s: please create GID " GID_FMT,
                                                       i->name, i->gid);
                        if (r == 0)
                                return 0;
                }
                if (r == 0) {
                        log_info("Suggested group ID " GID_FMT " for %s already used.", i->gid, i->name);
                        i->gid_set = false;
                }
        }

        /* Try to reuse the numeric uid, if there's one */
        if (!i->gid_set && i->uid_set) {
                r = gid_is_ok((gid_t) i->uid, i->name, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify GID " GID_FMT ": %m", i->gid);
                if (r > 0) {
                        i->gid = (gid_t) i->uid;
                        i->gid_set = true;
                }
        }

        /* If that didn't work, try to read it from the specified path */
        if (!i->gid_set) {
                gid_t c;

                if (read_id_from_file(i, NULL, &c) > 0) {

                        if (c <= 0 || !uid_range_contains(uid_range, c))
                                log_debug("Group ID " GID_FMT " of file not suitable for %s.", c, i->name);
                        else {
                                r = gid_is_ok(c, i->name, true);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to verify GID " GID_FMT ": %m", i->gid);
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
                maybe_emit_login_defs_warning();

                for (;;) {
                        /* We look for new GIDs in the UID pool! */
                        r = uid_range_next_lower(uid_range, &search_uid);
                        if (r < 0)
                                return log_error_errno(r, "No free group ID available for %s.", i->name);

                        r = gid_is_ok(search_uid, i->name, true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to verify GID " GID_FMT ": %m", i->gid);
                        else if (r > 0)
                                break;
                }

                i->gid_set = true;
                i->gid = search_uid;
        }

        r = ordered_hashmap_ensure_put(&todo_gids, NULL, GID_TO_PTR(i->gid), i);
        if (r == -EEXIST)
                return log_error_errno(r, "Requested group %s with GID "GID_FMT " to be created is duplicated or conflicts with another user.", i->name, i->gid);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_error_errno(r, "Failed to store group %s with GID " GID_FMT " to be created: %m", i->name, i->gid);

        i->todo_group = true;
        log_info("Creating group '%s' with GID " GID_FMT ".", i->name, i->gid);

        return 0;
}

static int process_item(Item *i) {
        int r;

        assert(i);

        switch (i->type) {

        case ADD_USER: {
                Item *j = NULL;

                if (!i->gid_set)
                        j = ordered_hashmap_get(groups, i->group_name ?: i->name);

                if (j && j->todo_group) {
                        /* When a group with the target name is already in queue,
                         * use the information about the group and do not create
                         * duplicated group entry. */
                        i->gid_set = j->gid_set;
                        i->gid = j->gid;
                        i->id_set_strict = true;
                } else if (i->group_name) {
                        /* When a group name was given instead of a GID and it's
                         * not in queue, then it must already exist. */
                        r = get_gid_by_name(i->group_name, &i->gid);
                        if (r < 0)
                                return log_error_errno(r, "Group %s not found.", i->group_name);
                        i->gid_set = true;
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
                assert_not_reached();
        }
}

static Item* item_free(Item *i) {
        if (!i)
                return NULL;

        free(i->name);
        free(i->group_name);
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
        int r;

        /* Implicitly create additional users and groups, if they were listed in "m" lines */
        ORDERED_HASHMAP_FOREACH_KEY(l, g, members) {
                STRV_FOREACH(m, l)
                        if (!ordered_hashmap_get(users, *m)) {
                                _cleanup_(item_freep) Item *j = NULL;

                                j = new0(Item, 1);
                                if (!j)
                                        return log_oom();

                                j->type = ADD_USER;
                                j->name = strdup(*m);
                                if (!j->name)
                                        return log_oom();

                                r = ordered_hashmap_ensure_put(&users, &item_hash_ops, j->name, j);
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0)
                                        return log_error_errno(r, "Failed to add implicit user '%s': %m", j->name);

                                log_debug("Adding implicit user '%s' due to m line", j->name);
                                TAKE_PTR(j);
                        }

                if (!(ordered_hashmap_get(users, g) ||
                      ordered_hashmap_get(groups, g))) {
                        _cleanup_(item_freep) Item *j = NULL;

                        j = new0(Item, 1);
                        if (!j)
                                return log_oom();

                        j->type = ADD_GROUP;
                        j->name = strdup(g);
                        if (!j->name)
                                return log_oom();

                        r = ordered_hashmap_ensure_put(&groups, &item_hash_ops, j->name, j);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Failed to add implicit group '%s': %m", j->name);

                        log_debug("Adding implicit group '%s' due to m line", j->name);
                        TAKE_PTR(j);
                }
        }

        return 0;
}

static int item_equivalent(Item *a, Item *b) {
        int r;

        assert(a);
        assert(b);

        if (a->type != b->type)
                return false;

        if (!streq_ptr(a->name, b->name))
                return false;

        /* Paths were simplified previously, so we can use streq. */
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

        /* Check if the two paths refer to the same file.
         * If the paths are equal (after normalization), it's obviously the same file.
         * If both paths specify a nologin shell, treat them as the same (e.g. /bin/true and /bin/false).
         * Otherwise, try to resolve the paths, and see if we get the same result, (e.g. /sbin/nologin and
         * /usr/sbin/nologin).
         * If we can't resolve something, treat different paths as different. */

        const char *a_shell = pick_shell(a),
                   *b_shell = pick_shell(b);
        if (!path_equal_ptr(a_shell, b_shell) &&
            !(is_nologin_shell(a_shell) && is_nologin_shell(b_shell))) {
                _cleanup_free_ char *pa = NULL, *pb = NULL;

                r = chase_symlinks(a_shell, arg_root, CHASE_PREFIX_ROOT | CHASE_NONEXISTENT, &pa, NULL);
                if (r < 0) {
                        log_full_errno(ERRNO_IS_RESOURCE(r) ? LOG_ERR : LOG_DEBUG,
                                       r, "Failed to look up path '%s%s%s': %m",
                                       strempty(arg_root), arg_root ? "/" : "", a_shell);
                        return ERRNO_IS_RESOURCE(r) ? r : false;
                }

                r = chase_symlinks(b_shell, arg_root, CHASE_PREFIX_ROOT | CHASE_NONEXISTENT, &pb, NULL);
                if (r < 0) {
                        log_full_errno(ERRNO_IS_RESOURCE(r) ? LOG_ERR : LOG_DEBUG,
                                       r, "Failed to look up path '%s%s%s': %m",
                                       strempty(arg_root), arg_root ? "/" : "", b_shell);
                        return ERRNO_IS_RESOURCE(r) ? r : false;
                }

                if (!path_equal(pa, pb))
                        return false;
        }

        return true;
}

static int parse_line(const char *fname, unsigned line, const char *buffer) {
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
                return log_syntax(NULL, LOG_ERR, fname, line, r, "Syntax error.");
        if (r < 2)
                return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                  "Missing action and name columns.");
        if (!isempty(p))
                return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                  "Trailing garbage.");

        /* Verify action */
        if (strlen(action) != 1)
                return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                  "Unknown modifier '%s'.", action);

        if (!IN_SET(action[0], ADD_USER, ADD_GROUP, ADD_MEMBER, ADD_RANGE))
                return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EBADMSG),
                                  "Unknown command type '%c'.", action[0]);

        /* Verify name */
        if (empty_or_dash(name))
                name = mfree(name);

        if (name) {
                r = specifier_printf(name, NAME_MAX, system_and_tmp_specifier_table, arg_root, NULL, &resolved_name);
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, fname, line, r, "Failed to replace specifiers in '%s': %m", name);

                if (!valid_user_group_name(resolved_name, 0))
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "'%s' is not a valid user or group name.", resolved_name);
        }

        /* Verify id */
        if (empty_or_dash(id))
                id = mfree(id);

        if (id) {
                r = specifier_printf(id, PATH_MAX-1, system_and_tmp_specifier_table, arg_root, NULL, &resolved_id);
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, fname, line, r,
                                          "Failed to replace specifiers in '%s': %m", name);
        }

        /* Verify description */
        if (empty_or_dash(description))
                description = mfree(description);

        if (description) {
                r = specifier_printf(description, LONG_LINE_MAX, system_and_tmp_specifier_table, arg_root, NULL, &resolved_description);
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, fname, line, r,
                                          "Failed to replace specifiers in '%s': %m", description);

                if (!valid_gecos(resolved_description))
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "'%s' is not a valid GECOS field.", resolved_description);
        }

        /* Verify home */
        if (empty_or_dash(home))
                home = mfree(home);

        if (home) {
                r = specifier_printf(home, PATH_MAX-1, system_and_tmp_specifier_table, arg_root, NULL, &resolved_home);
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, fname, line, r,
                                          "Failed to replace specifiers in '%s': %m", home);

                path_simplify(resolved_home);

                if (!valid_home(resolved_home))
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "'%s' is not a valid home directory field.", resolved_home);
        }

        /* Verify shell */
        if (empty_or_dash(shell))
                shell = mfree(shell);

        if (shell) {
                r = specifier_printf(shell, PATH_MAX-1, system_and_tmp_specifier_table, arg_root, NULL, &resolved_shell);
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, fname, line, r,
                                          "Failed to replace specifiers in '%s': %m", shell);

                path_simplify(resolved_shell);

                if (!valid_shell(resolved_shell))
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "'%s' is not a valid login shell field.", resolved_shell);
        }

        switch (action[0]) {

        case ADD_RANGE:
                if (resolved_name)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type 'r' don't take a name field.");

                if (!resolved_id)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type 'r' require an ID range in the third field.");

                if (description || home || shell)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type '%c' don't take a %s field.",
                                          action[0],
                                          description ? "GECOS" : home ? "home directory" : "login shell");

                r = uid_range_add_str(&uid_range, resolved_id);
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Invalid UID range %s.", resolved_id);

                return 0;

        case ADD_MEMBER: {
                /* Try to extend an existing member or group item */
                if (!name)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type 'm' require a user name in the second field.");

                if (!resolved_id)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type 'm' require a group name in the third field.");

                if (!valid_user_group_name(resolved_id, 0))
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                               "'%s' is not a valid user or group name.", resolved_id);

                if (description || home || shell)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type '%c' don't take a %s field.",
                                          action[0],
                                          description ? "GECOS" : home ? "home directory" : "login shell");

                r = string_strv_ordered_hashmap_put(&members, resolved_id, resolved_name);
                if (r < 0)
                        return log_error_errno(r, "Failed to store mapping for %s: %m", resolved_id);

                return 0;
        }

        case ADD_USER:
                if (!name)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type 'u' require a user name in the second field.");

                r = ordered_hashmap_ensure_allocated(&users, &item_hash_ops);
                if (r < 0)
                        return log_oom();

                i = new0(Item, 1);
                if (!i)
                        return log_oom();

                if (resolved_id) {
                        if (path_is_absolute(resolved_id)) {
                                i->uid_path = TAKE_PTR(resolved_id);
                                path_simplify(i->uid_path);
                        } else {
                                _cleanup_free_ char *uid = NULL, *gid = NULL;
                                if (split_pair(resolved_id, ":", &uid, &gid) == 0) {
                                        r = parse_gid(gid, &i->gid);
                                        if (r < 0) {
                                                if (valid_user_group_name(gid, 0))
                                                        i->group_name = TAKE_PTR(gid);
                                                else
                                                        return log_syntax(NULL, LOG_ERR, fname, line, r,
                                                                          "Failed to parse GID: '%s': %m", id);
                                        } else {
                                                i->gid_set = true;
                                                i->id_set_strict = true;
                                        }
                                        free_and_replace(resolved_id, uid);
                                }
                                if (!streq(resolved_id, "-")) {
                                        r = parse_uid(resolved_id, &i->uid);
                                        if (r < 0)
                                                return log_syntax(NULL, LOG_ERR, fname, line, r,
                                                                  "Failed to parse UID: '%s': %m", id);
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
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type 'g' require a user name in the second field.");

                if (description || home || shell)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type '%c' don't take a %s field.",
                                          action[0],
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
                                path_simplify(i->gid_path);
                        } else {
                                r = parse_gid(resolved_id, &i->gid);
                                if (r < 0)
                                        return log_syntax(NULL, LOG_ERR, fname, line, r,
                                                          "Failed to parse GID: '%s': %m", id);

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
                /* Two functionally-equivalent items are fine */
                r = item_equivalent(existing, i);
                if (r < 0)
                        return r;
                if (r == 0)
                        log_syntax(NULL, LOG_WARNING, fname, line, SYNTHETIC_ERRNO(EUCLEAN),
                                   "Conflict with earlier configuration for %s '%s', ignoring line.",
                                   item_type_to_string(i->type), i->name);

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
        _cleanup_free_ char *pp = NULL;
        FILE *f = NULL;
        unsigned v = 0;
        int r = 0;

        assert(fn);

        if (streq(fn, "-"))
                f = stdin;
        else {
                r = search_and_fopen(fn, "re", arg_root, (const char**) CONF_PATHS_STRV("sysusers.d"), &rf, &pp);
                if (r < 0) {
                        if (ignore_enoent && r == -ENOENT)
                                return 0;

                        return log_error_errno(r, "Failed to open '%s', ignoring: %m", fn);
                }

                f = rf;
                fn = pp;
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

        pager_open(arg_pager_flags);

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
               "     --image=PATH           Operate on disk image as filesystem root\n"
               "     --replace=PATH         Treat arguments as replacement for PATH\n"
               "     --dry-run              Just print what would be done\n"
               "     --inline               Treat arguments as configuration lines\n"
               "     --no-pager             Do not pipe output into a pager\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_CAT_CONFIG,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_REPLACE,
                ARG_DRY_RUN,
                ARG_INLINE,
                ARG_NO_PAGER,
        };

        static const struct option options[] = {
                { "help",       no_argument,       NULL, 'h'            },
                { "version",    no_argument,       NULL, ARG_VERSION    },
                { "cat-config", no_argument,       NULL, ARG_CAT_CONFIG },
                { "root",       required_argument, NULL, ARG_ROOT       },
                { "image",      required_argument, NULL, ARG_IMAGE      },
                { "replace",    required_argument, NULL, ARG_REPLACE    },
                { "dry-run",    no_argument,       NULL, ARG_DRY_RUN    },
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
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
#ifdef STANDALONE
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "This systemd-sysusers version is compiled without support for --image=.");
#else
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;
#endif

                case ARG_REPLACE:
                        if (!path_is_absolute(optarg) ||
                            !endswith(optarg, ".conf"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "The argument to --replace= must an absolute path to a config file");

                        arg_replace = optarg;
                        break;

                case ARG_DRY_RUN:
                        arg_dry_run = true;
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
                        assert_not_reached();
                }

        if (arg_replace && arg_cat_config)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --replace= is not supported with --cat-config");

        if (arg_replace && optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "When --replace= is given, some configuration items must be specified");

        if (arg_image && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        return 1;
}

static int parse_arguments(char **args) {
        unsigned pos = 1;
        int r;

        STRV_FOREACH(arg, args) {
                if (arg_inline)
                        /* Use (argument):n, where n==1 for the first positional arg */
                        r = parse_line("(argument)", pos, *arg);
                else
                        r = read_config_file(*arg, /* ignore_enoent= */ false);
                if (r < 0)
                        return r;

                pos++;
        }

        return 0;
}

static int read_config_files(char **args) {
        _cleanup_strv_free_ char **files = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        r = conf_files_list_with_replacement(arg_root, CONF_PATHS_STRV("sysusers.d"), arg_replace, &files, &p);
        if (r < 0)
                return r;

        STRV_FOREACH(f, files)
                if (p && path_equal(*f, p)) {
                        log_debug("Parsing arguments at position \"%s\"%s", *f, special_glyph(SPECIAL_GLYPH_ELLIPSIS));

                        r = parse_arguments(args);
                        if (r < 0)
                                return r;
                } else {
                        log_debug("Reading config file \"%s\"%s", *f, special_glyph(SPECIAL_GLYPH_ELLIPSIS));

                        /* Just warn, ignore result otherwise */
                        (void) read_config_file(*f, /* ignore_enoent= */ true);
                }

        return 0;
}

static int read_credential_lines(void) {
        _cleanup_free_ char *j = NULL;
        const char *d;
        int r;

        r = get_credentials_dir(&d);
        if (r == -ENXIO)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to get credentials directory: %m");

        j = path_join(d, "sysusers.extra");
        if (!j)
                return log_oom();

        (void) read_config_file(j, /* ignore_enoent= */ true);
        return 0;
}

static int run(int argc, char *argv[]) {
#ifndef STANDALONE
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *unlink_dir = NULL;
#endif
        _cleanup_close_ int lock = -1;
        Item *i;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        if (arg_cat_config)
                return cat_config();

        umask(0022);

        r = mac_selinux_init();
        if (r < 0)
                return r;

#ifndef STANDALONE
        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_VALIDATE_OS |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_FSCK |
                                DISSECT_IMAGE_GROWFS,
                                &unlink_dir,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(unlink_dir);
                if (!arg_root)
                        return log_oom();
        }
#else
        assert(!arg_image);
#endif

        /* If command line arguments are specified along with --replace, read all configuration files and
         * insert the positional arguments at the specified place. Otherwise, if command line arguments are
         * specified, execute just them, and finally, without --replace= or any positional arguments, just
         * read configuration and execute it. */
        if (arg_replace || optind >= argc)
                r = read_config_files(argv + optind);
        else
                r = parse_arguments(argv + optind);
        if (r < 0)
                return r;

        r = read_credential_lines();
        if (r < 0)
                return r;

        /* Let's tell nss-systemd not to synthesize the "root" and "nobody" entries for it, so that our
         * detection whether the names or UID/GID area already used otherwise doesn't get confused. After
         * all, even though nss-systemd synthesizes these users/groups, they should still appear in
         * /etc/passwd and /etc/group, as the synthesizing logic is merely supposed to be fallback for cases
         * where we run with a completely unpopulated /etc. */
        if (setenv("SYSTEMD_NSS_BYPASS_SYNTHETIC", "1", 1) < 0)
                return log_error_errno(errno, "Failed to set SYSTEMD_NSS_BYPASS_SYNTHETIC environment variable: %m");

        if (!uid_range) {
                /* Default to default range of SYSTEMD_UID_MIN..SYSTEM_UID_MAX. */
                r = read_login_defs(&login_defs, NULL, arg_root);
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s%s: %m",
                                               strempty(arg_root), "/etc/login.defs");

                login_defs_need_warning = true;

                /* We pick a range that very conservative: we look at compiled-in maximum and the value in
                 * /etc/login.defs. That way the UIDs/GIDs which we allocate will be interpreted correctly,
                 * even if /etc/login.defs is removed later. (The bottom bound doesn't matter much, since
                 * it's only used during allocation, so we use the configured value directly). */
                uid_t begin = login_defs.system_alloc_uid_min,
                      end = MIN3((uid_t) SYSTEM_UID_MAX, login_defs.system_uid_max, login_defs.system_gid_max);
                if (begin < end) {
                        r = uid_range_add(&uid_range, begin, end - begin + 1);
                        if (r < 0)
                                return log_oom();
                }
        }

        r = add_implicit();
        if (r < 0)
                return r;

        if (!arg_dry_run) {
                lock = take_etc_passwd_lock(arg_root);
                if (lock < 0)
                        return log_error_errno(lock, "Failed to take /etc/passwd lock: %m");
        }

        r = load_user_database();
        if (r < 0)
                return log_error_errno(r, "Failed to load user database: %m");

        r = load_group_database();
        if (r < 0)
                return log_error_errno(r, "Failed to read group database: %m");

        ORDERED_HASHMAP_FOREACH(i, groups)
                (void) process_item(i);

        ORDERED_HASHMAP_FOREACH(i, users)
                (void) process_item(i);

        return write_files();
}

DEFINE_MAIN_FUNCTION(run);
