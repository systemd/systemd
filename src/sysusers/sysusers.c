/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "alloc-util.h"
#include "audit-util.h"
#include "build.h"
#include "chase.h"
#include "conf-files.h"
#include "constants.h"
#include "copy.h"
#include "creds-util.h"
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
#include "uid-classification.h"
#include "uid-range.h"
#include "user-util.h"
#include "utf8.h"

typedef enum ItemType {
        ADD_USER =   'u',
        ADD_GROUP =  'g',
        ADD_MEMBER = 'm',
        ADD_RANGE =  'r',
} ItemType;

static const char* item_type_to_string(ItemType t) {
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

        char *filename;
        unsigned line;

        bool gid_set;

        /* When set the group with the specified GID must exist
         * and the check if a UID clashes with the GID is skipped.
         */
        bool id_set_strict;

        bool uid_set;

        bool locked;

        bool todo_user;
        bool todo_group;
} Item;

static char *arg_root = NULL;
static char *arg_image = NULL;
static CatFlags arg_cat_flags = CAT_CONFIG_OFF;
static const char *arg_replace = NULL;
static bool arg_dry_run = false;
static bool arg_inline = false;
static PagerFlags arg_pager_flags = 0;
static ImagePolicy *arg_image_policy = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

typedef struct Context {
        int audit_fd;

        OrderedHashmap *users, *groups;
        OrderedHashmap *todo_uids, *todo_gids;
        OrderedHashmap *members;

        Hashmap *database_by_uid, *database_by_username;
        Hashmap *database_by_gid, *database_by_groupname;

        /* A helper set to hold names that are used by database_by_{uid,gid,username,groupname} above. */
        Set *names;

        uid_t search_uid;
        UIDRange *uid_range;

        UGIDAllocationRange login_defs;
        bool login_defs_need_warning;
} Context;

static void context_done(Context *c) {
        assert(c);

        c->audit_fd = close_audit_fd(c->audit_fd);

        ordered_hashmap_free(c->groups);
        ordered_hashmap_free(c->users);
        ordered_hashmap_free(c->members);
        ordered_hashmap_free(c->todo_uids);
        ordered_hashmap_free(c->todo_gids);

        hashmap_free(c->database_by_uid);
        hashmap_free(c->database_by_username);
        hashmap_free(c->database_by_gid);
        hashmap_free(c->database_by_groupname);

        set_free_free(c->names);
        uid_range_free(c->uid_range);
}

static void maybe_emit_login_defs_warning(Context *c) {
        assert(c);

        if (!c->login_defs_need_warning)
                return;

        if (c->login_defs.system_alloc_uid_min != SYSTEM_ALLOC_UID_MIN ||
            c->login_defs.system_uid_max != SYSTEM_UID_MAX)
                log_warning("login.defs specifies UID allocation range "UID_FMT"–"UID_FMT
                            " that is different than the built-in defaults ("UID_FMT"–"UID_FMT")",
                            c->login_defs.system_alloc_uid_min, c->login_defs.system_uid_max,
                            (uid_t) SYSTEM_ALLOC_UID_MIN, (uid_t) SYSTEM_UID_MAX);
        if (c->login_defs.system_alloc_gid_min != SYSTEM_ALLOC_GID_MIN ||
            c->login_defs.system_gid_max != SYSTEM_GID_MAX)
                log_warning("login.defs specifies GID allocation range "GID_FMT"–"GID_FMT
                            " that is different than the built-in defaults ("GID_FMT"–"GID_FMT")",
                            c->login_defs.system_alloc_gid_min, c->login_defs.system_gid_max,
                            (gid_t) SYSTEM_ALLOC_GID_MIN, (gid_t) SYSTEM_GID_MAX);

        c->login_defs_need_warning = false;
}

static void log_audit_accounts(Context *c, ItemType what) {
#if HAVE_AUDIT
        assert(c);
        assert(IN_SET(what, ADD_USER, ADD_GROUP));

        if (arg_dry_run || c->audit_fd < 0)
                return;

        Item *i;
        int type = what == ADD_USER ? AUDIT_ADD_USER : AUDIT_ADD_GROUP;
        const char *op = what == ADD_USER ? "adding-user" : "adding-group";

        /* Notes:
         *
         * The op must not contain whitespace. The format with a dash matches what Fedora shadow-utils uses.
         *
         * We send id == -1, even though we know the number, in particular on success. This is because if we
         * send the id, the generated audit message will not contain the name. The name seems more useful
         * than the number, hence send just the name:
         *
         * type=ADD_USER msg=audit(01/10/2025 16:02:00.639:3854) :
         *   pid=3846380 uid=root auid=zbyszek ses=2 msg='op=adding-user id=unknown(952) exe=systemd-sysusers ... res=success'
         * vs.
         * type=ADD_USER msg=audit(01/10/2025 16:03:15.457:3908) :
         *   pid=3846607 uid=root auid=zbyszek ses=2 msg='op=adding-user acct=foo5 exe=systemd-sysusers ... res=success'
         */

        ORDERED_HASHMAP_FOREACH(i, what == ADD_USER ? c->todo_uids : c->todo_gids)
                audit_log_acct_message(
                                c->audit_fd,
                                type,
                                program_invocation_short_name,
                                op,
                                i->name,
                                /* id= */ (unsigned) -1,
                                /* host= */ NULL,
                                /* addr= */ NULL,
                                /* tty= */ NULL,
                                /* success= */ 1);
#endif
}

static int load_user_database(Context *c) {
        _cleanup_free_ char *passwd_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        struct passwd *pw;
        int r;

        assert(c);

        r = chase_and_fopen_unlocked("/etc/passwd", arg_root, CHASE_PREFIX_ROOT, "re", &passwd_path, &f);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        while ((r = fgetpwent_sane(f, &pw)) > 0) {

                char *n = strdup(pw->pw_name);
                if (!n)
                        return -ENOMEM;

                /* Note that we use NULL hash_ops (i.e. trivial_hash_ops) here, so identical strings can
                 * exist in the set. */
                r = set_ensure_consume(&c->names, /* hash_ops= */ NULL, n);
                if (r < 0)
                        return r;
                assert(r > 0);  /* The set uses pointer comparisons, so n must not be in the set. */

                r = hashmap_ensure_put(&c->database_by_username, &string_hash_ops, n, UID_TO_PTR(pw->pw_uid));
                if (r == -EEXIST)
                        log_debug_errno(r, "%s: user '%s' is listed twice, ignoring duplicate uid.",
                                        passwd_path, n);
                else if (r < 0)
                        return r;

                r = hashmap_ensure_put(&c->database_by_uid, /* hash_ops= */ NULL, UID_TO_PTR(pw->pw_uid), n);
                if (r == -EEXIST)
                        log_debug_errno(r, "%s: uid "UID_FMT" is listed twice, ignoring duplicate name.",
                                        passwd_path, pw->pw_uid);
                else if (r < 0)
                        return r;
        }
        return r;
}

static int load_group_database(Context *c) {
        _cleanup_free_ char *group_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        struct group *gr;
        int r;

        assert(c);

        r = chase_and_fopen_unlocked("/etc/group", arg_root, CHASE_PREFIX_ROOT, "re", &group_path, &f);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        while ((r = fgetgrent_sane(f, &gr)) > 0) {
                char *n = strdup(gr->gr_name);
                if (!n)
                        return -ENOMEM;

                /* Note that we use NULL hash_ops (i.e. trivial_hash_ops) here, so identical strings can
                 * exist in the set. */
                r = set_ensure_consume(&c->names, /* hash_ops= */ NULL, n);
                if (r < 0)
                        return r;
                assert(r > 0);  /* The set uses pointer comparisons, so n must not be in the set. */

                r = hashmap_ensure_put(&c->database_by_groupname, &string_hash_ops, n, GID_TO_PTR(gr->gr_gid));
                if (r == -EEXIST)
                        log_debug_errno(r, "%s: group '%s' is listed twice, ignoring duplicate gid.",
                                        group_path, n);
                else if (r < 0)
                        return r;

                r = hashmap_ensure_put(&c->database_by_gid, /* hash_ops= */ NULL, GID_TO_PTR(gr->gr_gid), n);
                if (r == -EEXIST)
                        log_debug_errno(r, "%s: gid "GID_FMT" is listed twice, ignoring duplicate name.",
                                        group_path, gr->gr_gid);
                else if (r < 0)
                        return r;
        }
        return r;
}

static int make_backup(const char *target, const char *x) {
        _cleanup_(unlink_and_freep) char *dst_tmp = NULL;
        _cleanup_fclose_ FILE *dst = NULL;
        _cleanup_close_ int src = -EBADF;
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

static int putgrent_with_members(
                Context *c,
                const struct group *gr,
                FILE *group) {

        char **a;
        int r;

        assert(c);
        assert(gr);
        assert(group);

        a = ordered_hashmap_get(c->members, gr->gr_name);
        if (a) {
                _cleanup_strv_free_ char **l = NULL;
                bool added = false;

                l = strv_copy(gr->gr_mem);
                if (!l)
                        return -ENOMEM;

                STRV_FOREACH(i, a) {
                        if (strv_contains(l, *i))
                                continue;

                        r = strv_extend(&l, *i);
                        if (r < 0)
                                return r;

                        added = true;
                }

                if (added) {
                        struct group t;

                        strv_sort_uniq(l);

                        t = *gr;
                        t.gr_mem = l;

                        r = putgrent_sane(&t, group);
                        return r < 0 ? r : 1;
                }
        }

        return putgrent_sane(gr, group);
}

#if ENABLE_GSHADOW
static int putsgent_with_members(
                Context *c,
                const struct sgrp *sg,
                FILE *gshadow) {

        char **a;
        int r;

        assert(sg);
        assert(gshadow);

        a = ordered_hashmap_get(c->members, sg->sg_namp);
        if (a) {
                _cleanup_strv_free_ char **l = NULL;
                bool added = false;

                l = strv_copy(sg->sg_mem);
                if (!l)
                        return -ENOMEM;

                STRV_FOREACH(i, a) {
                        if (strv_contains(l, *i))
                                continue;

                        r = strv_extend(&l, *i);
                        if (r < 0)
                                return r;

                        added = true;
                }

                if (added) {
                        struct sgrp t;

                        strv_sort_uniq(l);

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
        assert(i);

        if (i->type != ADD_USER)
                return NULL;
        if (i->shell)
                return i->shell;
        if (i->uid_set && i->uid == 0)
                return default_root_shell(arg_root);
        return NOLOGIN;
}

static int write_temporary_passwd(
                Context *c,
                const char *passwd_path,
                FILE **ret_tmpfile,
                char **ret_tmpfile_path) {

        _cleanup_fclose_ FILE *original = NULL, *passwd = NULL;
        _cleanup_(unlink_and_freep) char *passwd_tmp = NULL;
        struct passwd *pw = NULL;
        Item *i;
        int r;

        assert(c);

        if (ordered_hashmap_isempty(c->todo_uids))
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
                        i = ordered_hashmap_get(c->users, pw->pw_name);
                        if (i && i->todo_user)
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: User \"%s\" already exists.",
                                                       passwd_path, pw->pw_name);

                        if (ordered_hashmap_contains(c->todo_uids, UID_TO_PTR(pw->pw_uid)))
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

        ORDERED_HASHMAP_FOREACH(i, c->todo_uids) {
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
                                               i->name);
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

        *ret_tmpfile = TAKE_PTR(passwd);
        *ret_tmpfile_path = TAKE_PTR(passwd_tmp);

        return 0;
}

static usec_t epoch_or_now(void) {
        uint64_t epoch;

        if (secure_getenv_uint64("SOURCE_DATE_EPOCH", &epoch) >= 0) {
                if (epoch > UINT64_MAX/USEC_PER_SEC) /* Overflow check */
                        return USEC_INFINITY;
                return (usec_t) epoch * USEC_PER_SEC;
        }

        return now(CLOCK_REALTIME);
}

static int write_temporary_shadow(
                Context *c,
                const char *shadow_path,
                FILE **ret_tmpfile,
                char **ret_tmpfile_path) {

        _cleanup_fclose_ FILE *original = NULL, *shadow = NULL;
        _cleanup_(unlink_and_freep) char *shadow_tmp = NULL;
        struct spwd *sp = NULL;
        long lstchg;
        Item *i;
        int r;

        assert(c);

        if (ordered_hashmap_isempty(c->todo_uids))
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
                        i = ordered_hashmap_get(c->users, sp->sp_namp);
                        if (i && i->todo_user) {
                                /* we will update the existing entry */
                                sp->sp_lstchg = lstchg;

                                /* only the /etc/shadow stage is left, so we can
                                 * safely remove the item from the todo set */
                                i->todo_user = false;
                                ordered_hashmap_remove(c->todo_uids, UID_TO_PTR(i->uid));
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

        ORDERED_HASHMAP_FOREACH(i, c->todo_uids) {
                _cleanup_(erase_and_freep) char *creds_password = NULL;
                bool is_hashed;

                struct spwd n = {
                        .sp_namp = i->name,
                        .sp_lstchg = lstchg,
                        .sp_min = -1,
                        .sp_max = -1,
                        .sp_warn = -1,
                        .sp_inact = -1,
                        .sp_expire = i->locked ? 1 : -1, /* Negative expiration means "unset". Expiration 0 or 1 means "locked" */
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
                else if (streq(i->name, "root"))
                        /* Let firstboot set the password later */
                        n.sp_pwdp = (char*) PASSWORD_UNPROVISIONED;
                else
                        n.sp_pwdp = (char*) PASSWORD_LOCKED_AND_INVALID;

                r = putspent_sane(&n, shadow);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add new user \"%s\" to temporary shadow file: %m",
                                               i->name);
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

        *ret_tmpfile = TAKE_PTR(shadow);
        *ret_tmpfile_path = TAKE_PTR(shadow_tmp);

        return 0;
}

static int write_temporary_group(
                Context *c,
                const char *group_path,
                FILE **ret_tmpfile,
                char **ret_tmpfile_path) {

        _cleanup_fclose_ FILE *original = NULL, *group = NULL;
        _cleanup_(unlink_and_freep) char *group_tmp = NULL;
        bool group_changed = false;
        struct group *gr = NULL;
        Item *i;
        int r;

        assert(c);

        if (ordered_hashmap_isempty(c->todo_gids) && ordered_hashmap_isempty(c->members))
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

                        i = ordered_hashmap_get(c->groups, gr->gr_name);
                        if (i && i->todo_group)
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: Group \"%s\" already exists.",
                                                       group_path, gr->gr_name);

                        if (ordered_hashmap_contains(c->todo_gids, GID_TO_PTR(gr->gr_gid)))
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: Detected collision for GID " GID_FMT ".",
                                                       group_path, gr->gr_gid);

                        /* Make sure we keep the NIS entries (if any) at the end. */
                        if (IN_SET(gr->gr_name[0], '+', '-'))
                                break;

                        r = putgrent_with_members(c, gr, group);
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

        ORDERED_HASHMAP_FOREACH(i, c->todo_gids) {
                struct group n = {
                        .gr_name = i->name,
                        .gr_gid = i->gid,
                        .gr_passwd = (char*) PASSWORD_SEE_SHADOW,
                };

                r = putgrent_with_members(c, &n, group);
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
                *ret_tmpfile = TAKE_PTR(group);
                *ret_tmpfile_path = TAKE_PTR(group_tmp);
        }
        return 0;
}

static int write_temporary_gshadow(
                Context *c,
                const char * gshadow_path,
                FILE **ret_tmpfile,
                char **ret_tmpfile_path) {

#if ENABLE_GSHADOW
        _cleanup_fclose_ FILE *original = NULL, *gshadow = NULL;
        _cleanup_(unlink_and_freep) char *gshadow_tmp = NULL;
        bool group_changed = false;
        Item *i;
        int r;

        assert(c);

        if (ordered_hashmap_isempty(c->todo_gids) && ordered_hashmap_isempty(c->members))
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

                        i = ordered_hashmap_get(c->groups, sg->sg_namp);
                        if (i && i->todo_group)
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: Group \"%s\" already exists.",
                                                       gshadow_path, sg->sg_namp);

                        r = putsgent_with_members(c, sg, gshadow);
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

        ORDERED_HASHMAP_FOREACH(i, c->todo_gids) {
                struct sgrp n = {
                        .sg_namp = i->name,
                        .sg_passwd = (char*) PASSWORD_LOCKED_AND_INVALID,
                };

                r = putsgent_with_members(c, &n, gshadow);
                if (r < 0)
                        return log_error_errno(r, "Failed to add new group \"%s\" to temporary gshadow file: %m",
                                               n.sg_namp);

                group_changed = true;
        }

        r = fflush_sync_and_check(gshadow);
        if (r < 0)
                return log_error_errno(r, "Failed to flush %s: %m", gshadow_tmp);

        if (group_changed) {
                *ret_tmpfile = TAKE_PTR(gshadow);
                *ret_tmpfile_path = TAKE_PTR(gshadow_tmp);
        }
#endif
        return 0;
}

static int write_files(Context *c) {
        _cleanup_fclose_ FILE *passwd = NULL, *group = NULL, *shadow = NULL, *gshadow = NULL;
        _cleanup_(unlink_and_freep) char *passwd_tmp = NULL, *group_tmp = NULL, *shadow_tmp = NULL, *gshadow_tmp = NULL;
        int r;

        const char
                *passwd_path = prefix_roota(arg_root, "/etc/passwd"),
                *shadow_path = prefix_roota(arg_root, "/etc/shadow"),
                *group_path = prefix_roota(arg_root, "/etc/group"),
                *gshadow_path = prefix_roota(arg_root, "/etc/gshadow");

        assert(c);

        r = write_temporary_group(c, group_path, &group, &group_tmp);
        if (r < 0)
                return r;

        r = write_temporary_gshadow(c, gshadow_path, &gshadow, &gshadow_tmp);
        if (r < 0)
                return r;

        r = write_temporary_passwd(c, passwd_path, &passwd, &passwd_tmp);
        if (r < 0)
                return r;

        r = write_temporary_shadow(c, shadow_path, &shadow, &shadow_tmp);
        if (r < 0)
                return r;

        /* Make a backup of the old files */
        if (group) {
                r = make_backup("/etc/group", group_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to backup %s: %m", group_path);
        }
        if (gshadow) {
                r = make_backup("/etc/gshadow", gshadow_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to backup %s: %m", gshadow_path);
        }

        if (passwd) {
                r = make_backup("/etc/passwd", passwd_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to backup %s: %m", passwd_path);
        }
        if (shadow) {
                r = make_backup("/etc/shadow", shadow_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to backup %s: %m", shadow_path);
        }

        /* And make the new files count */
        if (group) {
                r = rename_and_apply_smack_floor_label(group_tmp, group_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to rename %s to %s: %m",
                                               group_tmp, group_path);
                group_tmp = mfree(group_tmp);
        }
        /* OK, we have written the group entries successfully */
        log_audit_accounts(c, ADD_GROUP);
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
        }
        /* OK, we have written the user entries successfully */
        log_audit_accounts(c, ADD_USER);
        if (shadow) {
                r = rename_and_apply_smack_floor_label(shadow_tmp, shadow_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to rename %s to %s: %m",
                                               shadow_tmp, shadow_path);

                shadow_tmp = mfree(shadow_tmp);
        }

        return 0;
}

static int uid_is_ok(
                Context *c,
                uid_t uid,
                const char *name,
                bool check_with_gid) {

        int r;
        assert(c);

        /* Let's see if we already have assigned the UID a second time */
        if (ordered_hashmap_get(c->todo_uids, UID_TO_PTR(uid)))
                return 0;

        /* Try to avoid using uids that are already used by a group
         * that doesn't have the same name as our new user. */
        if (check_with_gid) {
                Item *i;

                i = ordered_hashmap_get(c->todo_gids, GID_TO_PTR(uid));
                if (i && !streq(i->name, name))
                        return 0;
        }

        /* Let's check the files directly */
        if (hashmap_contains(c->database_by_uid, UID_TO_PTR(uid)))
                return 0;

        if (check_with_gid) {
                const char *n;

                n = hashmap_get(c->database_by_gid, GID_TO_PTR(uid));
                if (n && !streq(n, name))
                        return 0;
        }

        /* Let's also check via NSS, to avoid UID clashes over LDAP and such, just in case */
        if (!arg_root) {
                _cleanup_free_ struct group *g = NULL;

                r = getpwuid_malloc(uid, /* ret= */ NULL);
                if (r >= 0)
                        return 0;
                if (r != -ESRCH)
                        log_warning_errno(r, "Unexpected failure while looking up UID '" UID_FMT "' via NSS, assuming it doesn't exist: %m", uid);

                if (check_with_gid) {
                        r = getgrgid_malloc((gid_t) uid, &g);
                        if (r >= 0) {
                                if (!streq(g->gr_name, name))
                                        return 0;
                        } else if (r != -ESRCH)
                                log_warning_errno(r, "Unexpected failure while looking up GID '" GID_FMT "' via NSS, assuming it doesn't exist: %m", uid);
                }
        }

        return 1;
}

static int root_stat(const char *p, struct stat *ret_st) {
        return chase_and_stat(p, arg_root, CHASE_PREFIX_ROOT, /* ret_path= */ NULL, ret_st);
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

static int add_user(Context *c, Item *i) {
        void *z;
        int r;

        assert(c);
        assert(i);

        /* Check the database directly */
        z = hashmap_get(c->database_by_username, i->name);
        if (z) {
                log_debug("User %s already exists.", i->name);
                i->uid = PTR_TO_UID(z);
                i->uid_set = true;
                return 0;
        }

        if (!arg_root) {
                _cleanup_free_ struct passwd *p = NULL;

                /* Also check NSS */
                r = getpwnam_malloc(i->name, &p);
                if (r >= 0) {
                        log_debug("User %s already exists.", i->name);
                        i->uid = p->pw_uid;
                        i->uid_set = true;

                        r = free_and_strdup(&i->description, p->pw_gecos);
                        if (r < 0)
                                return log_oom();

                        return 0;
                }
                if (r != -ESRCH)
                        log_warning_errno(r, "Unexpected failure while looking up user '%s' via NSS, assuming it doesn't exist: %m", i->name);
        }

        /* Try to use the suggested numeric UID */
        if (i->uid_set) {
                r = uid_is_ok(c, i->uid, i->name, !i->id_set_strict);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify UID " UID_FMT ": %m", i->uid);
                if (r == 0) {
                        log_info("Suggested user ID " UID_FMT " for %s already used.", i->uid, i->name);
                        i->uid_set = false;
                }
        }

        /* If that didn't work, try to read it from the specified path */
        if (!i->uid_set) {
                uid_t candidate;

                if (read_id_from_file(i, &candidate, NULL) > 0) {

                        if (candidate <= 0 || !uid_range_contains(c->uid_range, candidate))
                                log_debug("User ID " UID_FMT " of file not suitable for %s.", candidate, i->name);
                        else {
                                r = uid_is_ok(c, candidate, i->name, true);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to verify UID " UID_FMT ": %m", i->uid);
                                else if (r > 0) {
                                        i->uid = candidate;
                                        i->uid_set = true;
                                } else
                                        log_debug("User ID " UID_FMT " of file for %s is already used.", candidate, i->name);
                        }
                }
        }

        /* Otherwise, try to reuse the group ID */
        if (!i->uid_set && i->gid_set) {
                r = uid_is_ok(c, (uid_t) i->gid, i->name, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify UID " UID_FMT ": %m", i->uid);
                if (r > 0) {
                        i->uid = (uid_t) i->gid;
                        i->uid_set = true;
                }
        }

        /* And if that didn't work either, let's try to find a free one */
        if (!i->uid_set) {
                maybe_emit_login_defs_warning(c);

                for (;;) {
                        r = uid_range_next_lower(c->uid_range, &c->search_uid);
                        if (r < 0)
                                return log_error_errno(r, "No free user ID available for %s.", i->name);

                        r = uid_is_ok(c, c->search_uid, i->name, true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to verify UID " UID_FMT ": %m", i->uid);
                        else if (r > 0)
                                break;
                }

                i->uid_set = true;
                i->uid = c->search_uid;
        }

        r = ordered_hashmap_ensure_put(&c->todo_uids, NULL, UID_TO_PTR(i->uid), i);
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

static int gid_is_ok(
                Context *c,
                gid_t gid,
                const char *groupname,
                bool check_with_uid) {

        Item *user;
        char *username;
        int r;

        assert(c);
        assert(groupname);

        if (ordered_hashmap_get(c->todo_gids, GID_TO_PTR(gid)))
                return 0;

        /* Avoid reusing gids that are already used by a different user */
        if (check_with_uid) {
                user = ordered_hashmap_get(c->todo_uids, UID_TO_PTR(gid));
                if (user && !streq(user->name, groupname))
                        return 0;
        }

        if (hashmap_contains(c->database_by_gid, GID_TO_PTR(gid)))
                return 0;

        if (check_with_uid) {
                username = hashmap_get(c->database_by_uid, UID_TO_PTR(gid));
                if (username && !streq(username, groupname))
                        return 0;
        }

        if (!arg_root) {
                r = getgrgid_malloc(gid, /* ret= */ NULL);
                if (r >= 0)
                        return 0;
                if (r != -ESRCH)
                        log_warning_errno(r, "Unexpected failure while looking up GID '" GID_FMT "' via NSS, assuming it doesn't exist: %m", gid);

                if (check_with_uid) {
                        r = getpwuid_malloc(gid, /* ret= */ NULL);
                        if (r >= 0)
                                return 0;
                        if (r != -ESRCH)
                                log_warning_errno(r, "Unexpected failure while looking up GID '" GID_FMT "' via NSS, assuming it doesn't exist: %m", gid);
                }
        }

        return 1;
}

static int get_gid_by_name(
                Context *c,
                const char *name,
                gid_t *ret_gid) {

        void *z;
        int r;

        assert(c);
        assert(ret_gid);

        /* Check the database directly */
        z = hashmap_get(c->database_by_groupname, name);
        if (z) {
                *ret_gid = PTR_TO_GID(z);
                return 0;
        }

        /* Also check NSS */
        if (!arg_root) {
                _cleanup_free_ struct group *g = NULL;

                r = getgrnam_malloc(name, &g);
                if (r >= 0) {
                        *ret_gid = g->gr_gid;
                        return 0;
                }
                if (r != -ESRCH)
                        log_warning_errno(r, "Unexpected failure while looking up group '%s' via NSS, assuming it doesn't exist: %m", name);
        }

        return -ENOENT;
}

static int add_group(Context *c, Item *i) {
        int r;

        assert(c);
        assert(i);

        r = get_gid_by_name(c, i->name, &i->gid);
        if (r != -ENOENT) {
                if (r < 0)
                        return r;
                log_debug("Group %s already exists.", i->name);
                i->gid_set = true;
                return 0;
        }

        /* Try to use the suggested numeric GID */
        if (i->gid_set) {
                r = gid_is_ok(c, i->gid, i->name, false);
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
                r = gid_is_ok(c, (gid_t) i->uid, i->name, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify GID " GID_FMT ": %m", i->gid);
                if (r > 0) {
                        i->gid = (gid_t) i->uid;
                        i->gid_set = true;
                }
        }

        /* If that didn't work, try to read it from the specified path */
        if (!i->gid_set) {
                gid_t candidate;

                if (read_id_from_file(i, NULL, &candidate) > 0) {

                        if (candidate <= 0 || !uid_range_contains(c->uid_range, candidate))
                                log_debug("Group ID " GID_FMT " of file not suitable for %s.", candidate, i->name);
                        else {
                                r = gid_is_ok(c, candidate, i->name, true);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to verify GID " GID_FMT ": %m", i->gid);
                                else if (r > 0) {
                                        i->gid = candidate;
                                        i->gid_set = true;
                                } else
                                        log_debug("Group ID " GID_FMT " of file for %s already used.", candidate, i->name);
                        }
                }
        }

        /* And if that didn't work either, let's try to find a free one */
        if (!i->gid_set) {
                maybe_emit_login_defs_warning(c);

                for (;;) {
                        /* We look for new GIDs in the UID pool! */
                        r = uid_range_next_lower(c->uid_range, &c->search_uid);
                        if (r < 0)
                                return log_error_errno(r, "No free group ID available for %s.", i->name);

                        r = gid_is_ok(c, c->search_uid, i->name, true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to verify GID " GID_FMT ": %m", i->gid);
                        else if (r > 0)
                                break;
                }

                i->gid_set = true;
                i->gid = c->search_uid;
        }

        r = ordered_hashmap_ensure_put(&c->todo_gids, NULL, GID_TO_PTR(i->gid), i);
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

static int process_item(Context *c, Item *i) {
        int r;

        assert(c);
        assert(i);

        switch (i->type) {

        case ADD_USER: {
                Item *j = NULL;

                if (!i->gid_set) {
                        j = ordered_hashmap_get(c->groups, i->group_name ?: i->name);

                        /* If that's not a match, also check if the group name
                         * matches a user name in the queue. */
                        if (!j && i->group_name)
                                j = ordered_hashmap_get(c->users, i->group_name);
                }

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
                        r = get_gid_by_name(c, i->group_name, &i->gid);
                        if (r < 0)
                                return log_error_errno(r, "Group %s not found.", i->group_name);
                        i->gid_set = true;
                        i->id_set_strict = true;
                } else {
                        r = add_group(c, i);
                        if (r < 0)
                                return r;
                }

                return add_user(c, i);
        }

        case ADD_GROUP:
                return add_group(c, i);

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
        free(i->filename);
        return mfree(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Item*, item_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(item_hash_ops, char, string_hash_func, string_compare_func, Item, item_free);

static Item* item_new(ItemType type, const char *name, const char *filename, unsigned line) {
        assert(name);
        assert(!!filename == (line > 0));

        _cleanup_(item_freep) Item *new = new(Item, 1);
        if (!new)
                return NULL;

        *new = (Item) {
                .type = type,
                .line = line,
        };

        if (free_and_strdup(&new->name, name) < 0 ||
            free_and_strdup(&new->filename, filename) < 0)
                return NULL;

        return TAKE_PTR(new);
}

static int add_implicit(Context *c) {
        char *g, **l;
        int r;

        assert(c);

        /* Implicitly create additional users and groups, if they were listed in "m" lines */
        ORDERED_HASHMAP_FOREACH_KEY(l, g, c->members) {
                STRV_FOREACH(m, l)
                        if (!ordered_hashmap_get(c->users, *m)) {
                                _cleanup_(item_freep) Item *j =
                                        item_new(ADD_USER, *m, /* filename= */ NULL, /* line= */ 0);
                                if (!j)
                                        return log_oom();

                                r = ordered_hashmap_ensure_put(&c->users, &item_hash_ops, j->name, j);
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0)
                                        return log_error_errno(r, "Failed to add implicit user '%s': %m", j->name);

                                log_debug("Adding implicit user '%s' due to m line", j->name);
                                TAKE_PTR(j);
                        }

                if (!(ordered_hashmap_get(c->users, g) ||
                      ordered_hashmap_get(c->groups, g))) {
                        _cleanup_(item_freep) Item *j =
                                item_new(ADD_GROUP, g, /* filename= */ NULL, /* line= */ 0);
                        if (!j)
                                return log_oom();

                        r = ordered_hashmap_ensure_put(&c->groups, &item_hash_ops, j->name, j);
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

        if (a->type != b->type) {
                log_syntax(NULL, LOG_DEBUG, a->filename, a->line, 0,
                           "Item not equivalent because types differ");
                return false;
        }

        if (!streq_ptr(a->name, b->name)) {
                log_syntax(NULL, LOG_DEBUG, a->filename, a->line, 0,
                           "Item not equivalent because names differ ('%s' vs. '%s')",
                           a->name, b->name);
                return false;
        }

        /* Paths were simplified previously, so we can use streq. */
        if (!streq_ptr(a->uid_path, b->uid_path)) {
                log_syntax(NULL, LOG_DEBUG, a->filename, a->line, 0,
                           "Item not equivalent because UID paths differ (%s vs. %s)",
                           a->uid_path ?: "(unset)", b->uid_path ?: "(unset)");
                return false;
        }

        if (!streq_ptr(a->gid_path, b->gid_path)) {
                log_syntax(NULL, LOG_DEBUG, a->filename, a->line, 0,
                           "Item not equivalent because GID paths differ (%s vs. %s)",
                           a->gid_path ?: "(unset)", b->gid_path ?: "(unset)");
                return false;
        }

        if (!streq_ptr(a->description, b->description))  {
                log_syntax(NULL, LOG_DEBUG, a->filename, a->line, 0,
                           "Item not equivalent because descriptions differ ('%s' vs. '%s')",
                           strempty(a->description), strempty(b->description));
                return false;
        }

        if ((a->uid_set != b->uid_set) ||
            (a->uid_set && a->uid != b->uid)) {
                log_syntax(NULL, LOG_DEBUG, a->filename, a->line, 0,
                           "Item not equivalent because UIDs differ (%s vs. %s)",
                           a->uid_set ? FORMAT_UID(a->uid) : "(unset)",
                           b->uid_set ? FORMAT_UID(b->uid) : "(unset)");
                return false;
        }

        if ((a->gid_set != b->gid_set) ||
            (a->gid_set && a->gid != b->gid)) {
                log_syntax(NULL, LOG_DEBUG, a->filename, a->line, 0,
                           "Item not equivalent because GIDs differ (%s vs. %s)",
                           a->gid_set ? FORMAT_GID(a->gid) : "(unset)",
                           b->gid_set ? FORMAT_GID(b->gid) : "(unset)");
                return false;
        }

        if (!streq_ptr(a->home, b->home)) {
                log_syntax(NULL, LOG_DEBUG, a->filename, a->line, 0,
                           "Item not equivalent because home directories differ ('%s' vs. '%s')",
                           strempty(a->description), strempty(b->description));
                return false;
        }

        /* Check if the two paths refer to the same file.
         * If the paths are equal (after normalization), it's obviously the same file.
         * If both paths specify a nologin shell, treat them as the same (e.g. /bin/true and /bin/false).
         * Otherwise, try to resolve the paths, and see if we get the same result, (e.g. /sbin/nologin and
         * /usr/sbin/nologin).
         * If we can't resolve something, treat different paths as different. */

        const char *a_shell = pick_shell(a),
                   *b_shell = pick_shell(b);
        if (!path_equal(a_shell, b_shell) &&
            !(is_nologin_shell(a_shell) && is_nologin_shell(b_shell))) {
                _cleanup_free_ char *pa = NULL, *pb = NULL;

                r = chase(a_shell, arg_root, CHASE_PREFIX_ROOT | CHASE_NONEXISTENT, &pa, NULL);
                if (r < 0) {
                        log_full_errno(ERRNO_IS_RESOURCE(r) ? LOG_ERR : LOG_DEBUG,
                                       r, "Failed to look up path '%s%s%s': %m",
                                       strempty(arg_root), arg_root ? "/" : "", a_shell);
                        return ERRNO_IS_RESOURCE(r) ? r : false;
                }

                r = chase(b_shell, arg_root, CHASE_PREFIX_ROOT | CHASE_NONEXISTENT, &pb, NULL);
                if (r < 0) {
                        log_full_errno(ERRNO_IS_RESOURCE(r) ? LOG_ERR : LOG_DEBUG,
                                       r, "Failed to look up path '%s%s%s': %m",
                                       strempty(arg_root), arg_root ? "/" : "", b_shell);
                        return ERRNO_IS_RESOURCE(r) ? r : false;
                }

                if (!path_equal(pa, pb)) {
                        log_syntax(NULL, LOG_DEBUG, a->filename, a->line, 0,
                                   "Item not equivalent because shells differ ('%s' vs. '%s')",
                                   pa, pb);
                        return false;
                }
        }

        return true;
}

static int parse_line(
                const char *fname,
                unsigned line,
                const char *buffer,
                bool *invalid_config,
                void *context) {

        Context *c = ASSERT_PTR(context);
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
        assert(!invalid_config); /* We don't support invalid_config yet. */

        /* Parse columns */
        p = buffer;
        r = extract_many_words(&p, NULL, EXTRACT_UNQUOTE,
                               &action, &name, &id, &description, &home, &shell);
        if (r < 0)
                return log_syntax(NULL, LOG_ERR, fname, line, r, "Syntax error.");
        if (r < 2)
                return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                  "Missing action and name columns.");
        if (!isempty(p))
                return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                  "Trailing garbage.");

        if (isempty(action))
                return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EBADMSG),
                                  "Empty command specification.");

        bool locked = false;
        for (int pos = 1; action[pos]; pos++)
                if (action[pos] == '!' && !locked)
                        locked = true;
                else
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EBADMSG),
                                          "Unknown modifiers in command '%s'.", action);

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
                if (locked)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Flag '!' not permitted on lines of type 'r'.");

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

                r = uid_range_add_str(&c->uid_range, resolved_id);
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Invalid UID range %s.", resolved_id);

                return 0;

        case ADD_MEMBER: {
                /* Try to extend an existing member or group item */
                if (!name)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type 'm' require a user name in the second field.");

                if (locked)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Flag '!' not permitted on lines of type 'm'.");

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

                r = string_strv_ordered_hashmap_put(&c->members, resolved_id, resolved_name);
                if (r < 0)
                        return log_error_errno(r, "Failed to store mapping for %s: %m", resolved_id);

                return 0;
        }

        case ADD_USER:
                if (!name)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type 'u' require a user name in the second field.");

                r = ordered_hashmap_ensure_allocated(&c->users, &item_hash_ops);
                if (r < 0)
                        return log_oom();

                i = item_new(ADD_USER, resolved_name, fname, line);
                if (!i)
                        return log_oom();

                if (resolved_id) {
                        if (path_is_absolute(resolved_id))
                                i->uid_path = path_simplify(TAKE_PTR(resolved_id));
                        else {
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
                i->locked = locked;

                h = c->users;
                break;

        case ADD_GROUP:
                if (!name)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type 'g' require a user name in the second field.");

                if (locked)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Flag '!' not permitted on lines of type 'g'.");

                if (description || home || shell)
                        return log_syntax(NULL, LOG_ERR, fname, line, SYNTHETIC_ERRNO(EINVAL),
                                          "Lines of type '%c' don't take a %s field.",
                                          action[0],
                                          description ? "GECOS" : home ? "home directory" : "login shell");

                r = ordered_hashmap_ensure_allocated(&c->groups, &item_hash_ops);
                if (r < 0)
                        return log_oom();

                i = item_new(ADD_GROUP, resolved_name, fname, line);
                if (!i)
                        return log_oom();

                if (resolved_id) {
                        if (path_is_absolute(resolved_id))
                                i->gid_path = path_simplify(TAKE_PTR(resolved_id));
                        else {
                                r = parse_gid(resolved_id, &i->gid);
                                if (r < 0)
                                        return log_syntax(NULL, LOG_ERR, fname, line, r,
                                                          "Failed to parse GID: '%s': %m", id);

                                i->gid_set = true;
                        }
                }

                h = c->groups;
                break;

        default:
                assert_not_reached();
        }

        existing = ordered_hashmap_get(h, i->name);
        if (existing) {
                /* Two functionally-equivalent items are fine */
                r = item_equivalent(i, existing);
                if (r < 0)
                        return r;
                if (r == 0) {
                        if (existing->filename)
                                log_syntax(NULL, LOG_WARNING, fname, line, 0,
                                           "Conflict with earlier configuration for %s '%s' in %s:%u, ignoring line.",
                                           item_type_to_string(i->type),
                                           i->name,
                                           existing->filename, existing->line);
                        else
                                log_syntax(NULL, LOG_WARNING, fname, line, 0,
                                           "Conflict with earlier configuration for %s '%s', ignoring line.",
                                           item_type_to_string(i->type),
                                           i->name);
                }

                return 0;
        }

        r = ordered_hashmap_put(h, i->name, i);
        if (r < 0)
                return log_oom();

        i = NULL;
        return 0;
}

static int read_config_file(Context *c, const char *fn, bool ignore_enoent) {
        return conf_file_read(
                        arg_root,
                        (const char**) CONF_PATHS_STRV("sysusers.d"),
                        ASSERT_PTR(fn),
                        parse_line,
                        ASSERT_PTR(c),
                        ignore_enoent,
                        /* invalid_config= */ NULL);
}

static int cat_config(void) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        r = conf_files_list_with_replacement(arg_root, CONF_PATHS_STRV("sysusers.d"), arg_replace, &files, NULL);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        return cat_files(NULL, files, arg_cat_flags);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-sysusers.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [CONFIGURATION FILE...]\n"
               "\n%2$sCreates system user and group accounts.%4$s\n"
               "\n%3$sCommands:%4$s\n"
               "     --cat-config           Show configuration files\n"
               "     --tldr                 Show non-comment parts of configuration\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "\n%3$sOptions:%4$s\n"
               "     --root=PATH            Operate on an alternate filesystem root\n"
               "     --image=PATH           Operate on disk image as filesystem root\n"
               "     --image-policy=POLICY  Specify disk image dissection policy\n"
               "     --replace=PATH         Treat arguments as replacement for PATH\n"
               "     --dry-run              Just print what would be done\n"
               "     --inline               Treat arguments as configuration lines\n"
               "     --no-pager             Do not pipe output into a pager\n"
               "\nSee the %5$s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_underline(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_CAT_CONFIG,
                ARG_TLDR,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
                ARG_REPLACE,
                ARG_DRY_RUN,
                ARG_INLINE,
                ARG_NO_PAGER,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "cat-config",   no_argument,       NULL, ARG_CAT_CONFIG   },
                { "tldr",         no_argument,       NULL, ARG_TLDR         },
                { "root",         required_argument, NULL, ARG_ROOT         },
                { "image",        required_argument, NULL, ARG_IMAGE        },
                { "image-policy", required_argument, NULL, ARG_IMAGE_POLICY },
                { "replace",      required_argument, NULL, ARG_REPLACE      },
                { "dry-run",      no_argument,       NULL, ARG_DRY_RUN      },
                { "inline",       no_argument,       NULL, ARG_INLINE       },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER     },
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
                        arg_cat_flags = CAT_CONFIG_ON;
                        break;

                case ARG_TLDR:
                        arg_cat_flags = CAT_TLDR;
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

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                case ARG_REPLACE:
                        if (!path_is_absolute(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "The argument to --replace= must be an absolute path.");
                        if (!endswith(optarg, ".conf"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "The argument to --replace= must have the extension '.conf'.");

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

        if (arg_replace && arg_cat_flags != CAT_CONFIG_OFF)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --replace= is not supported with --cat-config/--tldr.");

        if (arg_replace && optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "When --replace= is given, some configuration items must be specified.");

        if (arg_image && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Use either --root= or --image=, the combination of both is not supported.");

        return 1;
}

static int parse_arguments(Context *c, char **args) {
        unsigned pos = 1;
        int r;

        assert(c);

        STRV_FOREACH(arg, args) {
                if (arg_inline)
                        /* Use (argument):n, where n==1 for the first positional arg */
                        r = parse_line("(argument)", pos, *arg, /* invalid_config= */ NULL, c);
                else
                        r = read_config_file(c, *arg, /* ignore_enoent= */ false);
                if (r < 0)
                        return r;

                pos++;
        }

        return 0;
}

static int read_config_files(Context *c, char **args) {
        _cleanup_strv_free_ char **files = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(c);

        r = conf_files_list_with_replacement(arg_root, CONF_PATHS_STRV("sysusers.d"), arg_replace, &files, &p);
        if (r < 0)
                return r;

        STRV_FOREACH(f, files)
                if (p && path_equal(*f, p)) {
                        log_debug("Parsing arguments at position \"%s\"%s", *f, special_glyph(SPECIAL_GLYPH_ELLIPSIS));

                        r = parse_arguments(c, args);
                        if (r < 0)
                                return r;
                } else {
                        log_debug("Reading config file \"%s\"%s", *f, special_glyph(SPECIAL_GLYPH_ELLIPSIS));

                        /* Just warn, ignore result otherwise */
                        (void) read_config_file(c, *f, /* ignore_enoent= */ true);
                }

        return 0;
}

static int read_credential_lines(Context *c) {
        _cleanup_free_ char *j = NULL;
        const char *d;
        int r;

        assert(c);

        r = get_credentials_dir(&d);
        if (r == -ENXIO)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to get credentials directory: %m");

        j = path_join(d, "sysusers.extra");
        if (!j)
                return log_oom();

        (void) read_config_file(c, j, /* ignore_enoent= */ true);
        return 0;
}

static int run(int argc, char *argv[]) {
#ifndef STANDALONE
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
#endif
        _cleanup_close_ int lock = -EBADF;
        _cleanup_(context_done) Context c = {
                .audit_fd = -EBADF,
                .search_uid = UID_INVALID,
        };

        Item *i;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        if (arg_cat_flags != CAT_CONFIG_OFF)
                return cat_config();

        umask(0022);

        r = mac_init();
        if (r < 0)
                return r;

#ifndef STANDALONE
        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_VALIDATE_OS |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_FSCK |
                                DISSECT_IMAGE_GROWFS |
                                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY,
                                &mounted_dir,
                                /* ret_dir_fd= */ NULL,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(mounted_dir);
                if (!arg_root)
                        return log_oom();
        }
#else
        assert(!arg_image);
#endif

        /* Prepare to emit audit events, but only if we're operating on the host system. */
        if (!arg_root)
                c.audit_fd = open_audit_fd_or_warn();

        /* If command line arguments are specified along with --replace, read all configuration files and
         * insert the positional arguments at the specified place. Otherwise, if command line arguments are
         * specified, execute just them, and finally, without --replace= or any positional arguments, just
         * read configuration and execute it. */
        if (arg_replace || optind >= argc)
                r = read_config_files(&c, argv + optind);
        else
                r = parse_arguments(&c, argv + optind);
        if (r < 0)
                return r;

        r = read_credential_lines(&c);
        if (r < 0)
                return r;

        /* Let's tell nss-systemd not to synthesize the "root" and "nobody" entries for it, so that our
         * detection whether the names or UID/GID area already used otherwise doesn't get confused. After
         * all, even though nss-systemd synthesizes these users/groups, they should still appear in
         * /etc/passwd and /etc/group, as the synthesizing logic is merely supposed to be fallback for cases
         * where we run with a completely unpopulated /etc. */
        if (setenv("SYSTEMD_NSS_BYPASS_SYNTHETIC", "1", 1) < 0)
                return log_error_errno(errno, "Failed to set SYSTEMD_NSS_BYPASS_SYNTHETIC environment variable: %m");

        if (!c.uid_range) {
                /* Default to default range of SYSTEMD_UID_MIN..SYSTEM_UID_MAX. */
                r = read_login_defs(&c.login_defs, NULL, arg_root);
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s%s: %m",
                                               strempty(arg_root), "/etc/login.defs");

                c.login_defs_need_warning = true;

                /* We pick a range that very conservative: we look at compiled-in maximum and the value in
                 * /etc/login.defs. That way the UIDs/GIDs which we allocate will be interpreted correctly,
                 * even if /etc/login.defs is removed later. (The bottom bound doesn't matter much, since
                 * it's only used during allocation, so we use the configured value directly). */
                uid_t begin = c.login_defs.system_alloc_uid_min,
                      end = MIN3((uid_t) SYSTEM_UID_MAX, c.login_defs.system_uid_max, c.login_defs.system_gid_max);
                if (begin < end) {
                        r = uid_range_add(&c.uid_range, begin, end - begin + 1);
                        if (r < 0)
                                return log_oom();
                }
        }

        r = add_implicit(&c);
        if (r < 0)
                return r;

        if (!arg_dry_run) {
                lock = take_etc_passwd_lock(arg_root);
                if (lock < 0)
                        return log_error_errno(lock, "Failed to take /etc/passwd lock: %m");
        }

        r = load_user_database(&c);
        if (r < 0)
                return log_error_errno(r, "Failed to load user database: %m");

        r = load_group_database(&c);
        if (r < 0)
                return log_error_errno(r, "Failed to read group database: %m");

        ORDERED_HASHMAP_FOREACH(i, c.groups)
                (void) process_item(&c, i);

        ORDERED_HASHMAP_FOREACH(i, c.users)
                (void) process_item(&c, i);

        return write_files(&c);
}

DEFINE_MAIN_FUNCTION(run);
