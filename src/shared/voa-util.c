/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "alloc-util.h"
#include "chase.h"
#include "conf-files.h"
#include "fd-util.h"
#include "log.h"
#include "os-util.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "set.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "voa-util.h"

#define VOA_IDENTIFIER_CHARSET LOWERCASE_LETTERS DIGITS "._-"

/* System mode load paths, in descending priority */
static const char* const voa_load_paths[] = {
        "/etc/voa",
        VOA_EPHEMERAL_LOAD_PATH,
        "/usr/local/share/voa",
        "/usr/share/voa",
        NULL,
};

typedef struct VoaContext {
        int root_fd;
        int log_level;          /* for entries the specification says to ignore */
        ConfFilesFlags conf_flags;
        char **hierarchy;       /* the load paths that exist, physically resolved */
} VoaContext;

bool voa_identifier_is_valid(const char *s, bool allow_colon) {
        if (!filename_is_valid(s))
                return false;

        return in_charset(s, allow_colon ? VOA_IDENTIFIER_CHARSET ":" : VOA_IDENTIFIER_CHARSET);
}

bool voa_os_is_valid(const char *s) {
        size_t n = 1;

        /* ID[:VERSION_ID[:VARIANT_ID[:IMAGE_ID[:IMAGE_VERSION]]]], with unset trailing parts omitted */

        if (!voa_identifier_is_valid(s, /* allow_colon= */ true))
                return false;

        if (s[0] == ':' || endswith(s, ":"))
                return false;

        for (const char *p = s; *p; p++)
                if (*p == ':')
                        n++;

        return n <= 5;
}

int voa_os_identifiers(int root_fd, char ***ret) {
        _cleanup_free_ char *id = NULL, *version_id = NULL, *variant_id = NULL, *image_id = NULL,
                *image_version = NULL, *exact = NULL;
        _cleanup_strv_free_ char **l = NULL;
        bool usable = true;
        int r;

        assert(root_fd >= 0 || root_fd == AT_FDCWD);
        assert(ret);

        /* Returns the identifiers to look up for the OS in the root: the exact one composed of all set
         * os-release fields, followed by the bare ID. Returns > 0 if the exact one is unusable because a
         * field contains characters the specification does not permit. */

        r = parse_os_release_at(root_fd,
                                "ID", &id,
                                "VERSION_ID", &version_id,
                                "VARIANT_ID", &variant_id,
                                "IMAGE_ID", &image_id,
                                "IMAGE_VERSION", &image_version);
        /* Seeing ENOENT is fine. If we have no os-release at all we default to the "linux" default. */
        if (r < 0 && r != -ENOENT)
                return r;

        if (!id) {
                r = strdup_to(&id, "linux"); /* the documented default */
                if (r < 0)
                        return r;
        }
        if (!voa_identifier_is_valid(id, /* allow_colon= */ false))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "os-release ID '%s' is not a valid VOA identifier.", id);

        exact = strdup(id);
        if (!exact)
                return -ENOMEM;

        /* Unset trailing parts are cut off again */
        size_t end = strlen(exact);
        FOREACH_STRING(p, strempty(version_id), strempty(variant_id), strempty(image_id),
                       strempty(image_version)) {
                if (!strextend(&exact, ":", p))
                        return -ENOMEM;
                if (isempty(p))
                        continue;

                if (!voa_identifier_is_valid(p, /* allow_colon= */ false)) {
                        log_debug("os-release field '%s' is not a valid VOA identifier part, "
                                  "exact OS identifier unusable.", p);
                        usable = false;
                }

                end = strlen(exact);
        }
        exact[end] = 0;

        if (usable && end > strlen(id)) {
                r = strv_consume(&l, TAKE_PTR(exact));
                if (r < 0)
                        return r;
        }

        r = strv_consume(&l, TAKE_PTR(id));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(l);
        return !usable;
}

/* chase() already vetted ownership along both walks. Nothing may be writable by anybody else on top of
 * that. */
static bool voa_stat_trusted(const struct stat *st) {
        assert(st);

        return (st->st_mode & 0022) == 0;
}

/* Collects the masked and the candidate files of one verifier directory */
static int voa_collect(
                const VoaContext *c,
                const char *dir,
                const char *suffix,
                Set **masked,
                ConfFile ***files,
                size_t *n_files) {

        _cleanup_free_ DirectoryEntries *de = NULL;
        _cleanup_free_ char *physical = NULL;
        _cleanup_close_ int dfd = -EBADF;
        int r;

        assert(c);
        assert(dir);
        assert(suffix);
        assert(masked);
        assert(files);
        assert(n_files);

        /* Only a readdir handle, not a pin: every entry is re-resolved below and confined via its own
         * resolved path */
        dfd = chase_and_openat(c->root_fd, c->root_fd, dir, CHASE_MUST_BE_DIRECTORY|CHASE_SAFE,
                               O_DIRECTORY|O_CLOEXEC, &physical);
        if (dfd == -ENOENT)
                return 0;
        /* One bad load path, an unsafe transition included, must not hide the others */
        if (IN_SET(dfd, -ENOTDIR, -ELOOP, -ENOLINK, -EACCES, -EPERM)) {
                log_full_errno(c->log_level, dfd, "Ignoring '%s': %m", dir);
                return 0;
        }
        if (dfd < 0)
                return dfd;

        if (!path_startswith_strv(physical, c->hierarchy)) {
                log_full(c->log_level, "Ignoring '%s': resolves outside of the VOA hierarchy.", dir);
                return 0;
        }

        struct stat dir_st;
        if (fstat(dfd, &dir_st) < 0)
                return -errno;

        /* Let's discard any directory that is owned by someone else. */
        if (!voa_stat_trusted(&dir_st)) {
                log_full(c->log_level, "Ignoring '%s': writable by group or others.", dir);
                return 0;
        }

        r = readdir_all(dfd, RECURSE_DIR_SORT, &de);
        if (r < 0)
                return r;

        FOREACH_ARRAY(i, de->entries, de->n_entries) {
                _cleanup_(conf_file_freep) ConfFile *f = NULL;
                _cleanup_free_ char *path = NULL, *fn = NULL;
                const char *name = (*i)->d_name, *e;

                e = endswith(name, suffix);
                if (!e)
                        continue;

                path = path_join(dir, name);
                if (!path)
                        return -ENOMEM;

                /* The same rule credential names follow */
                _cleanup_free_ char *prefix = strndup(name, e - name);
                if (!prefix)
                        return -ENOMEM;
                if (!voa_identifier_is_valid(prefix, /* allow_colon= */ false)) {
                        log_full(c->log_level, "Ignoring '%s': file name is not a valid VOA identifier.",
                                 path);
                        continue;
                }

                r = conf_file_new_at(path, /* root= */ NULL, c->root_fd, c->conf_flags, &f);
                if (r == -ERFKILL) {
                        /* chase() vetted the mask, an unsafe transition comes back as -ENOLINK instead */
                        r = set_put_strdup(masked, name);
                        if (r < 0)
                                return r;

                        log_debug("'%s' masks '%s'.", path, name);
                        continue;
                }
                if (r == -ENOMEM)
                        return r;
                if (r < 0) /* logged already, at warning level if requested */
                        continue;

                /* The VOA spec mandates that verifiers may not point outside of the hierarchy.
                 * So ignore them. */
                if (!path_startswith_strv(f->resolved_path, c->hierarchy)) {
                        log_full(c->log_level, "Ignoring '%s': points outside of the VOA hierarchy.", path);
                        continue;
                }

                r = path_extract_filename(f->resolved_path, &fn);
                if (r < 0)
                        return r;
                if (!streq(fn, name)) {
                        log_full(c->log_level, "Ignoring '%s': target '/%s' has a different name.",
                                 path, skip_leading_slash(f->resolved_path));
                        continue;
                }

                /* The prefix was resolved twice, once to enumerate and once to open. A regular entry of
                 * the enumerated directory must be the very file that was opened. */
                struct stat est;
                if (fstatat(dfd, name, &est, AT_SYMLINK_NOFOLLOW) < 0) {
                        log_full_errno(c->log_level, errno, "Ignoring '%s': %m", path);
                        continue;
                }
                if (S_ISREG(est.st_mode) && !stat_inode_same(&est, &f->st)) {
                        log_full(c->log_level, "Ignoring '%s': changed while collecting.", path);
                        continue;
                }

                /* Ignore anything that doesn't have clean and limited permissions. */
                if (!voa_stat_trusted(&f->st)) {
                        log_full(c->log_level, "Ignoring '%s': writable by group or others.", path);
                        continue;
                }

                if (!GREEDY_REALLOC(*files, *n_files + 1))
                        return -ENOMEM;

                (*files)[(*n_files)++] = TAKE_PTR(f);
        }

        return 0;
}

static int voa_list_one(
                const VoaContext *c,
                const char *os,
                const char *purpose,
                const char *context,
                const char *technology,
                const char *suffix,
                ConfFile ***files,
                size_t *n_files) {

        _cleanup_set_free_ Set *masked = NULL;
        ConfFile **candidates = NULL;
        size_t n_candidates = 0;
        int r;

        assert(c);
        assert(files);
        assert(n_files);

        CLEANUP_ARRAY(candidates, n_candidates, conf_file_free_array);

        /* A mask applies to all load paths, hence collect everything first */

        STRV_FOREACH(lp, voa_load_paths) {
                _cleanup_free_ char *dir = path_join(*lp, os, purpose, context, technology);
                if (!dir)
                        return -ENOMEM;

                r = voa_collect(c, dir, suffix, &masked, &candidates, &n_candidates);
                if (r < 0)
                        return r;
        }

        FOREACH_ARRAY(f, candidates, n_candidates) {
                if (set_contains(masked, (*f)->filename)) {
                        log_debug("'%s' is masked, ignoring.", (*f)->original_path);
                        continue;
                }

                if (!GREEDY_REALLOC(*files, *n_files + 1))
                        return -ENOMEM;

                (*files)[(*n_files)++] = TAKE_PTR(*f);
        }

        return 0;
}

/* Return all matching verifier files in all load paths. Pin the verifiers through an O_PATH fd.
 * Adhere to merging semantics, meaning every copy of a verifier counts and a verifier masked in any load
 * path is treated as masked in all of them. The files are returned per OS identifier in the given order.
 * They are then ordered by descending priority of the load path.
 *
 * Note that ConfFile.original_path is the path the file was found as and ConfFile.resolved_path where it
 * physically is. Both are relative to the root. */
int voa_list_verifiers(
                int root_fd,
                const VoaLookup *lookup,
                VoaFlags flags,
                ConfFile ***ret_files,
                size_t *ret_n_files) {

        _cleanup_strv_free_ char **hierarchy = NULL;
        _cleanup_free_ char *purpose = NULL;
        ConfFile **files = NULL;
        size_t n_files = 0;
        int r;

        assert(root_fd >= 0 || root_fd == AT_FDCWD);
        assert(lookup);
        assert(ret_files);
        assert(!*ret_files);
        assert(ret_n_files);

        CLEANUP_ARRAY(files, n_files, conf_file_free_array);

        if (strv_isempty(lookup->os))
                return -EINVAL;
        STRV_FOREACH(os, lookup->os)
                if (!voa_os_is_valid(*os))
                        return -EINVAL;
        if (!voa_identifier_is_valid(lookup->context, /* allow_colon= */ false))
                return -EINVAL;
        if (!voa_identifier_is_valid(lookup->role, /* allow_colon= */ false) ||
            startswith(lookup->role, "trust-anchor-"))
                return -EINVAL;
        if (lookup->mode < 0 || lookup->mode >= _VOA_MODE_MAX)
                return -EINVAL;
        if (!voa_identifier_is_valid(lookup->technology, /* allow_colon= */ false))
                return -EINVAL;
        if (isempty(lookup->suffix))
                return -EINVAL;

        int log_level = FLAGS_SET(flags, VOA_WARN) ? LOG_WARNING : LOG_DEBUG;

        /* The hierarchy check further below compares resolved paths. So we need to resolve the load paths
         * too as on some systems such as rpm-ostree /usr/local is a symlink into /var */
        STRV_FOREACH(lp, voa_load_paths) {
                _cleanup_free_ char *physical = NULL;

                r = chaseat(root_fd, root_fd, *lp, CHASE_MUST_BE_DIRECTORY, &physical, /* ret_fd= */ NULL);
                if (r == -ENOENT)
                        continue;
                /* Like in voa_collect(), one bad load path must not hide the others */
                if (IN_SET(r, -ENOTDIR, -ELOOP, -EACCES, -EPERM)) {
                        log_full_errno(log_level, r, "Ignoring load path '%s': %m", *lp);
                        continue;
                }
                if (r < 0)
                        return r;

                r = strv_consume(&hierarchy, TAKE_PTR(physical));
                if (r < 0)
                        return r;
        }

        VoaContext c = {
                .root_fd = root_fd,
                .log_level = log_level,
                .conf_flags = CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED_BY_SYMLINK|CONF_FILES_CHASE_SAFE|
                              (FLAGS_SET(flags, VOA_WARN) ? CONF_FILES_WARN : 0),
                .hierarchy = hierarchy,
        };

        if (lookup->mode == VOA_MODE_TRUST_ANCHOR)
                purpose = strjoin("trust-anchor-", lookup->role);
        else
                purpose = strdup(lookup->role);
        if (!purpose)
                return -ENOMEM;

        STRV_FOREACH(os, lookup->os) {
                r = voa_list_one(&c, *os, purpose, lookup->context, lookup->technology, lookup->suffix,
                                 &files, &n_files);
                if (r < 0)
                        return r;
        }

        *ret_files = TAKE_PTR(files);
        *ret_n_files = n_files;
        return 0;
}
