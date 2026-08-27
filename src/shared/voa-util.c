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
#include "string-util.h"
#include "strv.h"
#include "voa-util.h"

#define VOA_IDENTIFIER_CHARSET LOWERCASE_LETTERS DIGITS "._-"

const char* const voa_load_paths[] = {
        "/etc/voa",
        "/run/voa",
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
        if (isempty(s))
                return false;

        if (dot_or_dot_dot(s))
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
        size_t n = 0;
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
        if (r < 0)
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

        const char *parts[] = { version_id, variant_id, image_id, image_version };
        FOREACH_ELEMENT(p, parts)
                if (!isempty(*p)) {
                        n = p - parts + 1;
                        if (!voa_identifier_is_valid(*p, /* allow_colon= */ false)) {
                                log_debug("os-release field '%s' is not a valid VOA identifier part, "
                                          "exact OS identifier unusable.", *p);
                                usable = false;
                        }
                }

        if (usable && n > 0) {
                for (size_t i = 0; i < n; i++)
                        if (!strextend(&exact, ":", strempty(parts[i])))
                                return -ENOMEM;

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

/* Collects the masks and the candidate files of one technology directory */
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

        /* Directories are resolved like the kernel does, but must stay inside the hierarchy */
        dfd = chase_and_openat(c->root_fd, c->root_fd, dir, CHASE_MUST_BE_DIRECTORY,
                               O_DIRECTORY|O_CLOEXEC, &physical);
        if (dfd == -ENOENT)
                return 0;
        if (IN_SET(dfd, -ENOTDIR, -ELOOP)) {
                log_full_errno(c->log_level, dfd, "Ignoring '%s': %m", dir);
                return 0;
        }
        if (dfd < 0)
                return dfd;

        if (!path_startswith_strv(physical, c->hierarchy)) {
                log_full(c->log_level, "Ignoring '%s': resolves outside of the VOA hierarchy.", dir);
                return 0;
        }

        r = readdir_all(dfd, RECURSE_DIR_SORT, &de);
        if (r < 0)
                return r;

        FOREACH_ARRAY(i, de->entries, de->n_entries) {
                _cleanup_(conf_file_freep) ConfFile *f = NULL;
                _cleanup_free_ char *path = NULL, *fn = NULL;
                const char *name = (*i)->d_name;

                if (!endswith(name, suffix))
                        continue;

                path = path_join(dir, name);
                if (!path)
                        return -ENOMEM;

                /* Symlinks are resolved like the kernel does, the target must be a regular file inside the
                 * hierarchy carrying the symlink's name. The specification's other rules cannot change the
                 * result of a merging lookup. */
                r = conf_file_new_at(path, /* root= */ NULL, c->root_fd, c->conf_flags, &f);
                if (r == -ERFKILL) {
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
                const char *technology,
                const char *suffix,
                ConfFile ***files,
                size_t *n_files) {

        _cleanup_set_free_ Set *masked = NULL;
        ConfFile **candidates = NULL;
        size_t n_candidates = 0;
        int r;

        CLEANUP_ARRAY(candidates, n_candidates, conf_file_free_array);

        assert(c);
        assert(files);
        assert(n_files);

        /* A mask applies to all load paths, hence collect everything first */

        STRV_FOREACH(lp, voa_load_paths) {
                _cleanup_free_ char *dir = path_join(*lp, os, purpose, "default" /* context */, technology);
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

        CLEANUP_ARRAY(files, n_files, conf_file_free_array);

        assert(root_fd >= 0 || root_fd == AT_FDCWD);
        assert(lookup);
        assert(ret_files);
        assert(ret_n_files);

        /* Returns all matching verifier files in all load paths, pinned by O_PATH fd, in merging semantics:
         * every copy of a verifier counts, and a verifier masked in any load path is masked in all of them.
         * ConfFile.original_path is the path a file was found as, ConfFile.resolved_path where it physically
         * is, both relative to the root. */

        if (strv_isempty(lookup->os))
                return -EINVAL;
        STRV_FOREACH(os, lookup->os)
                if (!voa_os_is_valid(*os))
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

        VoaContext c = {
                .root_fd = root_fd,
                .log_level = FLAGS_SET(flags, VOA_WARN) ? LOG_WARNING : LOG_DEBUG,
                .conf_flags = CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED_BY_SYMLINK|
                              (FLAGS_SET(flags, VOA_WARN) ? CONF_FILES_WARN : 0),
        };

        /* Symlinks must stay inside the hierarchy, which is judged by where the load paths physically are */
        STRV_FOREACH(lp, voa_load_paths) {
                _cleanup_free_ char *physical = NULL;

                r = chaseat(root_fd, root_fd, *lp, CHASE_MUST_BE_DIRECTORY, &physical, /* ret_fd= */ NULL);
                if (IN_SET(r, -ENOENT, -ENOTDIR, -ELOOP))
                        continue;
                if (r < 0)
                        return r;

                r = strv_consume(&hierarchy, TAKE_PTR(physical));
                if (r < 0)
                        return r;
        }
        c.hierarchy = hierarchy;

        if (lookup->mode == VOA_MODE_TRUST_ANCHOR)
                purpose = strjoin("trust-anchor-", lookup->role);
        else
                purpose = strdup(lookup->role);
        if (!purpose)
                return -ENOMEM;

        STRV_FOREACH(os, lookup->os) {
                r = voa_list_one(&c, *os, purpose, lookup->technology, lookup->suffix, &files, &n_files);
                if (r < 0)
                        return r;
        }

        *ret_files = TAKE_PTR(files);
        *ret_n_files = n_files;
        return 0;
}
