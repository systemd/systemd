/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "architecture.h"
#include "chase.h"
#include "fd-util.h"
#include "fs-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "vpick.h"

void pick_result_done(PickResult *p) {
        assert(p);

        free(p->path);
        safe_close(p->fd);
        free(p->version);

        *p = PICK_RESULT_NULL;
}

static int format_fname(
                const PickFilter *filter,
                PickFlags flags,
                char **ret) {

        _cleanup_free_ char *fn = NULL;
        int r;

        assert(filter);
        assert(ret);

        if (FLAGS_SET(flags, PICK_TRIES) || !filter->version) /* Underspecified? */
                return -ENOEXEC;

        /* The format for names we match goes like this:
         *
         *        <basename><suffix>
         *  or:
         *        <basename>_<version><suffix>
         *  or:
         *        <basename>_<version>_<architecture><suffix>
         *  or:
         *        <basename>_<architecture><suffix>
         *
         * (Note that basename can be empty, in which case the leading "_" is suppressed)
         *
         * Examples: foo.raw, foo_1.3-7.raw, foo_1.3-7_x86-64.raw, foo_x86-64.raw
         *
         * Why use "_" as separator here? Primarily because it is not used by Semver 2.0. In RPM it is used
         * for "unsortable" versions, i.e. doesn't show up in "sortable" versions, which we matter for this
         * usecase here. In Debian the underscore is not allowed (and it uses it itself for separating
         * fields).
         *
         * This is very close to Debian's way to name packages, but allows arbitrary suffixes, and makes the
         * architecture field redundant.
         *
         * Compare with RPM's "NEVRA" concept. Here we have "BVAS" (basename, version, architecture, suffix).
         */

        if (filter->basename) {
                fn = strdup(filter->basename);
                if (!fn)
                        return -ENOMEM;
        }

        if (filter->version) {
                if (isempty(fn)) {
                        r = free_and_strdup(&fn, filter->version);
                        if (r < 0)
                                return r;
                } else if (!strextend(&fn, "_", filter->version))
                        return -ENOMEM;
        }

        if (FLAGS_SET(flags, PICK_ARCHITECTURE) && filter->architecture >= 0) {
                const char *as = ASSERT_PTR(architecture_to_string(filter->architecture));
                if (isempty(fn)) {
                        r = free_and_strdup(&fn, as);
                        if (r < 0)
                                return r;
                } else if (!strextend(&fn, "_", as))
                        return -ENOMEM;
        }

        if (filter->suffix && !strextend(&fn, filter->suffix))
                return -ENOMEM;

        if (!filename_is_valid(fn))
                return -EINVAL;

        *ret = TAKE_PTR(fn);
        return 0;
}

static int errno_from_mode(uint32_t type_mask, mode_t found) {
        /* Returns the most appropriate error code if we are lookging for an inode of type of those in the
         * 'type_mask' but found 'found' instead.
         *
         * type_mask is a mask of 1U << DT_REG, 1U << DT_DIR, … flags, while found is a S_IFREG, S_IFDIR, …
         * mode value. */

        if (type_mask == 0) /* type doesn't matter */
                return 0;

        if (FLAGS_SET(type_mask, UINT32_C(1) << IFTODT(found)))
                return 0;

        if (type_mask == (UINT32_C(1) << DT_BLK))
                return -ENOTBLK;
        if (type_mask == (UINT32_C(1) << DT_DIR))
                return -ENOTDIR;
        if (type_mask == (UINT32_C(1) << DT_SOCK))
                return -ENOTSOCK;

        if (S_ISLNK(found))
                return -ELOOP;
        if (S_ISDIR(found))
                return -EISDIR;

        return -EBADF;
}

static int pin_choice(
                const char *toplevel_path,
                int toplevel_fd,
                const char *inode_path,
                int _inode_fd, /* we always take ownership of the fd, even on failure */
                unsigned tries_left,
                unsigned tries_done,
                const PickFilter *filter,
                PickFlags flags,
                PickResult *ret) {

        _cleanup_close_ int inode_fd = TAKE_FD(_inode_fd);
        _cleanup_free_ char *resolved_path = NULL;
        int r;

        assert(toplevel_fd >= 0 || toplevel_fd == AT_FDCWD);
        assert(inode_path);
        assert(filter);

        toplevel_path = strempty(toplevel_path);

        if (inode_fd < 0 || FLAGS_SET(flags, PICK_RESOLVE)) {
                r = chaseat(toplevel_fd,
                            inode_path,
                            CHASE_AT_RESOLVE_IN_ROOT,
                            FLAGS_SET(flags, PICK_RESOLVE) ? &resolved_path : 0,
                            inode_fd < 0 ? &inode_fd : NULL);
                if (r < 0)
                        return r;

                if (resolved_path)
                        inode_path = resolved_path;
        }

        struct stat st;
        if (fstat(inode_fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat discovered inode '%s/%s': %m", toplevel_path, inode_path);

        if (filter->type_mask != 0 &&
            !FLAGS_SET(filter->type_mask, UINT32_C(1) << IFTODT(st.st_mode)))
                return log_debug_errno(
                                SYNTHETIC_ERRNO(errno_from_mode(filter->type_mask, st.st_mode)),
                                "Inode '%s/%s' has wrong type, found '%s'.",
                                toplevel_path, inode_path,
                                inode_type_to_string(st.st_mode));

        _cleanup_(pick_result_done) PickResult result = {
                .fd = TAKE_FD(inode_fd),
                .st = st,
                .architecture = filter->architecture,
                .tries_left = tries_left,
                .tries_done = tries_done,
        };

        result.path = strdup(inode_path);
        if (!result.path)
                return log_oom_debug();

        if (filter->version) {
                result.version = strdup(filter->version);
                if (!result.version)
                        return log_oom_debug();
        }

        *ret = TAKE_PICK_RESULT(result);
        return 1;
}

static int parse_tries(const char *s, unsigned *ret_tries_left, unsigned *ret_tries_done) {
        unsigned left, done;
        size_t n;

        assert(s);
        assert(ret_tries_left);
        assert(ret_tries_done);

        if (s[0] != '+')
                goto nomatch;

        s++;

        n = strspn(s, DIGITS);
        if (n == 0)
                goto nomatch;

        if (s[n] == 0) {
                if (safe_atou(s, &left) < 0)
                        goto nomatch;

                done = 0;
        } else if (s[n] == '-') {
                _cleanup_free_ char *c = NULL;

                c = strndup(s, n);
                if (!c)
                        return -ENOMEM;

                if (safe_atou(c, &left) < 0)
                        goto nomatch;

                s += n + 1;

                if (!in_charset(s, DIGITS))
                        goto nomatch;

                if (safe_atou(s, &done) < 0)
                        goto nomatch;
        } else
                goto nomatch;

        *ret_tries_left = left;
        *ret_tries_done = done;
        return 1;

nomatch:
        *ret_tries_left = *ret_tries_done = UINT_MAX;
        return 0;
}

static int make_choice(
                const char *toplevel_path,
                int toplevel_fd,
                const char *inode_path,
                int _inode_fd, /* we always take ownership of the fd, even on failure */
                const PickFilter *filter,
                PickFlags flags,
                PickResult *ret) {

        static const Architecture local_architectures[] = {
                /* In order of preference */
                native_architecture(),
#ifdef ARCHITECTURE_SECONDARY
                ARCHITECTURE_SECONDARY,
#endif
                _ARCHITECTURE_INVALID, /* accept any arch, as last resort */
        };

        _cleanup_free_ DirectoryEntries *de = NULL;
        _cleanup_free_ char *best_version = NULL, *best_filename = NULL, *p = NULL, *j = NULL;
        _cleanup_close_ int dir_fd = -EBADF, object_fd = -EBADF, inode_fd = TAKE_FD(_inode_fd);
        const Architecture *architectures;
        unsigned best_tries_left = UINT_MAX, best_tries_done = UINT_MAX;
        size_t n_architectures, best_architecture_index = SIZE_MAX;
        int r;

        assert(toplevel_fd >= 0 || toplevel_fd == AT_FDCWD);
        assert(inode_path);
        assert(filter);

        toplevel_path = strempty(toplevel_path);

        if (inode_fd < 0) {
                r = chaseat(toplevel_fd, inode_path, CHASE_AT_RESOLVE_IN_ROOT, NULL, &inode_fd);
                if (r < 0)
                        return r;
        }

        /* Maybe the filter is fully specified? Then we can generate the file name directly */
        r = format_fname(filter, flags, &j);
        if (r >= 0) {
                _cleanup_free_ char *object_path = NULL;

                /* Yay! This worked! */
                p = path_join(inode_path, j);
                if (!p)
                        return log_oom_debug();

                r = chaseat(toplevel_fd, p, CHASE_AT_RESOLVE_IN_ROOT, &object_path, &object_fd);
                if (r < 0) {
                        if (r != -ENOENT)
                                return log_debug_errno(r, "Failed to open '%s/%s': %m", toplevel_path, p);

                        *ret = PICK_RESULT_NULL;
                        return 0;
                }

                return pin_choice(
                                toplevel_path,
                                toplevel_fd,
                                FLAGS_SET(flags, PICK_RESOLVE) ? object_path : p,
                                TAKE_FD(object_fd), /* unconditionally pass ownership of the fd */
                                /* tries_left= */ UINT_MAX,
                                /* tries_done= */ UINT_MAX,
                                filter,
                                flags & ~PICK_RESOLVE,
                                ret);

        } else if (r != -ENOEXEC)
                return log_debug_errno(r, "Failed to format file name: %m");

        /* Underspecified, so we do our enumeration dance */

        /* Convert O_PATH to a regular directory fd */
        dir_fd = fd_reopen(inode_fd, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
        if (dir_fd < 0)
                return log_debug_errno(dir_fd, "Failed to reopen '%s/%s' as directory: %m", toplevel_path, inode_path);

        r = readdir_all(dir_fd, 0, &de);
        if (r < 0)
                return log_debug_errno(r, "Failed to read directory '%s/%s': %m", toplevel_path, inode_path);

        if (filter->architecture < 0) {
                architectures = local_architectures;
                n_architectures = ELEMENTSOF(local_architectures);
        } else {
                architectures = &filter->architecture;
                n_architectures = 1;
        }

        FOREACH_ARRAY(entry, de->entries, de->n_entries) {
                unsigned found_tries_done = UINT_MAX, found_tries_left = UINT_MAX;
                _cleanup_free_ char *chopped = NULL;
                size_t found_architecture_index = SIZE_MAX;
                const char *e;

                if (!isempty(filter->basename)) {
                        e = startswith((*entry)->d_name, filter->basename);
                        if (!e)
                                continue;

                        if (e[0] != '_')
                                continue;

                        e++;
                } else
                        e = (*entry)->d_name;

                if (!isempty(filter->suffix)) {
                        const char *sfx;

                        sfx = endswith(e, filter->suffix);
                        if (!sfx)
                                continue;

                        chopped = strndup(e, sfx - e);
                        if (!chopped)
                                return log_oom_debug();

                        e = chopped;
                }

                if (FLAGS_SET(flags, PICK_TRIES)) {
                        char *plus = strrchr(e, '+');
                        if (plus) {
                                r = parse_tries(plus, &found_tries_left, &found_tries_done);
                                if (r < 0)
                                        return r;
                                if (r > 0) /* Found and parsed, now chop off */
                                        *plus = 0;
                        }
                }

                if (FLAGS_SET(flags, PICK_ARCHITECTURE)) {
                        char *underscore = strrchr(e, '_');
                        Architecture a;

                        a = underscore ? architecture_from_string(underscore + 1) : _ARCHITECTURE_INVALID;

                        for (size_t i = 0; i < n_architectures; i++)
                                if (architectures[i] == a) {
                                        found_architecture_index = i;
                                        break;
                                }

                        if (found_architecture_index == SIZE_MAX) { /* No matching arch found */
                                log_debug("Found entry with architecture '%s' which is not what we are looking for, ignoring entry.", a < 0 ? "any" : architecture_to_string(a));
                                continue;
                        }

                        /* Chop off architecture from string */
                        if (underscore)
                                *underscore = 0;
                }

                if (!version_is_valid(e)) {
                        log_debug("Version string '%s' of entry '%s' is invalid, ignoring entry.", e, (*entry)->d_name);
                        continue;
                }

                if (filter->version && !streq(filter->version, e)) {
                        log_debug("Found entry with version string '%s', but was looking for '%s', ignoring entry.", e, filter->version);
                        continue;
                }

                if (best_filename) { /* Already found one matching entry? Then figure out the better one */
                        int d = 0;

                        /* First, prefer entries with tries left over those without */
                        if (FLAGS_SET(flags, PICK_TRIES))
                                d = CMP(found_tries_left != 0, best_tries_left != 0);

                        /* Second, prefer newer versions */
                        if (d == 0)
                                d = strverscmp_improved(e, best_version);

                        /* Third, prefer native architectures over secondary architectures */
                        if (d == 0 &&
                            FLAGS_SET(flags, PICK_ARCHITECTURE) &&
                            found_architecture_index != SIZE_MAX && best_architecture_index != SIZE_MAX)
                                d = -CMP(found_architecture_index, best_architecture_index);

                        /* Fourth, prefer entries with more tries left */
                        if (FLAGS_SET(flags, PICK_TRIES)) {
                                if (d == 0)
                                        d = CMP(found_tries_left, best_tries_left);

                                /* Fifth, prefer entries with fewer attempts done so far */
                                if (d == 0)
                                        d = -CMP(found_tries_done, best_tries_done);
                        }

                        /* Last, just compare the filenames as strings */
                        if (d == 0)
                                d = strcmp((*entry)->d_name, best_filename);

                        if (d < 0) {
                                log_debug("Found entry '%s' but previously found entry '%s' matches better, hence skipping entry.", (*entry)->d_name, best_filename);
                                continue;
                        }
                }

                r = free_and_strdup_warn(&best_version, e);
                if (r < 0)
                        return r;

                r = free_and_strdup_warn(&best_filename, (*entry)->d_name);
                if (r < 0)
                        return r;

                best_architecture_index = found_architecture_index;
                best_tries_left = found_tries_left;
                best_tries_done = found_tries_done;
        }

        if (!best_filename) { /* Everything was good, but we didn't find any suitable entry */
                *ret = PICK_RESULT_NULL;
                return 0;
        }

        p = path_join(inode_path, best_filename);
        if (!p)
                return log_oom_debug();

        object_fd = openat(dir_fd, best_filename, O_CLOEXEC|O_PATH);
        if (object_fd < 0)
                return log_debug_errno(errno, "Failed to open '%s/%s': %m", toplevel_path, p);

        return pin_choice(
                        toplevel_path,
                        toplevel_fd,
                        p,
                        TAKE_FD(object_fd),
                        best_tries_left,
                        best_tries_done,
                        &(const PickFilter) {
                                .type_mask = filter->type_mask,
                                .basename = filter->basename,
                                .version = empty_to_null(best_version),
                                .architecture = best_architecture_index != SIZE_MAX ? architectures[best_architecture_index] : _ARCHITECTURE_INVALID,
                                .suffix = filter->suffix,
                        },
                        flags,
                        ret);
}

int path_pick(const char *toplevel_path,
              int toplevel_fd,
              const char *path,
              const PickFilter *filter,
              PickFlags flags,
              PickResult *ret) {

        _cleanup_free_ char *filter_bname = NULL, *dir = NULL, *parent = NULL, *fname = NULL;
        const char *filter_suffix, *enumeration_path;
        uint32_t filter_type_mask;
        int r;

        assert(toplevel_fd >= 0 || toplevel_fd == AT_FDCWD);
        assert(path);

        toplevel_path = strempty(toplevel_path);

        /* Given a path, resolve .v/ subdir logic (if used!), and returns the choice made. This supports
         * three ways to be called:
         *
         * • with a path referring a directory of any name, and filter→basename *explicitly* specified, in
         *   which case we'll use a pattern "<filter→basename>_*<filter→suffix>" on the directory's files.
         *
         * • with no filter→basename explicitly specified and a path referring to a directory named in format
         *   "<somestring><filter→suffix>.v" . In this case the filter basename to search for inside the dir
         *   is derived from the directory name. Example: "/foo/bar/baz.suffix.v" → we'll search for
         *   "/foo/bar/baz.suffix.v/baz_*.suffix".
         *
         * • with a path whose penultimate component ends in ".v/". In this case the final component of the
         *   path refers to the pattern. Example: "/foo/bar/baz.v/waldo__.suffix" → we'll search for
         *   "/foo/bar/baz.v/waldo_*.suffix".
         */

        /* Explicit basename specified, then shortcut things and do .v mode regardless of the path name. */
        if (filter->basename)
                return make_choice(
                                toplevel_path,
                                toplevel_fd,
                                path,
                                /* inode_fd= */ -EBADF,
                                filter,
                                flags,
                                ret);

        r = path_extract_filename(path, &fname);
        if (r < 0) {
                if (r != -EADDRNOTAVAIL) /* root dir or "." */
                        return r;

                /* If there's no path element we can derive a pattern off, the don't */
                goto bypass;
        }

        /* Remember if the path ends in a dash suffix */
        bool slash_suffix = r == O_DIRECTORY;

        const char *e = endswith(fname, ".v");
        if (e) {
                /* So a path in the form /foo/bar/baz.v is specified. In this case our search basename is
                 * "baz", possibly with a suffix chopped off if there's one specified. */
                filter_bname = strndup(fname, e - fname);
                if (!filter_bname)
                        return -ENOMEM;

                if (filter->suffix) {
                        /* Chop off suffix, if specified */
                        char *f = endswith(filter_bname, filter->suffix);
                        if (f)
                                *f = 0;
                }

                filter_suffix = filter->suffix;
                filter_type_mask = filter->type_mask;

                enumeration_path = path;
        } else {
                /* The path does not end in '.v', hence see if the last element is a pattern. */

                char *wildcard = strrstr(fname, "___");
                if (!wildcard)
                        goto bypass; /* Not a pattern, then bypass */

                /* We found the '___' wildcard, hence everything after it is our filter suffix, and
                 * everything before is our filter basename */
                *wildcard = 0;
                filter_suffix = empty_to_null(wildcard + 3);

                filter_bname = TAKE_PTR(fname);

                r = path_extract_directory(path, &dir);
                if (r < 0) {
                        if (!IN_SET(r, -EDESTADDRREQ, -EADDRNOTAVAIL)) /* only filename specified (no dir), or root or "." */
                                return r;

                        goto bypass; /* No dir extractable, can't check if parent ends in ".v" */
                }

                r = path_extract_filename(dir, &parent);
                if (r < 0) {
                        if (r != -EADDRNOTAVAIL) /* root dir or "." */
                                return r;

                        goto bypass; /* Cannot extract fname from parent dir, can't check if it ends in ".v" */
                }

                e = endswith(parent, ".v");
                if (!e)
                        goto bypass; /* Doesn't end in ".v", shortcut */

                filter_type_mask = filter->type_mask;
                if (slash_suffix) {
                        /* If the pattern is suffixed by a / then we are looking for directories apparently. */
                        if (filter_type_mask != 0 && !FLAGS_SET(filter_type_mask, UINT32_C(1) << DT_DIR))
                                return log_debug_errno(SYNTHETIC_ERRNO(errno_from_mode(filter_type_mask, S_IFDIR)),
                                                       "Specified pattern ends in '/', but not looking for directories, refusing.");
                        filter_type_mask = UINT32_C(1) << DT_DIR;
                }

                enumeration_path = dir;
        }

        return make_choice(
                        toplevel_path,
                        toplevel_fd,
                        enumeration_path,
                        /* inode_fd= */ -EBADF,
                        &(const PickFilter) {
                                .type_mask = filter_type_mask,
                                .basename = filter_bname,
                                .version = filter->version,
                                .architecture = filter->architecture,
                                .suffix = filter_suffix,
                        },
                        flags,
                        ret);

bypass:
        /* Don't make any choice, but just use the passed path literally */
        return pin_choice(
                        toplevel_path,
                        toplevel_fd,
                        path,
                        /* inode_fd= */ -EBADF,
                        /* tries_left= */ UINT_MAX,
                        /* tries_done= */ UINT_MAX,
                        filter,
                        flags,
                        ret);
}

int path_pick_update_warn(
                char **path,
                const PickFilter *filter,
                PickFlags flags,
                PickResult *ret_result) {

        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;
        int r;

        assert(path);
        assert(*path);

        /* This updates the first argument if needed! */

        r = path_pick(/* toplevel_path= */ NULL,
                      /* toplevel_fd= */ AT_FDCWD,
                      *path,
                      filter,
                      flags,
                      &result);
        if (r == -ENOENT) {
                log_debug("Path '%s' doesn't exist, leaving as is.", *path);
                *ret_result = PICK_RESULT_NULL;
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to pick version on path '%s': %m", *path);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No matching entries in versioned directory '%s' found.", *path);

        log_debug("Resolved versioned directory pattern '%s' to file '%s' as version '%s'.", result.path, *path, strna(result.version));

        if (ret_result) {
                r = free_and_strdup_warn(path, result.path);
                if (r < 0)
                        return r;

                *ret_result = TAKE_PICK_RESULT(result);
        } else
                free_and_replace(*path, result.path);

        return 1;
}

const PickFilter pick_filter_image_raw = {
        .type_mask = (UINT32_C(1) << DT_REG) | (UINT32_C(1) << DT_BLK),
        .architecture = _ARCHITECTURE_INVALID,
        .suffix = ".raw",
};

const PickFilter pick_filter_image_dir = {
        .type_mask = UINT32_C(1) << DT_DIR,
        .architecture = _ARCHITECTURE_INVALID,
};
