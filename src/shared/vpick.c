/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "architecture.h"
#include "chase.h"
#include "fd-util.h"
#include "fs-util.h"
#include "vpick.h"
#include "path-util.h"
#include "recurse-dir.h"

static int format_fname(
                const char *basename,
                const char *version,
                Architecture a,
                const char *suffix,
                char **ret) {

        _cleanup_free_ char *fn = NULL;

        assert(ret);

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

        if (basename) {
                fn = strdup(basename);
                if (!fn)
                        return -ENOMEM;
        }

        if (version) {
                if (isempty(fn)) {
                        fn = strdup(version);
                        if (!fn)
                                return -ENOMEM;
                } else if (!strextend(&fn, "_", version))
                        return -ENOMEM;
        }

        if (a >= 0) {
                const char *as = architecture_to_string(a);
                if (isempty(fn)) {
                        fn = strdup(as);
                        if (!fn)
                                return -ENOMEM;
                } else if (!strextend(&fn, "_", as))
                        return -ENOMEM;
        }

        if (suffix && !strextend(&fn, suffix))
                return -ENOMEM;

        if (!filename_is_valid(fn))
                return -EINVAL;

        *ret = TAKE_PTR(fn);
        return 0;
}

static int errno_from_mode(mode_t looking_for, mode_t found) {
        /* Returns the most appropriate error code if we are lookging for an inode of type 'looking_for' but found 'found' instead */

        if (((looking_for ^ found) & S_IFMT) == 0)
                return 0;

        if (looking_for == MODE_INVALID) /* type doesn't matter */
                return 0;

        if (S_ISBLK(looking_for))
                return -ENOTBLK;
        if (S_ISDIR(looking_for))
                return -ENOTDIR;
        if (S_ISSOCK(looking_for))
                return -ENOTSOCK;

        if (S_ISLNK(found))
                return -ELOOP;
        if (S_ISDIR(found))
                return -EISDIR;

        return -EBADFD;
}

static int select_choice(
                const char *toplevel_path,
                int toplevel_fd,
                const char *inode_path,
                int _inode_fd, /* we always take ownership of the fd, even on failure */
                mode_t search_mode,
                const char *search_basename,
                const char *search_version,
                Architecture search_architecture,
                const char *search_suffix,
                char **ret_inode_path,
                int *ret_inode_fd,
                mode_t *ret_inode_mode,
                char **ret_version,
                Architecture *ret_architecture) {

        _cleanup_free_ char *p = NULL, *v = NULL;
        _cleanup_close_ int fd = -EBADF, inode_fd = TAKE_FD(_inode_fd);
        struct stat st;

        assert(toplevel_fd >= 0 || toplevel_fd == AT_FDCWD);
        assert(inode_path);
        assert(inode_fd >= 0);

        toplevel_path = strempty(toplevel_path);

        if (search_mode != MODE_INVALID || ret_inode_mode) {
                if (fstat(inode_fd, &st) < 0)
                        return log_debug_errno(errno, "Failed to stat discovered inode '%s/%s': %m", toplevel_path, inode_path);

                if (search_mode != MODE_INVALID &&
                    ((search_mode ^ st.st_mode) & S_IFMT) != 0)
                        return log_debug_errno(
                                        SYNTHETIC_ERRNO(errno_from_mode(search_mode, st.st_mode)),
                                        "Inode '%s/%s' has wrong type, was looking for '%s', got '%s'.",
                                        toplevel_path, inode_path,
                                        inode_type_to_string(search_mode), inode_type_to_string(st.st_mode));
        }

        if (ret_inode_path) {
                p = strdup(inode_path);
                if (!p)
                        return log_oom_debug();
        }

        if (ret_version && search_version) {
                v = strdup(search_version);
                if (!v)
                        return log_oom_debug();
        }

        if (ret_inode_path)
                *ret_inode_path = TAKE_PTR(p);
        if (ret_inode_fd)
                *ret_inode_fd = TAKE_FD(inode_fd);
        if (ret_inode_mode)
                *ret_inode_mode = st.st_mode;
        if (ret_version)
                *ret_version = TAKE_PTR(v);
        if (ret_architecture)
                *ret_architecture = search_architecture;

        return 1;
}

static int make_choice(
                const char *toplevel_path,
                int toplevel_fd,
                const char *inode_path,
                int _inode_fd, /* we always take ownership of the fd, even on failure */
                mode_t search_mode,
                const char *search_basename,
                const char *search_version,
                Architecture search_architecture,
                const char *search_suffix,
                char **ret_inode_path,
                int *ret_inode_fd,
                mode_t *ret_inode_mode,
                char **ret_version,
                Architecture *ret_architecture) {

        static const Architecture local_architectures[] = {
                /* In order of preference */
                native_architecture(),
#ifdef ARCHITECTURE_SECONDARY
                ARCHITECTURE_SECONDARY,
#endif
                _ARCHITECTURE_INVALID,
        };

        _cleanup_free_ DirectoryEntries *de = NULL;
        _cleanup_free_ char *best_version = NULL, *best_filename = NULL, *p = NULL, *object = NULL;
        _cleanup_close_ int dir_fd = -EBADF, object_fd = -EBADF, inode_fd = TAKE_FD(_inode_fd);
        const Architecture *architectures, *best_architecture = NULL;
        size_t n_architectures;
        int r;

        assert(toplevel_fd >= 0 || toplevel_fd == AT_FDCWD);
        assert(inode_path);
        assert(inode_fd >= 0);

        toplevel_path = strempty(toplevel_path);

        if (search_version && search_architecture >= 0) {
                _cleanup_free_ char *j = NULL;

                /* If we already know the version and architecture, we can directly check if we can open it */

                r = format_fname(search_basename, search_version, search_architecture, search_suffix, &j);
                if (r < 0)
                        return log_debug_errno(r, "Failed to format file name: %m");

                p = path_join(inode_path, j);
                if (!p)
                        return log_oom_debug();

                r = chaseat(toplevel_fd, p, CHASE_AT_RESOLVE_IN_ROOT, &object, &object_fd);
                if (r < 0) {
                        if (r != -ENOENT)
                                return log_debug_errno(r, "Failed to open '%s/%s': %m", toplevel_path, p);

                        goto not_found;
                } else
                        goto found;
        }

        /* Convert O_PATH to a regular directory fd */
        dir_fd = fd_reopen(inode_fd, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
        if (dir_fd < 0)
                return log_debug_errno(dir_fd, "Failed to reopen '%s/%s' as directory: %m", toplevel_path, inode_path);

        r = readdir_all(dir_fd, 0, &de);
        if (r < 0)
                return log_debug_errno(r, "Failed to read directory '%s/%s': %m", toplevel_path, inode_path);

        if (search_architecture < 0) {
                architectures = local_architectures;
                n_architectures = ELEMENTSOF(local_architectures);
        } else {
                architectures = &search_architecture;
                n_architectures = 1;
        }

        FOREACH_ARRAY(entry, de->entries, de->n_entries) {
                _cleanup_free_ char *chopped = NULL, *chopped2 = NULL;
                const Architecture *found_architecture = NULL;
                const char *e;

                if (!isempty(search_basename)) {
                        e = startswith((*entry)->d_name, search_basename);
                        if (!e)
                                continue;

                        if (e[0] != '_')
                                continue;

                        e++;
                } else
                        e = (*entry)->d_name;

                if (!isempty(search_suffix)) {
                        const char *sfx;

                        sfx = endswith(e, search_suffix);
                        if (!sfx)
                                continue;

                        chopped = strndup(e, sfx - e);
                        if (!chopped)
                                return log_oom_debug();

                        e = chopped;
                }

                FOREACH_ARRAY(a, architectures, n_architectures) {

                        if (*a >= 0) {
                                const char *as, *end;

                                as = ASSERT_PTR(architecture_to_string(*a));

                                end = endswith(e, as);
                                if (!end)
                                        continue;
                                if (end > e) {
                                        if (end[-1] != '_')
                                                continue;

                                        end--;
                                }

                                chopped2 = strndup(e, end - e);
                                if (!chopped2)
                                        return log_oom_debug();

                                e = chopped2;
                        } else {
                                const char *pa;
                                /* If an item without an architecture specification is OK, then check if this entry really has none */

                                pa = strrchr(e, '_');
                                if (pa)
                                        pa++;
                                else
                                        pa = e;
                                if (architecture_from_string(pa) >= 0)
                                        continue;
                        }

                        found_architecture = a;
                        break;
                }
                if (!found_architecture) /* no matching arch found */
                        continue;

                if (!isempty(e) && !version_is_valid(e)) {
                        log_debug("Version string '%s' of entry '%s' is invalid, ignoring entry.", e, (*entry)->d_name);
                        continue;
                }

                assert(!best_version == !best_filename);

                if (search_version) {
                        if (!streq(search_version, e))
                                continue;
                } else {
                        if (best_version && strverscmp_improved(e, best_version) < 0)
                                continue;
                }

                if (best_version &&
                    found_architecture &&
                    best_architecture &&
                    found_architecture > best_architecture)
                        continue;

                r = free_and_strdup_warn(&best_version, e);
                if (r < 0)
                        return r;

                r = free_and_strdup_warn(&best_filename, (*entry)->d_name);
                if (r < 0)
                        return r;

                best_architecture = found_architecture;
        }

        if (!best_version)
                goto not_found;

        p = path_join(inode_path, best_filename);
        if (!p)
                return log_oom_debug();

        r = chaseat(toplevel_fd, p, CHASE_AT_RESOLVE_IN_ROOT, &object, &object_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to open '%s/%s': %m", toplevel_path, p);

        search_architecture = *best_architecture;
        search_version = empty_to_null(best_version);

found:
        return select_choice(
                        toplevel_path,
                        toplevel_fd,
                        object,
                        TAKE_FD(object_fd),
                        search_mode,
                        search_basename,
                        search_version,
                        search_architecture,
                        search_suffix,
                        ret_inode_path,
                        ret_inode_fd,
                        ret_inode_mode,
                        ret_version,
                        ret_architecture);

not_found:
        if (ret_inode_path)
                *ret_inode_path = NULL;
        if (ret_inode_fd)
                *ret_inode_fd = -EBADF;
        if (ret_inode_mode)
                *ret_inode_mode = MODE_INVALID;
        if (ret_version)
                *ret_version = NULL;
        if (ret_architecture)
                *ret_architecture = _ARCHITECTURE_INVALID;

        return 0;
}

int path_pick(const char *toplevel_path,
              int toplevel_fd,
              const char *path,
              mode_t search_mode,
              const char *search_basename,
              const char *search_version,
              Architecture search_architecture,
              const char *search_suffix,
              char **ret_inode_path,
              int *ret_inode_fd,
              mode_t *ret_inode_mode,
              char **ret_version,
              Architecture *ret_architecture) {

        _cleanup_free_ char *dir = NULL, *pattern = NULL, *fname = NULL;
        typeof(select_choice) *func = NULL;
        _cleanup_close_ int fd = -1;
        const char *bn = NULL;
        int r;

        assert(toplevel_fd >= 0 || toplevel_fd == AT_FDCWD);
        assert(path);

        toplevel_path = strempty(toplevel_path);

        /* Given a path, resolve .v/ subdir logic (if used!), and returns the choice made. This supports
         * three ways to be called:
         *
         * • with path referring to any kind of directory, but search_basename/search_suffix explicitly
         *   specified with suitable basename + suffix for files to search for inside.
         *
         * • with path referring to a directory ending in .v/. In this case the pattern to search for inside
         *   the dir is derived from the directory name. Example: "/foo/bar/baz.v" → we'll search for
         *   "/foo/bar/baz.v/baz*".
         *
         * • with path whose penultimate component ends in .v/. In this case the last component of the path
         *   refers to the pattern. Example: "/foo/bar/baz.v/waldo" → we'll search for
         *   "/foo/bar/baz.v/waldo*".
         *
         * When deriving the match pattern from the path, we allow a triple underscore "___" to indicate
         * where to fill in version/architecture. Example: "/foo/bar/baz___.raw.v/" (which looks for
         * /foo/bar/baz___.raw.v/baz*.raw") or "/foo/bar/baz.v/waldo___.raw" (which looks for
         * /foo/bar/baz.v/waldo*.raw).
         */

        if (search_basename) {
                /* Explicit basename specified, then shortcut things and do .v mode regardless of the path name. */
                bn = search_basename;
                func = make_choice;
                goto open_now;
        }

        r = path_extract_filename(path, &fname);
        if (r < 0) {
                if (r != -EADDRNOTAVAIL)
                        return r;

                /* If there's not path element we can derive a pattern off, the don't */
                func = select_choice;
                goto open_now;
        }

        /* remember of the path ends in a suffix */
        bool slash_suffix = r == O_DIRECTORY;

        const char *e = endswith(fname, ".v");
        if (e) {
                /* So a path in the form /foo/bar/baz.v is specified. In this case our search pattern is "baz" */
                pattern = strndup(fname, e - fname);
                if (!pattern)
                        return -ENOMEM;
        } else {
                r = path_extract_directory(path, &dir);
                if (r < 0) {
                        if (!IN_SET(r, -EDESTADDRREQ, -EADDRNOTAVAIL))
                                return r;
                } else {
                        _cleanup_free_ char *parent = NULL;

                        r = path_extract_filename(dir, &parent);
                        if (r < 0) {
                                if (r != -EADDRNOTAVAIL)
                                        return r;
                        } else {
                                e = endswith(parent, ".v");
                                if (e) {
                                        /* So a path in the form /quux/waldo.v/wuff is specified. In this
                                         * case our search pattern is "wuff". But before we go for it, we
                                         * check if the full path might exist as-is, because if so this
                                         * trumps the pattern logic. */

                                        r = chaseat(toplevel_fd, path, CHASE_AT_RESOLVE_IN_ROOT, NULL, &fd);
                                        if (r < 0) {
                                                if (r != -ENOENT)
                                                        return r;
                                        } else {
                                                func = select_choice;
                                                goto ready; /* this worked? bypass pattern logic */
                                        }

                                        if (slash_suffix) {
                                                /* If the pattern is suffixed by a / then we are looking for directories apparently. */
                                                if (search_mode == MODE_INVALID)
                                                        search_mode = S_IFDIR;
                                                else if (!S_ISDIR(search_mode))
                                                        return log_debug_errno(SYNTHETIC_ERRNO(errno_from_mode(search_mode, S_IFDIR)),
                                                                               "Specified pattern ends in '/', but not looking for directories, refusing.");
                                        }

                                        pattern = TAKE_PTR(fname);
                                        path = dir;
                                }
                        }
                }
        }

        if (pattern) {
                char *wildcard;

                /* We are in .v/ mode! Now check if the path contains a wildcard sequence ("___"), in
                 * which case we have both a search suffix and a basename to look for. Otherwise only
                 * a basename. */

                wildcard = strrstr(pattern, "___");
                if (wildcard) {
                        search_suffix = empty_to_null(wildcard + 3);
                        *wildcard = 0;
                }

                func = make_choice;
                bn = pattern;
        } else /* Not in .v mode, take path literally */
                func = select_choice;

open_now:
        r = chaseat(toplevel_fd, path, CHASE_AT_RESOLVE_IN_ROOT, NULL, &fd);
        if (r < 0)
                return r;

ready:
        return func(toplevel_path,
                    toplevel_fd,
                    path,
                    TAKE_FD(fd),
                    search_mode,
                    bn,
                    search_version,
                    search_architecture,
                    search_suffix,
                    ret_inode_path,
                    ret_inode_fd,
                    ret_inode_mode,
                    ret_version,
                    ret_architecture);
}

int path_pick_update_warn(
                char **path,
                mode_t search_mode,
                Architecture search_architecture,
                const char *search_suffix,
                Architecture *ret_architecture) {

        _cleanup_free_ char *p = NULL, *version = NULL;
        Architecture a;
        int r;

        assert(path);
        assert(*path);

        /* This updates the first argument if needed! */

        r = path_pick(/* toplevel_path= */ NULL,
                      /* toplevel_fd= */ AT_FDCWD,
                      *path,
                      search_mode,
                      /* search_basename= */ NULL,
                      /* search_version= */ NULL,
                      search_architecture,
                      search_suffix,
                      &p,
                      /* ret_inode_fd= */ NULL,
                      /* ret_inode_mode= */ NULL,
                      &version,
                      &a);
        if (r == -ENOENT) {
                log_debug("Path '%s' doesn't exist, leaving as is.", *path);

                if (ret_architecture)
                        *ret_architecture = _ARCHITECTURE_INVALID;
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to pick version on path '%s': %m", *path);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Not matching entries in versioned directory '%s' found.", *path);

        log_debug("Resolved versioned directory pattern '%s' to file '%s' as version '%s'.", p, *path, strna(version));

        free(*path);
        *path = TAKE_PTR(p);

        if (ret_architecture)
                *ret_architecture = a;

        return r;
}
