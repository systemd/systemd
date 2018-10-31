/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "def.h"
#include "dirent-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "install-printf.h"
#include "install.h"
#include "locale-util.h"
#include "log.h"
#include "macro.h"
#include "mkdir.h"
#include "path-lookup.h"
#include "path-util.h"
#include "rm-rf.h"
#include "set.h"
#include "special.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"

#define UNIT_FILE_FOLLOW_SYMLINK_MAX 64

typedef enum SearchFlags {
        SEARCH_LOAD                   = 1 << 0,
        SEARCH_FOLLOW_CONFIG_SYMLINKS = 1 << 1,
        SEARCH_DROPIN                 = 1 << 2,
} SearchFlags;

typedef struct {
        OrderedHashmap *will_process;
        OrderedHashmap *have_processed;
} InstallContext;

typedef enum {
        PRESET_UNKNOWN,
        PRESET_ENABLE,
        PRESET_DISABLE,
} PresetAction;

typedef struct {
        char *pattern;
        PresetAction action;
        char **instances;
} PresetRule;

typedef struct {
        PresetRule *rules;
        size_t n_rules;
} Presets;

static inline bool unit_file_install_info_has_rules(UnitFileInstallInfo *i) {
        assert(i);

        return !strv_isempty(i->aliases) ||
               !strv_isempty(i->wanted_by) ||
               !strv_isempty(i->required_by);
}

static inline bool unit_file_install_info_has_also(UnitFileInstallInfo *i) {
        assert(i);

        return !strv_isempty(i->also);
}

static inline void presets_freep(Presets *p) {
        size_t i;

        if (!p)
                return;

        for (i = 0; i < p->n_rules; i++) {
                free(p->rules[i].pattern);
                strv_free(p->rules[i].instances);
        }

        free(p->rules);
        p->n_rules = 0;
}

bool unit_type_may_alias(UnitType type) {
        return IN_SET(type,
                      UNIT_SERVICE,
                      UNIT_SOCKET,
                      UNIT_TARGET,
                      UNIT_DEVICE,
                      UNIT_TIMER,
                      UNIT_PATH);
}

bool unit_type_may_template(UnitType type) {
        return IN_SET(type,
                      UNIT_SERVICE,
                      UNIT_SOCKET,
                      UNIT_TARGET,
                      UNIT_TIMER,
                      UNIT_PATH);
}

static const char *unit_file_type_table[_UNIT_FILE_TYPE_MAX] = {
        [UNIT_FILE_TYPE_REGULAR] = "regular",
        [UNIT_FILE_TYPE_SYMLINK] = "symlink",
        [UNIT_FILE_TYPE_MASKED] = "masked",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(unit_file_type, UnitFileType);

static int in_search_path(const LookupPaths *p, const char *path) {
        _cleanup_free_ char *parent = NULL;
        char **i;

        assert(path);

        parent = dirname_malloc(path);
        if (!parent)
                return -ENOMEM;

        STRV_FOREACH(i, p->search_path)
                if (path_equal(parent, *i))
                        return true;

        return false;
}

static const char* skip_root(const LookupPaths *p, const char *path) {
        char *e;

        assert(p);
        assert(path);

        if (!p->root_dir)
                return path;

        e = path_startswith(path, p->root_dir);
        if (!e)
                return NULL;

        /* Make sure the returned path starts with a slash */
        if (e[0] != '/') {
                if (e == path || e[-1] != '/')
                        return NULL;

                e--;
        }

        return e;
}

static int path_is_generator(const LookupPaths *p, const char *path) {
        _cleanup_free_ char *parent = NULL;

        assert(p);
        assert(path);

        parent = dirname_malloc(path);
        if (!parent)
                return -ENOMEM;

        return path_equal_ptr(parent, p->generator) ||
               path_equal_ptr(parent, p->generator_early) ||
               path_equal_ptr(parent, p->generator_late);
}

static int path_is_transient(const LookupPaths *p, const char *path) {
        _cleanup_free_ char *parent = NULL;

        assert(p);
        assert(path);

        parent = dirname_malloc(path);
        if (!parent)
                return -ENOMEM;

        return path_equal_ptr(parent, p->transient);
}

static int path_is_control(const LookupPaths *p, const char *path) {
        _cleanup_free_ char *parent = NULL;

        assert(p);
        assert(path);

        parent = dirname_malloc(path);
        if (!parent)
                return -ENOMEM;

        return path_equal_ptr(parent, p->persistent_control) ||
               path_equal_ptr(parent, p->runtime_control);
}

static int path_is_config(const LookupPaths *p, const char *path, bool check_parent) {
        _cleanup_free_ char *parent = NULL;

        assert(p);
        assert(path);

        /* Note that we do *not* have generic checks for /etc or /run in place, since with
         * them we couldn't discern configuration from transient or generated units */

        if (check_parent) {
                parent = dirname_malloc(path);
                if (!parent)
                        return -ENOMEM;

                path = parent;
        }

        return path_equal_ptr(path, p->persistent_config) ||
               path_equal_ptr(path, p->runtime_config);
}

static int path_is_runtime(const LookupPaths *p, const char *path, bool check_parent) {
        _cleanup_free_ char *parent = NULL;
        const char *rpath;

        assert(p);
        assert(path);

        /* Everything in /run is considered runtime. On top of that we also add
         * explicit checks for the various runtime directories, as safety net. */

        rpath = skip_root(p, path);
        if (rpath && path_startswith(rpath, "/run"))
                return true;

        if (check_parent) {
                parent = dirname_malloc(path);
                if (!parent)
                        return -ENOMEM;

                path = parent;
        }

        return path_equal_ptr(path, p->runtime_config) ||
               path_equal_ptr(path, p->generator) ||
               path_equal_ptr(path, p->generator_early) ||
               path_equal_ptr(path, p->generator_late) ||
               path_equal_ptr(path, p->transient) ||
               path_equal_ptr(path, p->runtime_control);
}

static int path_is_vendor(const LookupPaths *p, const char *path) {
        const char *rpath;

        assert(p);
        assert(path);

        rpath = skip_root(p, path);
        if (!rpath)
                return 0;

        if (path_startswith(rpath, "/usr"))
                return true;

#if HAVE_SPLIT_USR
        if (path_startswith(rpath, "/lib"))
                return true;
#endif

        return path_equal(rpath, SYSTEM_DATA_UNIT_PATH);
}

int unit_file_changes_add(
                UnitFileChange **changes,
                size_t *n_changes,
                UnitFileChangeType type,
                const char *path,
                const char *source) {

        _cleanup_free_ char *p = NULL, *s = NULL;
        UnitFileChange *c;

        assert(path);
        assert(!changes == !n_changes);

        if (!changes)
                return 0;

        c = reallocarray(*changes, *n_changes + 1, sizeof(UnitFileChange));
        if (!c)
                return -ENOMEM;
        *changes = c;

        p = strdup(path);
        if (source)
                s = strdup(source);

        if (!p || (source && !s))
                return -ENOMEM;

        path_simplify(p, false);
        if (s)
                path_simplify(s, false);

        c[*n_changes] = (UnitFileChange) { type, p, s };
        p = s = NULL;
        (*n_changes) ++;
        return 0;
}

void unit_file_changes_free(UnitFileChange *changes, size_t n_changes) {
        size_t i;

        assert(changes || n_changes == 0);

        for (i = 0; i < n_changes; i++) {
                free(changes[i].path);
                free(changes[i].source);
        }

        free(changes);
}

void unit_file_dump_changes(int r, const char *verb, const UnitFileChange *changes, size_t n_changes, bool quiet) {
        size_t i;
        bool logged = false;

        assert(changes || n_changes == 0);
        /* If verb is not specified, errors are not allowed! */
        assert(verb || r >= 0);

        for (i = 0; i < n_changes; i++) {
                assert(verb || changes[i].type >= 0);

                switch(changes[i].type) {
                case UNIT_FILE_SYMLINK:
                        if (!quiet)
                                log_info("Created symlink %s %s %s.",
                                         changes[i].path,
                                         special_glyph(ARROW),
                                         changes[i].source);
                        break;
                case UNIT_FILE_UNLINK:
                        if (!quiet)
                                log_info("Removed %s.", changes[i].path);
                        break;
                case UNIT_FILE_IS_MASKED:
                        if (!quiet)
                                log_info("Unit %s is masked, ignoring.", changes[i].path);
                        break;
                case UNIT_FILE_IS_DANGLING:
                        if (!quiet)
                                log_info("Unit %s is an alias to a unit that is not present, ignoring.",
                                         changes[i].path);
                        break;
                case -EEXIST:
                        if (changes[i].source)
                                log_error_errno(changes[i].type,
                                                "Failed to %s unit, file %s already exists and is a symlink to %s.",
                                                verb, changes[i].path, changes[i].source);
                        else
                                log_error_errno(changes[i].type,
                                                "Failed to %s unit, file %s already exists.",
                                                verb, changes[i].path);
                        logged = true;
                        break;
                case -ERFKILL:
                        log_error_errno(changes[i].type, "Failed to %s unit, unit %s is masked.",
                                        verb, changes[i].path);
                        logged = true;
                        break;
                case -EADDRNOTAVAIL:
                        log_error_errno(changes[i].type, "Failed to %s unit, unit %s is transient or generated.",
                                        verb, changes[i].path);
                        logged = true;
                        break;
                case -ELOOP:
                        log_error_errno(changes[i].type, "Failed to %s unit, refusing to operate on linked unit file %s",
                                        verb, changes[i].path);
                        logged = true;
                        break;

                case -ENOENT:
                        log_error_errno(changes[i].type, "Failed to %s unit, unit %s does not exist.", verb, changes[i].path);
                        logged = true;
                        break;

                default:
                        assert(changes[i].type < 0);
                        log_error_errno(changes[i].type, "Failed to %s unit, file %s: %m.",
                                        verb, changes[i].path);
                        logged = true;
                }
        }

        if (r < 0 && !logged)
                log_error_errno(r, "Failed to %s: %m.", verb);
}

/**
 * Checks if two paths or symlinks from wd are the same, when root is the root of the filesystem.
 * wc should be the full path in the host file system.
 */
static bool chroot_symlinks_same(const char *root, const char *wd, const char *a, const char *b) {
        assert(path_is_absolute(wd));

        /* This will give incorrect results if the paths are relative and go outside
         * of the chroot. False negatives are possible. */

        if (!root)
                root = "/";

        a = strjoina(path_is_absolute(a) ? root : wd, "/", a);
        b = strjoina(path_is_absolute(b) ? root : wd, "/", b);
        return path_equal_or_files_same(a, b, 0);
}

static int create_symlink(
                const LookupPaths *paths,
                const char *old_path,
                const char *new_path,
                bool force,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_free_ char *dest = NULL, *dirname = NULL;
        const char *rp;
        int r;

        assert(old_path);
        assert(new_path);

        rp = skip_root(paths, old_path);
        if (rp)
                old_path = rp;

        /* Actually create a symlink, and remember that we did. Is
         * smart enough to check if there's already a valid symlink in
         * place.
         *
         * Returns 1 if a symlink was created or already exists and points to
         * the right place, or negative on error.
         */

        mkdir_parents_label(new_path, 0755);

        if (symlink(old_path, new_path) >= 0) {
                unit_file_changes_add(changes, n_changes, UNIT_FILE_SYMLINK, new_path, old_path);
                return 1;
        }

        if (errno != EEXIST) {
                unit_file_changes_add(changes, n_changes, -errno, new_path, NULL);
                return -errno;
        }

        r = readlink_malloc(new_path, &dest);
        if (r < 0) {
                /* translate EINVAL (non-symlink exists) to EEXIST */
                if (r == -EINVAL)
                        r = -EEXIST;

                unit_file_changes_add(changes, n_changes, r, new_path, NULL);
                return r;
        }

        dirname = dirname_malloc(new_path);
        if (!dirname)
                return -ENOMEM;

        if (chroot_symlinks_same(paths->root_dir, dirname, dest, old_path))
                return 1;

        if (!force) {
                unit_file_changes_add(changes, n_changes, -EEXIST, new_path, dest);
                return -EEXIST;
        }

        r = symlink_atomic(old_path, new_path);
        if (r < 0) {
                unit_file_changes_add(changes, n_changes, r, new_path, NULL);
                return r;
        }

        unit_file_changes_add(changes, n_changes, UNIT_FILE_UNLINK, new_path, NULL);
        unit_file_changes_add(changes, n_changes, UNIT_FILE_SYMLINK, new_path, old_path);

        return 1;
}

static int mark_symlink_for_removal(
                Set **remove_symlinks_to,
                const char *p) {

        char *n;
        int r;

        assert(p);

        r = set_ensure_allocated(remove_symlinks_to, &path_hash_ops);
        if (r < 0)
                return r;

        n = strdup(p);
        if (!n)
                return -ENOMEM;

        path_simplify(n, false);

        r = set_consume(*remove_symlinks_to, n);
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return r;

        return 1;
}

static int remove_marked_symlinks_fd(
                Set *remove_symlinks_to,
                int fd,
                const char *path,
                const char *config_path,
                const LookupPaths *lp,
                bool dry_run,
                bool *restart,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        assert(remove_symlinks_to);
        assert(fd >= 0);
        assert(path);
        assert(config_path);
        assert(lp);
        assert(restart);

        d = fdopendir(fd);
        if (!d) {
                safe_close(fd);
                return -errno;
        }

        rewinddir(d);

        FOREACH_DIRENT(de, d, return -errno) {

                dirent_ensure_type(d, de);

                if (de->d_type == DT_DIR) {
                        _cleanup_free_ char *p = NULL;
                        int nfd, q;

                        nfd = openat(fd, de->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                        if (nfd < 0) {
                                if (errno == ENOENT)
                                        continue;

                                if (r == 0)
                                        r = -errno;
                                continue;
                        }

                        p = path_make_absolute(de->d_name, path);
                        if (!p) {
                                safe_close(nfd);
                                return -ENOMEM;
                        }

                        /* This will close nfd, regardless whether it succeeds or not */
                        q = remove_marked_symlinks_fd(remove_symlinks_to, nfd, p, config_path, lp, dry_run, restart, changes, n_changes);
                        if (q < 0 && r == 0)
                                r = q;

                } else if (de->d_type == DT_LNK) {
                        _cleanup_free_ char *p = NULL, *dest = NULL;
                        const char *rp;
                        bool found;
                        int q;

                        if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                                continue;

                        p = path_make_absolute(de->d_name, path);
                        if (!p)
                                return -ENOMEM;
                        path_simplify(p, false);

                        q = readlink_malloc(p, &dest);
                        if (q == -ENOENT)
                                continue;
                        if (q < 0) {
                                if (r == 0)
                                        r = q;
                                continue;
                        }

                        /* We remove all links pointing to a file or path that is marked, as well as all files sharing
                         * the same name as a file that is marked. */

                        found = set_contains(remove_symlinks_to, dest) ||
                                set_contains(remove_symlinks_to, basename(dest)) ||
                                set_contains(remove_symlinks_to, de->d_name);

                        if (!found)
                                continue;

                        if (!dry_run) {
                                if (unlinkat(fd, de->d_name, 0) < 0 && errno != ENOENT) {
                                        if (r == 0)
                                                r = -errno;
                                        unit_file_changes_add(changes, n_changes, -errno, p, NULL);
                                        continue;
                                }

                                (void) rmdir_parents(p, config_path);
                        }

                        unit_file_changes_add(changes, n_changes, UNIT_FILE_UNLINK, p, NULL);

                        /* Now, remember the full path (but with the root prefix removed) of
                         * the symlink we just removed, and remove any symlinks to it, too. */

                        rp = skip_root(lp, p);
                        q = mark_symlink_for_removal(&remove_symlinks_to, rp ?: p);
                        if (q < 0)
                                return q;
                        if (q > 0 && !dry_run)
                                *restart = true;
                }
        }

        return r;
}

static int remove_marked_symlinks(
                Set *remove_symlinks_to,
                const char *config_path,
                const LookupPaths *lp,
                bool dry_run,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_close_ int fd = -1;
        bool restart;
        int r = 0;

        assert(config_path);
        assert(lp);

        if (set_size(remove_symlinks_to) <= 0)
                return 0;

        fd = open(config_path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC);
        if (fd < 0)
                return errno == ENOENT ? 0 : -errno;

        do {
                int q, cfd;
                restart = false;

                cfd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                if (cfd < 0)
                        return -errno;

                /* This takes possession of cfd and closes it */
                q = remove_marked_symlinks_fd(remove_symlinks_to, cfd, config_path, config_path, lp, dry_run, &restart, changes, n_changes);
                if (r == 0)
                        r = q;
        } while (restart);

        return r;
}

static int is_symlink_with_known_name(const UnitFileInstallInfo *i, const char *name) {
        int r;

        if (streq(name, i->name))
                return true;

        if (strv_contains(i->aliases, name))
                return true;

        /* Look for template symlink matching DefaultInstance */
        if (i->default_instance && unit_name_is_valid(i->name, UNIT_NAME_TEMPLATE)) {
                _cleanup_free_ char *s = NULL;

                r = unit_name_replace_instance(i->name, i->default_instance, &s);
                if (r < 0) {
                        if (r != -EINVAL)
                                return r;

                } else if (streq(name, s))
                        return true;
        }

        return false;
}

static int find_symlinks_fd(
                const char *root_dir,
                UnitFileInstallInfo *i,
                bool match_aliases,
                int fd,
                const char *path,
                const char *config_path,
                bool *same_name_link) {

        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        assert(i);
        assert(fd >= 0);
        assert(path);
        assert(config_path);
        assert(same_name_link);

        d = fdopendir(fd);
        if (!d) {
                safe_close(fd);
                return -errno;
        }

        FOREACH_DIRENT(de, d, return -errno) {

                dirent_ensure_type(d, de);

                if (de->d_type == DT_DIR) {
                        _cleanup_free_ char *p = NULL;
                        int nfd, q;

                        nfd = openat(fd, de->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                        if (nfd < 0) {
                                if (errno == ENOENT)
                                        continue;

                                if (r == 0)
                                        r = -errno;
                                continue;
                        }

                        p = path_make_absolute(de->d_name, path);
                        if (!p) {
                                safe_close(nfd);
                                return -ENOMEM;
                        }

                        /* This will close nfd, regardless whether it succeeds or not */
                        q = find_symlinks_fd(root_dir, i, match_aliases, nfd,
                                             p, config_path, same_name_link);
                        if (q > 0)
                                return 1;
                        if (r == 0)
                                r = q;

                } else if (de->d_type == DT_LNK) {
                        _cleanup_free_ char *p = NULL, *dest = NULL;
                        bool found_path, found_dest, b = false;
                        int q;

                        /* Acquire symlink name */
                        p = path_make_absolute(de->d_name, path);
                        if (!p)
                                return -ENOMEM;

                        /* Acquire symlink destination */
                        q = readlink_malloc(p, &dest);
                        if (q == -ENOENT)
                                continue;
                        if (q < 0) {
                                if (r == 0)
                                        r = q;
                                continue;
                        }

                        /* Make absolute */
                        if (!path_is_absolute(dest)) {
                                char *x;

                                x = prefix_root(root_dir, dest);
                                if (!x)
                                        return -ENOMEM;

                                free(dest);
                                dest = x;
                        }

                        /* Check if the symlink itself matches what we
                         * are looking for */
                        if (path_is_absolute(i->name))
                                found_path = path_equal(p, i->name);
                        else
                                found_path = streq(de->d_name, i->name);

                        /* Check if what the symlink points to
                         * matches what we are looking for */
                        if (path_is_absolute(i->name))
                                found_dest = path_equal(dest, i->name);
                        else
                                found_dest = streq(basename(dest), i->name);

                        if (found_path && found_dest) {
                                _cleanup_free_ char *t = NULL;

                                /* Filter out same name links in the main
                                 * config path */
                                t = path_make_absolute(i->name, config_path);
                                if (!t)
                                        return -ENOMEM;

                                b = path_equal(t, p);
                        }

                        if (b)
                                *same_name_link = true;
                        else if (found_path || found_dest) {
                                if (!match_aliases)
                                        return 1;

                                /* Check if symlink name is in the set of names used by [Install] */
                                q = is_symlink_with_known_name(i, de->d_name);
                                if (q < 0)
                                        return q;
                                if (q > 0)
                                        return 1;
                        }
                }
        }

        return r;
}

static int find_symlinks(
                const char *root_dir,
                UnitFileInstallInfo *i,
                bool match_name,
                const char *config_path,
                bool *same_name_link) {

        int fd;

        assert(i);
        assert(config_path);
        assert(same_name_link);

        fd = open(config_path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC);
        if (fd < 0) {
                if (IN_SET(errno, ENOENT, ENOTDIR, EACCES))
                        return 0;
                return -errno;
        }

        /* This takes possession of fd and closes it */
        return find_symlinks_fd(root_dir, i, match_name, fd,
                                config_path, config_path, same_name_link);
}

static int find_symlinks_in_scope(
                UnitFileScope scope,
                const LookupPaths *paths,
                UnitFileInstallInfo *i,
                bool match_name,
                UnitFileState *state) {

        bool same_name_link_runtime = false, same_name_link_config = false;
        bool enabled_in_runtime = false, enabled_at_all = false;
        char **p;
        int r;

        assert(paths);
        assert(i);

        STRV_FOREACH(p, paths->search_path)  {
                bool same_name_link = false;

                r = find_symlinks(paths->root_dir, i, match_name, *p, &same_name_link);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* We found symlinks in this dir? Yay! Let's see where precisely it is enabled. */

                        if (path_equal_ptr(*p, paths->persistent_config)) {
                                /* This is the best outcome, let's return it immediately. */
                                *state = UNIT_FILE_ENABLED;
                                return 1;
                        }

                        /* look for global enablement of user units */
                        if (scope == UNIT_FILE_USER && path_is_user_config_dir(*p)) {
                                *state = UNIT_FILE_ENABLED;
                                return 1;
                        }

                        r = path_is_runtime(paths, *p, false);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                enabled_in_runtime = true;
                        else
                                enabled_at_all = true;

                } else if (same_name_link) {
                        if (path_equal_ptr(*p, paths->persistent_config))
                                same_name_link_config = true;
                        else {
                                r = path_is_runtime(paths, *p, false);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        same_name_link_runtime = true;
                        }
                }
        }

        if (enabled_in_runtime) {
                *state = UNIT_FILE_ENABLED_RUNTIME;
                return 1;
        }

        /* Here's a special rule: if the unit we are looking for is an instance, and it symlinked in the search path
         * outside of runtime and configuration directory, then we consider it statically enabled. Note we do that only
         * for instance, not for regular names, as those are merely aliases, while instances explicitly instantiate
         * something, and hence are a much stronger concept. */
        if (enabled_at_all && unit_name_is_valid(i->name, UNIT_NAME_INSTANCE)) {
                *state = UNIT_FILE_STATIC;
                return 1;
        }

        /* Hmm, we didn't find it, but maybe we found the same name
         * link? */
        if (same_name_link_config) {
                *state = UNIT_FILE_LINKED;
                return 1;
        }
        if (same_name_link_runtime) {
                *state = UNIT_FILE_LINKED_RUNTIME;
                return 1;
        }

        return 0;
}

static void install_info_free(UnitFileInstallInfo *i) {

        if (!i)
                return;

        free(i->name);
        free(i->path);
        strv_free(i->aliases);
        strv_free(i->wanted_by);
        strv_free(i->required_by);
        strv_free(i->also);
        free(i->default_instance);
        free(i->symlink_target);
        free(i);
}

static void install_context_done(InstallContext *c) {
        assert(c);

        c->will_process = ordered_hashmap_free_with_destructor(c->will_process, install_info_free);
        c->have_processed = ordered_hashmap_free_with_destructor(c->have_processed, install_info_free);
}

static UnitFileInstallInfo *install_info_find(InstallContext *c, const char *name) {
        UnitFileInstallInfo *i;

        i = ordered_hashmap_get(c->have_processed, name);
        if (i)
                return i;

        return ordered_hashmap_get(c->will_process, name);
}

static int install_info_may_process(
                UnitFileInstallInfo *i,
                const LookupPaths *paths,
                UnitFileChange **changes,
                size_t *n_changes) {
        assert(i);
        assert(paths);

        /* Checks whether the loaded unit file is one we should process, or is masked,
         * transient or generated and thus not subject to enable/disable operations. */

        if (i->type == UNIT_FILE_TYPE_MASKED) {
                unit_file_changes_add(changes, n_changes, -ERFKILL, i->path, NULL);
                return -ERFKILL;
        }
        if (path_is_generator(paths, i->path) ||
            path_is_transient(paths, i->path)) {
                unit_file_changes_add(changes, n_changes, -EADDRNOTAVAIL, i->path, NULL);
                return -EADDRNOTAVAIL;
        }

        return 0;
}

/**
 * Adds a new UnitFileInstallInfo entry under name in the InstallContext.will_process
 * hashmap, or retrieves the existing one if already present.
 *
 * Returns negative on error, 0 if the unit was already known, 1 otherwise.
 */
static int install_info_add(
                InstallContext *c,
                const char *name,
                const char *path,
                bool auxiliary,
                UnitFileInstallInfo **ret) {

        UnitFileInstallInfo *i = NULL;
        int r;

        assert(c);
        assert(name || path);

        if (!name)
                name = basename(path);

        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        i = install_info_find(c, name);
        if (i) {
                i->auxiliary = i->auxiliary && auxiliary;

                if (ret)
                        *ret = i;
                return 0;
        }

        r = ordered_hashmap_ensure_allocated(&c->will_process, &string_hash_ops);
        if (r < 0)
                return r;

        i = new0(UnitFileInstallInfo, 1);
        if (!i)
                return -ENOMEM;
        i->type = _UNIT_FILE_TYPE_INVALID;
        i->auxiliary = auxiliary;

        i->name = strdup(name);
        if (!i->name) {
                r = -ENOMEM;
                goto fail;
        }

        if (path) {
                i->path = strdup(path);
                if (!i->path) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        r = ordered_hashmap_put(c->will_process, i->name, i);
        if (r < 0)
                goto fail;

        if (ret)
                *ret = i;

        return 1;

fail:
        install_info_free(i);
        return r;
}

static int config_parse_alias(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        UnitType type;

        assert(unit);
        assert(filename);
        assert(lvalue);
        assert(rvalue);

        type = unit_name_to_type(unit);
        if (!unit_type_may_alias(type))
                return log_syntax(unit, LOG_WARNING, filename, line, 0,
                                  "Alias= is not allowed for %s units, ignoring.",
                                  unit_type_to_string(type));

        return config_parse_strv(unit, filename, line, section, section_line,
                                 lvalue, ltype, rvalue, data, userdata);
}

static int config_parse_also(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        UnitFileInstallInfo *info = userdata, *alsoinfo = NULL;
        InstallContext *c = data;
        int r;

        assert(unit);
        assert(filename);
        assert(lvalue);
        assert(rvalue);

        for (;;) {
                _cleanup_free_ char *word = NULL, *printed = NULL;

                r = extract_first_word(&rvalue, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = install_full_printf(info, word, &printed);
                if (r < 0)
                        return r;

                if (!unit_name_is_valid(printed, UNIT_NAME_ANY))
                        return -EINVAL;

                r = install_info_add(c, printed, NULL, true, &alsoinfo);
                if (r < 0)
                        return r;

                r = strv_push(&info->also, printed);
                if (r < 0)
                        return r;

                printed = NULL;
        }

        return 0;
}

static int config_parse_default_instance(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        UnitFileInstallInfo *i = data;
        _cleanup_free_ char *printed = NULL;
        int r;

        assert(unit);
        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (unit_name_is_valid(unit, UNIT_NAME_INSTANCE))
                /* When enabling an instance, we might be using a template unit file,
                 * but we should ignore DefaultInstance silently. */
                return 0;
        if (!unit_name_is_valid(unit, UNIT_NAME_TEMPLATE))
                return log_syntax(unit, LOG_WARNING, filename, line, 0,
                                  "DefaultInstance= only makes sense for template units, ignoring.");

        r = install_full_printf(i, rvalue, &printed);
        if (r < 0)
                return r;

        if (!unit_instance_is_valid(printed))
                return -EINVAL;

        return free_and_replace(i->default_instance, printed);
}

static int unit_file_load(
                InstallContext *c,
                UnitFileInstallInfo *info,
                const char *path,
                const char *root_dir,
                SearchFlags flags) {

        const ConfigTableItem items[] = {
                { "Install", "Alias",           config_parse_alias,            0, &info->aliases           },
                { "Install", "WantedBy",        config_parse_strv,             0, &info->wanted_by         },
                { "Install", "RequiredBy",      config_parse_strv,             0, &info->required_by       },
                { "Install", "DefaultInstance", config_parse_default_instance, 0, info                     },
                { "Install", "Also",            config_parse_also,             0, c                        },
                {}
        };

        UnitType type;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_close_ int fd = -1;
        struct stat st;
        int r;

        assert(info);
        assert(path);

        if (!(flags & SEARCH_DROPIN)) {
                /* Loading or checking for the main unit file… */

                type = unit_name_to_type(info->name);
                if (type < 0)
                        return -EINVAL;
                if (unit_name_is_valid(info->name, UNIT_NAME_TEMPLATE|UNIT_NAME_INSTANCE) && !unit_type_may_template(type)) {
                        log_error("Unit type %s cannot be templated.", unit_type_to_string(type));
                        return -EINVAL;
                }

                if (!(flags & SEARCH_LOAD)) {
                        r = lstat(path, &st);
                        if (r < 0)
                                return -errno;

                        if (null_or_empty(&st))
                                info->type = UNIT_FILE_TYPE_MASKED;
                        else if (S_ISREG(st.st_mode))
                                info->type = UNIT_FILE_TYPE_REGULAR;
                        else if (S_ISLNK(st.st_mode))
                                return -ELOOP;
                        else if (S_ISDIR(st.st_mode))
                                return -EISDIR;
                        else
                                return -ENOTTY;

                        return 0;
                }

                fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
                if (fd < 0)
                        return -errno;
        } else {
                /* Operating on a drop-in file. If we aren't supposed to load the unit file drop-ins don't matter, let's hence shortcut this. */

                if (!(flags & SEARCH_LOAD))
                        return 0;

                fd = chase_symlinks_and_open(path, root_dir, 0, O_RDONLY|O_CLOEXEC|O_NOCTTY, NULL);
                if (fd < 0)
                        return fd;
        }

        if (fstat(fd, &st) < 0)
                return -errno;

        if (null_or_empty(&st)) {
                if ((flags & SEARCH_DROPIN) == 0)
                        info->type = UNIT_FILE_TYPE_MASKED;

                return 0;
        }

        r = stat_verify_regular(&st);
        if (r < 0)
                return r;

        f = fdopen(fd, "re");
        if (!f)
                return -errno;
        fd = -1;

        /* c is only needed if we actually load the file (it's referenced from items[] btw, in case you wonder.) */
        assert(c);

        r = config_parse(info->name, path, f,
                         NULL,
                         config_item_table_lookup, items,
                         CONFIG_PARSE_RELAXED|CONFIG_PARSE_ALLOW_INCLUDE, info);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse %s: %m", info->name);

        if ((flags & SEARCH_DROPIN) == 0)
                info->type = UNIT_FILE_TYPE_REGULAR;

        return
                (int) strv_length(info->aliases) +
                (int) strv_length(info->wanted_by) +
                (int) strv_length(info->required_by);
}

static int unit_file_load_or_readlink(
                InstallContext *c,
                UnitFileInstallInfo *info,
                const char *path,
                const char *root_dir,
                SearchFlags flags) {

        _cleanup_free_ char *target = NULL;
        int r;

        r = unit_file_load(c, info, path, root_dir, flags);
        if (r != -ELOOP || (flags & SEARCH_DROPIN))
                return r;

        /* This is a symlink, let's read it. */

        r = readlink_malloc(path, &target);
        if (r < 0)
                return r;

        if (path_equal(target, "/dev/null"))
                info->type = UNIT_FILE_TYPE_MASKED;
        else {
                const char *bn;
                UnitType a, b;

                bn = basename(target);

                if (unit_name_is_valid(info->name, UNIT_NAME_PLAIN)) {

                        if (!unit_name_is_valid(bn, UNIT_NAME_PLAIN))
                                return -EINVAL;

                } else if (unit_name_is_valid(info->name, UNIT_NAME_INSTANCE)) {

                        if (!unit_name_is_valid(bn, UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE))
                                return -EINVAL;

                } else if (unit_name_is_valid(info->name, UNIT_NAME_TEMPLATE)) {

                        if (!unit_name_is_valid(bn, UNIT_NAME_TEMPLATE))
                                return -EINVAL;
                } else
                        return -EINVAL;

                /* Enforce that the symlink destination does not
                 * change the unit file type. */

                a = unit_name_to_type(info->name);
                b = unit_name_to_type(bn);
                if (a < 0 || b < 0 || a != b)
                        return -EINVAL;

                if (path_is_absolute(target))
                        /* This is an absolute path, prefix the root so that we always deal with fully qualified paths */
                        info->symlink_target = prefix_root(root_dir, target);
                else
                        /* This is a relative path, take it relative to the dir the symlink is located in. */
                        info->symlink_target = file_in_same_dir(path, target);
                if (!info->symlink_target)
                        return -ENOMEM;

                info->type = UNIT_FILE_TYPE_SYMLINK;
        }

        return 0;
}

static int unit_file_search(
                InstallContext *c,
                UnitFileInstallInfo *info,
                const LookupPaths *paths,
                SearchFlags flags) {

        const char *dropin_dir_name = NULL, *dropin_template_dir_name = NULL;
        _cleanup_strv_free_ char **dirs = NULL, **files = NULL;
        _cleanup_free_ char *template = NULL;
        bool found_unit = false;
        int r, result;
        char **p;

        assert(info);
        assert(paths);

        /* Was this unit already loaded? */
        if (info->type != _UNIT_FILE_TYPE_INVALID)
                return 0;

        if (info->path)
                return unit_file_load_or_readlink(c, info, info->path, paths->root_dir, flags);

        assert(info->name);

        if (unit_name_is_valid(info->name, UNIT_NAME_INSTANCE)) {
                r = unit_name_template(info->name, &template);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(p, paths->search_path) {
                _cleanup_free_ char *path = NULL;

                path = strjoin(*p, "/", info->name);
                if (!path)
                        return -ENOMEM;

                r = unit_file_load_or_readlink(c, info, path, paths->root_dir, flags);
                if (r >= 0) {
                        info->path = TAKE_PTR(path);
                        result = r;
                        found_unit = true;
                        break;
                } else if (!IN_SET(r, -ENOENT, -ENOTDIR, -EACCES))
                        return r;
        }

        if (!found_unit && template) {

                /* Unit file doesn't exist, however instance
                 * enablement was requested.  We will check if it is
                 * possible to load template unit file. */

                STRV_FOREACH(p, paths->search_path) {
                        _cleanup_free_ char *path = NULL;

                        path = strjoin(*p, "/", template);
                        if (!path)
                                return -ENOMEM;

                        r = unit_file_load_or_readlink(c, info, path, paths->root_dir, flags);
                        if (r >= 0) {
                                info->path = TAKE_PTR(path);
                                result = r;
                                found_unit = true;
                                break;
                        } else if (!IN_SET(r, -ENOENT, -ENOTDIR, -EACCES))
                                return r;
                }
        }

        if (!found_unit) {
                log_debug("Cannot find unit %s%s%s.", info->name, template ? " or " : "", strempty(template));
                return -ENOENT;
        }

        if (info->type == UNIT_FILE_TYPE_MASKED)
                return result;

        /* Search for drop-in directories */

        dropin_dir_name = strjoina(info->name, ".d");
        STRV_FOREACH(p, paths->search_path) {
                char *path;

                path = path_join(NULL, *p, dropin_dir_name);
                if (!path)
                        return -ENOMEM;

                r = strv_consume(&dirs, path);
                if (r < 0)
                        return r;
        }

        if (template) {
                dropin_template_dir_name = strjoina(template, ".d");
                STRV_FOREACH(p, paths->search_path) {
                        char *path;

                        path = path_join(NULL, *p, dropin_template_dir_name);
                        if (!path)
                                return -ENOMEM;

                        r = strv_consume(&dirs, path);
                        if (r < 0)
                                return r;
                }
        }

        /* Load drop-in conf files */

        r = conf_files_list_strv(&files, ".conf", NULL, 0, (const char**) dirs);
        if (r < 0)
                return log_debug_errno(r, "Failed to get list of conf files: %m");

        STRV_FOREACH(p, files) {
                r = unit_file_load_or_readlink(c, info, *p, paths->root_dir, flags | SEARCH_DROPIN);
                if (r < 0)
                        return log_debug_errno(r, "Failed to load conf file %s: %m", *p);
        }

        return result;
}

static int install_info_follow(
                InstallContext *c,
                UnitFileInstallInfo *i,
                const char *root_dir,
                SearchFlags flags,
                bool ignore_different_name) {

        assert(c);
        assert(i);

        if (i->type != UNIT_FILE_TYPE_SYMLINK)
                return -EINVAL;
        if (!i->symlink_target)
                return -EINVAL;

        /* If the basename doesn't match, the caller should add a
         * complete new entry for this. */

        if (!ignore_different_name && !streq(basename(i->symlink_target), i->name))
                return -EXDEV;

        free_and_replace(i->path, i->symlink_target);
        i->type = _UNIT_FILE_TYPE_INVALID;

        return unit_file_load_or_readlink(c, i, i->path, root_dir, flags);
}

/**
 * Search for the unit file. If the unit name is a symlink, follow the symlink to the
 * target, maybe more than once. Propagate the instance name if present.
 */
static int install_info_traverse(
                UnitFileScope scope,
                InstallContext *c,
                const LookupPaths *paths,
                UnitFileInstallInfo *start,
                SearchFlags flags,
                UnitFileInstallInfo **ret) {

        UnitFileInstallInfo *i;
        unsigned k = 0;
        int r;

        assert(paths);
        assert(start);
        assert(c);

        r = unit_file_search(c, start, paths, flags);
        if (r < 0)
                return r;

        i = start;
        while (i->type == UNIT_FILE_TYPE_SYMLINK) {
                /* Follow the symlink */

                if (++k > UNIT_FILE_FOLLOW_SYMLINK_MAX)
                        return -ELOOP;

                if (!(flags & SEARCH_FOLLOW_CONFIG_SYMLINKS)) {
                        r = path_is_config(paths, i->path, true);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                return -ELOOP;
                }

                r = install_info_follow(c, i, paths->root_dir, flags, false);
                if (r == -EXDEV) {
                        _cleanup_free_ char *buffer = NULL;
                        const char *bn;

                        /* Target has a different name, create a new
                         * install info object for that, and continue
                         * with that. */

                        bn = basename(i->symlink_target);

                        if (unit_name_is_valid(i->name, UNIT_NAME_INSTANCE) &&
                            unit_name_is_valid(bn, UNIT_NAME_TEMPLATE)) {

                                _cleanup_free_ char *instance = NULL;

                                r = unit_name_to_instance(i->name, &instance);
                                if (r < 0)
                                        return r;

                                r = unit_name_replace_instance(bn, instance, &buffer);
                                if (r < 0)
                                        return r;

                                if (streq(buffer, i->name)) {

                                        /* We filled in the instance, and the target stayed the same? If so, then let's
                                         * honour the link as it is. */

                                        r = install_info_follow(c, i, paths->root_dir, flags, true);
                                        if (r < 0)
                                                return r;

                                        continue;
                                }

                                bn = buffer;
                        }

                        r = install_info_add(c, bn, NULL, false, &i);
                        if (r < 0)
                                return r;

                        /* Try again, with the new target we found. */
                        r = unit_file_search(c, i, paths, flags);
                        if (r == -ENOENT)
                                /* Translate error code to highlight this specific case */
                                return -ENOLINK;
                }

                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = i;

        return 0;
}

/**
 * Call install_info_add() with name_or_path as the path (if name_or_path starts with "/")
 * or the name (otherwise). root_dir is prepended to the path.
 */
static int install_info_add_auto(
                InstallContext *c,
                const LookupPaths *paths,
                const char *name_or_path,
                UnitFileInstallInfo **ret) {

        assert(c);
        assert(name_or_path);

        if (path_is_absolute(name_or_path)) {
                const char *pp;

                pp = prefix_roota(paths->root_dir, name_or_path);

                return install_info_add(c, NULL, pp, false, ret);
        } else
                return install_info_add(c, name_or_path, NULL, false, ret);
}

static int install_info_discover(
                UnitFileScope scope,
                InstallContext *c,
                const LookupPaths *paths,
                const char *name,
                SearchFlags flags,
                UnitFileInstallInfo **ret,
                UnitFileChange **changes,
                size_t *n_changes) {

        UnitFileInstallInfo *i;
        int r;

        assert(c);
        assert(paths);
        assert(name);

        r = install_info_add_auto(c, paths, name, &i);
        if (r >= 0)
                r = install_info_traverse(scope, c, paths, i, flags, ret);

        if (r < 0)
                unit_file_changes_add(changes, n_changes, r, name, NULL);
        return r;
}

static int install_info_discover_and_check(
                        UnitFileScope scope,
                        InstallContext *c,
                        const LookupPaths *paths,
                        const char *name,
                        SearchFlags flags,
                        UnitFileInstallInfo **ret,
                        UnitFileChange **changes,
                        size_t *n_changes) {

        int r;

        r = install_info_discover(scope, c, paths, name, flags, ret, changes, n_changes);
        if (r < 0)
                return r;

        return install_info_may_process(ret ? *ret : NULL, paths, changes, n_changes);
}

static int install_info_symlink_alias(
                UnitFileInstallInfo *i,
                const LookupPaths *paths,
                const char *config_path,
                bool force,
                UnitFileChange **changes,
                size_t *n_changes) {

        char **s;
        int r = 0, q;

        assert(i);
        assert(paths);
        assert(config_path);

        STRV_FOREACH(s, i->aliases) {
                _cleanup_free_ char *alias_path = NULL, *dst = NULL;

                q = install_full_printf(i, *s, &dst);
                if (q < 0)
                        return q;

                alias_path = path_make_absolute(dst, config_path);
                if (!alias_path)
                        return -ENOMEM;

                q = create_symlink(paths, i->path, alias_path, force, changes, n_changes);
                if (r == 0)
                        r = q;
        }

        return r;
}

static int install_info_symlink_wants(
                UnitFileInstallInfo *i,
                const LookupPaths *paths,
                const char *config_path,
                char **list,
                const char *suffix,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_free_ char *buf = NULL;
        const char *n;
        char **s;
        int r = 0, q;

        assert(i);
        assert(paths);
        assert(config_path);

        if (strv_isempty(list))
                return 0;

        if (unit_name_is_valid(i->name, UNIT_NAME_TEMPLATE) && i->default_instance) {
                UnitFileInstallInfo instance = {
                        .type = _UNIT_FILE_TYPE_INVALID,
                };
                _cleanup_free_ char *path = NULL;

                r = unit_name_replace_instance(i->name, i->default_instance, &buf);
                if (r < 0)
                        return r;

                instance.name = buf;
                r = unit_file_search(NULL, &instance, paths, SEARCH_FOLLOW_CONFIG_SYMLINKS);
                if (r < 0)
                        return r;

                path = TAKE_PTR(instance.path);

                if (instance.type == UNIT_FILE_TYPE_MASKED) {
                        unit_file_changes_add(changes, n_changes, -ERFKILL, path, NULL);
                        return -ERFKILL;
                }

                n = buf;
        } else
                n = i->name;

        STRV_FOREACH(s, list) {
                _cleanup_free_ char *path = NULL, *dst = NULL;

                q = install_full_printf(i, *s, &dst);
                if (q < 0)
                        return q;

                if (!unit_name_is_valid(dst, UNIT_NAME_ANY)) {
                        r = -EINVAL;
                        continue;
                }

                path = strjoin(config_path, "/", dst, suffix, n);
                if (!path)
                        return -ENOMEM;

                q = create_symlink(paths, i->path, path, true, changes, n_changes);
                if (r == 0)
                        r = q;
        }

        return r;
}

static int install_info_symlink_link(
                UnitFileInstallInfo *i,
                const LookupPaths *paths,
                const char *config_path,
                bool force,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_free_ char *path = NULL;
        int r;

        assert(i);
        assert(paths);
        assert(config_path);
        assert(i->path);

        r = in_search_path(paths, i->path);
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        path = strjoin(config_path, "/", i->name);
        if (!path)
                return -ENOMEM;

        return create_symlink(paths, i->path, path, force, changes, n_changes);
}

static int install_info_apply(
                UnitFileInstallInfo *i,
                const LookupPaths *paths,
                const char *config_path,
                bool force,
                UnitFileChange **changes,
                size_t *n_changes) {

        int r, q;

        assert(i);
        assert(paths);
        assert(config_path);

        if (i->type != UNIT_FILE_TYPE_REGULAR)
                return 0;

        r = install_info_symlink_alias(i, paths, config_path, force, changes, n_changes);

        q = install_info_symlink_wants(i, paths, config_path, i->wanted_by, ".wants/", changes, n_changes);
        if (r == 0)
                r = q;

        q = install_info_symlink_wants(i, paths, config_path, i->required_by, ".requires/", changes, n_changes);
        if (r == 0)
                r = q;

        q = install_info_symlink_link(i, paths, config_path, force, changes, n_changes);
        /* Do not count links to the unit file towards the "carries_install_info" count */
        if (r == 0 && q < 0)
                r = q;

        return r;
}

static int install_context_apply(
                UnitFileScope scope,
                InstallContext *c,
                const LookupPaths *paths,
                const char *config_path,
                bool force,
                SearchFlags flags,
                UnitFileChange **changes,
                size_t *n_changes) {

        UnitFileInstallInfo *i;
        int r;

        assert(c);
        assert(paths);
        assert(config_path);

        if (ordered_hashmap_isempty(c->will_process))
                return 0;

        r = ordered_hashmap_ensure_allocated(&c->have_processed, &string_hash_ops);
        if (r < 0)
                return r;

        r = 0;
        while ((i = ordered_hashmap_first(c->will_process))) {
                int q;

                q = ordered_hashmap_move_one(c->have_processed, c->will_process, i->name);
                if (q < 0)
                        return q;

                q = install_info_traverse(scope, c, paths, i, flags, NULL);
                if (q < 0) {
                        unit_file_changes_add(changes, n_changes, r, i->name, NULL);
                        return q;
                }

                /* We can attempt to process a masked unit when a different unit
                 * that we were processing specifies it in Also=. */
                if (i->type == UNIT_FILE_TYPE_MASKED) {
                        unit_file_changes_add(changes, n_changes, UNIT_FILE_IS_MASKED, i->path, NULL);
                        if (r >= 0)
                                /* Assume that something *could* have been enabled here,
                                 * avoid "empty [Install] section" warning. */
                                r += 1;
                        continue;
                }

                if (i->type != UNIT_FILE_TYPE_REGULAR)
                        continue;

                q = install_info_apply(i, paths, config_path, force, changes, n_changes);
                if (r >= 0) {
                        if (q < 0)
                                r = q;
                        else
                                r += q;
                }
        }

        return r;
}

static int install_context_mark_for_removal(
                UnitFileScope scope,
                InstallContext *c,
                const LookupPaths *paths,
                Set **remove_symlinks_to,
                UnitFileChange **changes,
                size_t *n_changes) {

        UnitFileInstallInfo *i;
        int r;

        assert(c);
        assert(paths);

        /* Marks all items for removal */

        if (ordered_hashmap_isempty(c->will_process))
                return 0;

        r = ordered_hashmap_ensure_allocated(&c->have_processed, &string_hash_ops);
        if (r < 0)
                return r;

        while ((i = ordered_hashmap_first(c->will_process))) {

                r = ordered_hashmap_move_one(c->have_processed, c->will_process, i->name);
                if (r < 0)
                        return r;

                r = install_info_traverse(scope, c, paths, i, SEARCH_LOAD|SEARCH_FOLLOW_CONFIG_SYMLINKS, NULL);
                if (r == -ENOLINK) {
                        log_debug_errno(r, "Name %s leads to a dangling symlink, removing name.", i->name);
                        unit_file_changes_add(changes, n_changes, UNIT_FILE_IS_DANGLING, i->path ?: i->name, NULL);
                } else if (r == -ENOENT) {

                        if (i->auxiliary)  /* some unit specified in Also= or similar is missing */
                                log_debug_errno(r, "Auxiliary unit of %s not found, removing name.", i->name);
                        else {
                                log_debug_errno(r, "Unit %s not found, removing name.", i->name);
                                unit_file_changes_add(changes, n_changes, r, i->path ?: i->name, NULL);
                        }

                } else if (r < 0) {
                        log_debug_errno(r, "Failed to find unit %s, removing name: %m", i->name);
                        unit_file_changes_add(changes, n_changes, r, i->path ?: i->name, NULL);
                } else if (i->type == UNIT_FILE_TYPE_MASKED) {
                        log_debug("Unit file %s is masked, ignoring.", i->name);
                        unit_file_changes_add(changes, n_changes, UNIT_FILE_IS_MASKED, i->path ?: i->name, NULL);
                        continue;
                } else if (i->type != UNIT_FILE_TYPE_REGULAR) {
                        log_debug("Unit %s has type %s, ignoring.", i->name, unit_file_type_to_string(i->type) ?: "invalid");
                        continue;
                }

                r = mark_symlink_for_removal(remove_symlinks_to, i->name);
                if (r < 0)
                        return r;
        }

        return 0;
}

int unit_file_mask(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        const char *config_path;
        char **i;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        config_path = (flags & UNIT_FILE_RUNTIME) ? paths.runtime_config : paths.persistent_config;
        if (!config_path)
                return -ENXIO;

        STRV_FOREACH(i, files) {
                _cleanup_free_ char *path = NULL;
                int q;

                if (!unit_name_is_valid(*i, UNIT_NAME_ANY)) {
                        if (r == 0)
                                r = -EINVAL;
                        continue;
                }

                path = path_make_absolute(*i, config_path);
                if (!path)
                        return -ENOMEM;

                q = create_symlink(&paths, "/dev/null", path, !!(flags & UNIT_FILE_FORCE), changes, n_changes);
                if (q < 0 && r >= 0)
                        r = q;
        }

        return r;
}

int unit_file_unmask(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_set_free_free_ Set *remove_symlinks_to = NULL;
        _cleanup_strv_free_ char **todo = NULL;
        size_t n_todo = 0, n_allocated = 0;
        const char *config_path;
        char **i;
        bool dry_run = !!(flags & UNIT_FILE_DRY_RUN);
        int r, q;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        STRV_FOREACH(i, files) {
                if (!unit_name_is_valid(*i, UNIT_NAME_ANY))
                        return -EINVAL;

                FOREACH_STRING(config_path, paths.runtime_config, paths.persistent_config) {
                        _cleanup_free_ char *path = NULL;

                        path = path_make_absolute(*i, config_path);
                        if (!path)
                                return -ENOMEM;

                        r = null_or_empty_path(path);
                        if (r == -ENOENT)
                                continue;
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        if (!GREEDY_REALLOC0(todo, n_allocated, n_todo + 2))
                                return -ENOMEM;

                        todo[n_todo] = strdup(*i);
                        if (!todo[n_todo])
                                return -ENOMEM;

                        n_todo++;
                }
        }

        strv_uniq(todo);

        r = 0;
        FOREACH_STRING(config_path, paths.runtime_config, paths.persistent_config) {
                STRV_FOREACH(i, todo) {
                        _cleanup_free_ char *path = NULL;
                        const char *rp;

                        path = path_make_absolute(*i, config_path);
                        if (!path)
                                return -ENOMEM;

                        if (!dry_run && unlink(path) < 0) {
                                if (errno != ENOENT) {
                                        if (r >= 0)
                                                r = -errno;
                                        unit_file_changes_add(changes, n_changes, -errno, path, NULL);
                                }

                                continue;
                        }

                        unit_file_changes_add(changes, n_changes, UNIT_FILE_UNLINK, path, NULL);

                        rp = skip_root(&paths, path);
                        q = mark_symlink_for_removal(&remove_symlinks_to, rp ?: path);
                        if (q < 0)
                                return q;
                }

                q = remove_marked_symlinks(remove_symlinks_to, config_path, &paths, dry_run, changes, n_changes);
                if (r >= 0)
                        r = q;
        }

        return r;
}

int unit_file_link(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_strv_free_ char **todo = NULL;
        size_t n_todo = 0, n_allocated = 0;
        const char *config_path;
        char **i;
        int r, q;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        config_path = (flags & UNIT_FILE_RUNTIME) ? paths.runtime_config : paths.persistent_config;
        if (!config_path)
                return -ENXIO;

        STRV_FOREACH(i, files) {
                _cleanup_free_ char *full = NULL;
                struct stat st;
                char *fn;

                if (!path_is_absolute(*i))
                        return -EINVAL;

                fn = basename(*i);
                if (!unit_name_is_valid(fn, UNIT_NAME_ANY))
                        return -EINVAL;

                full = prefix_root(paths.root_dir, *i);
                if (!full)
                        return -ENOMEM;

                if (lstat(full, &st) < 0)
                        return -errno;
                r = stat_verify_regular(&st);
                if (r < 0)
                        return r;

                q = in_search_path(&paths, *i);
                if (q < 0)
                        return q;
                if (q > 0)
                        continue;

                if (!GREEDY_REALLOC0(todo, n_allocated, n_todo + 2))
                        return -ENOMEM;

                todo[n_todo] = strdup(*i);
                if (!todo[n_todo])
                        return -ENOMEM;

                n_todo++;
        }

        strv_uniq(todo);

        r = 0;
        STRV_FOREACH(i, todo) {
                _cleanup_free_ char *new_path = NULL;

                new_path = path_make_absolute(basename(*i), config_path);
                if (!new_path)
                        return -ENOMEM;

                q = create_symlink(&paths, *i, new_path, !!(flags & UNIT_FILE_FORCE), changes, n_changes);
                if (q < 0 && r >= 0)
                        r = q;
        }

        return r;
}

static int path_shall_revert(const LookupPaths *paths, const char *path) {
        int r;

        assert(paths);
        assert(path);

        /* Checks whether the path is one where the drop-in directories shall be removed. */

        r = path_is_config(paths, path, true);
        if (r != 0)
                return r;

        r = path_is_control(paths, path);
        if (r != 0)
                return r;

        return path_is_transient(paths, path);
}

int unit_file_revert(
                UnitFileScope scope,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_set_free_free_ Set *remove_symlinks_to = NULL;
        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_strv_free_ char **todo = NULL;
        size_t n_todo = 0, n_allocated = 0;
        char **i;
        int r, q;

        /* Puts a unit file back into vendor state. This means:
         *
         * a) we remove all drop-in snippets added by the user ("config"), add to transient units ("transient"), and
         *    added via "systemctl set-property" ("control"), but not if the drop-in is generated ("generated").
         *
         * c) if there's a vendor unit file (i.e. one in /usr) we remove any configured overriding unit files (i.e. in
         *    "config", but not in "transient" or "control" or even "generated").
         *
         * We remove all that in both the runtime and the persistent directories, if that applies.
         */

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        STRV_FOREACH(i, files) {
                bool has_vendor = false;
                char **p;

                if (!unit_name_is_valid(*i, UNIT_NAME_ANY))
                        return -EINVAL;

                STRV_FOREACH(p, paths.search_path) {
                        _cleanup_free_ char *path = NULL, *dropin = NULL;
                        struct stat st;

                        path = path_make_absolute(*i, *p);
                        if (!path)
                                return -ENOMEM;

                        r = lstat(path, &st);
                        if (r < 0) {
                                if (errno != ENOENT)
                                        return -errno;
                        } else if (S_ISREG(st.st_mode)) {
                                /* Check if there's a vendor version */
                                r = path_is_vendor(&paths, path);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        has_vendor = true;
                        }

                        dropin = strappend(path, ".d");
                        if (!dropin)
                                return -ENOMEM;

                        r = lstat(dropin, &st);
                        if (r < 0) {
                                if (errno != ENOENT)
                                        return -errno;
                        } else if (S_ISDIR(st.st_mode)) {
                                /* Remove the drop-ins */
                                r = path_shall_revert(&paths, dropin);
                                if (r < 0)
                                        return r;
                                if (r > 0) {
                                        if (!GREEDY_REALLOC0(todo, n_allocated, n_todo + 2))
                                                return -ENOMEM;

                                        todo[n_todo++] = TAKE_PTR(dropin);
                                }
                        }
                }

                if (!has_vendor)
                        continue;

                /* OK, there's a vendor version, hence drop all configuration versions */
                STRV_FOREACH(p, paths.search_path) {
                        _cleanup_free_ char *path = NULL;
                        struct stat st;

                        path = path_make_absolute(*i, *p);
                        if (!path)
                                return -ENOMEM;

                        r = lstat(path, &st);
                        if (r < 0) {
                                if (errno != ENOENT)
                                        return -errno;
                        } else if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
                                r = path_is_config(&paths, path, true);
                                if (r < 0)
                                        return r;
                                if (r > 0) {
                                        if (!GREEDY_REALLOC0(todo, n_allocated, n_todo + 2))
                                                return -ENOMEM;

                                        todo[n_todo++] = TAKE_PTR(path);
                                }
                        }
                }
        }

        strv_uniq(todo);

        r = 0;
        STRV_FOREACH(i, todo) {
                _cleanup_strv_free_ char **fs = NULL;
                const char *rp;
                char **j;

                (void) get_files_in_directory(*i, &fs);

                q = rm_rf(*i, REMOVE_ROOT|REMOVE_PHYSICAL);
                if (q < 0 && q != -ENOENT && r >= 0) {
                        r = q;
                        continue;
                }

                STRV_FOREACH(j, fs) {
                        _cleanup_free_ char *t = NULL;

                        t = strjoin(*i, "/", *j);
                        if (!t)
                                return -ENOMEM;

                        unit_file_changes_add(changes, n_changes, UNIT_FILE_UNLINK, t, NULL);
                }

                unit_file_changes_add(changes, n_changes, UNIT_FILE_UNLINK, *i, NULL);

                rp = skip_root(&paths, *i);
                q = mark_symlink_for_removal(&remove_symlinks_to, rp ?: *i);
                if (q < 0)
                        return q;
        }

        q = remove_marked_symlinks(remove_symlinks_to, paths.runtime_config, &paths, false, changes, n_changes);
        if (r >= 0)
                r = q;

        q = remove_marked_symlinks(remove_symlinks_to, paths.persistent_config, &paths, false, changes, n_changes);
        if (r >= 0)
                r = q;

        return r;
}

int unit_file_add_dependency(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                const char *target,
                UnitDependency dep,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_(install_context_done) InstallContext c = {};
        UnitFileInstallInfo *i, *target_info;
        const char *config_path;
        char **f;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(target);

        if (!IN_SET(dep, UNIT_WANTS, UNIT_REQUIRES))
                return -EINVAL;

        if (!unit_name_is_valid(target, UNIT_NAME_ANY))
                return -EINVAL;

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        config_path = (flags & UNIT_FILE_RUNTIME) ? paths.runtime_config : paths.persistent_config;
        if (!config_path)
                return -ENXIO;

        r = install_info_discover_and_check(scope, &c, &paths, target, SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                            &target_info, changes, n_changes);
        if (r < 0)
                return r;

        assert(target_info->type == UNIT_FILE_TYPE_REGULAR);

        STRV_FOREACH(f, files) {
                char ***l;

                r = install_info_discover_and_check(scope, &c, &paths, *f, SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                                    &i, changes, n_changes);
                if (r < 0)
                        return r;

                assert(i->type == UNIT_FILE_TYPE_REGULAR);

                /* We didn't actually load anything from the unit
                 * file, but instead just add in our new symlink to
                 * create. */

                if (dep == UNIT_WANTS)
                        l = &i->wanted_by;
                else
                        l = &i->required_by;

                strv_free(*l);
                *l = strv_new(target_info->name);
                if (!*l)
                        return -ENOMEM;
        }

        return install_context_apply(scope, &c, &paths, config_path, !!(flags & UNIT_FILE_FORCE), SEARCH_FOLLOW_CONFIG_SYMLINKS, changes, n_changes);
}

int unit_file_enable(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_(install_context_done) InstallContext c = {};
        const char *config_path;
        UnitFileInstallInfo *i;
        char **f;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        config_path = (flags & UNIT_FILE_RUNTIME) ? paths.runtime_config : paths.persistent_config;
        if (!config_path)
                return -ENXIO;

        STRV_FOREACH(f, files) {
                r = install_info_discover_and_check(scope, &c, &paths, *f, SEARCH_LOAD|SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                                    &i, changes, n_changes);
                if (r < 0)
                        return r;

                assert(i->type == UNIT_FILE_TYPE_REGULAR);
        }

        /* This will return the number of symlink rules that were
           supposed to be created, not the ones actually created. This
           is useful to determine whether the passed files had any
           installation data at all. */

        return install_context_apply(scope, &c, &paths, config_path, !!(flags & UNIT_FILE_FORCE), SEARCH_LOAD, changes, n_changes);
}

int unit_file_disable(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_(install_context_done) InstallContext c = {};
        _cleanup_set_free_free_ Set *remove_symlinks_to = NULL;
        bool dry_run = !!(flags & UNIT_FILE_DRY_RUN);
        const char *config_path;
        char **i;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        STRV_FOREACH(i, files) {
                if (!unit_name_is_valid(*i, UNIT_NAME_ANY))
                        return -EINVAL;

                r = install_info_add(&c, *i, NULL, false, NULL);
                if (r < 0)
                        return r;
        }

        r = install_context_mark_for_removal(scope, &c, &paths, &remove_symlinks_to, changes, n_changes);
        if (r < 0)
                return r;

        FOREACH_STRING(config_path, paths.runtime_config, paths.persistent_config) {
                r = remove_marked_symlinks(remove_symlinks_to, config_path, &paths, dry_run, changes, n_changes);
                if (r < 0)
                        return r;
        }

        return 0;
}

int unit_file_reenable(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes) {

        char **n;
        int r;
        size_t l, i;

        /* First, we invoke the disable command with only the basename... */
        l = strv_length(files);
        n = newa(char*, l+1);
        for (i = 0; i < l; i++)
                n[i] = basename(files[i]);
        n[i] = NULL;

        r = unit_file_disable(scope, flags, root_dir, n, changes, n_changes);
        if (r < 0)
                return r;

        /* But the enable command with the full name */
        return unit_file_enable(scope, flags, root_dir, files, changes, n_changes);
}

int unit_file_set_default(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                const char *name,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_(install_context_done) InstallContext c = {};
        UnitFileInstallInfo *i;
        const char *new_path;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(name);

        if (unit_name_to_type(name) != UNIT_TARGET) /* this also validates the name */
                return -EINVAL;
        if (streq(name, SPECIAL_DEFAULT_TARGET))
                return -EINVAL;

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        r = install_info_discover_and_check(scope, &c, &paths, name, 0, &i, changes, n_changes);
        if (r < 0)
                return r;

        new_path = strjoina(paths.persistent_config, "/" SPECIAL_DEFAULT_TARGET);
        return create_symlink(&paths, i->path, new_path, !!(flags & UNIT_FILE_FORCE), changes, n_changes);
}

int unit_file_get_default(
                UnitFileScope scope,
                const char *root_dir,
                char **name) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_(install_context_done) InstallContext c = {};
        UnitFileInstallInfo *i;
        char *n;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(name);

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        r = install_info_discover(scope, &c, &paths, SPECIAL_DEFAULT_TARGET, SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                  &i, NULL, NULL);
        if (r < 0)
                return r;
        r = install_info_may_process(i, &paths, NULL, 0);
        if (r < 0)
                return r;

        n = strdup(i->name);
        if (!n)
                return -ENOMEM;

        *name = n;
        return 0;
}

int unit_file_lookup_state(
                UnitFileScope scope,
                const LookupPaths *paths,
                const char *name,
                UnitFileState *ret) {

        _cleanup_(install_context_done) InstallContext c = {};
        UnitFileInstallInfo *i;
        UnitFileState state;
        int r;

        assert(paths);
        assert(name);

        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        r = install_info_discover(scope, &c, paths, name, SEARCH_LOAD|SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                  &i, NULL, NULL);
        if (r < 0)
                return r;

        /* Shortcut things, if the caller just wants to know if this unit exists. */
        if (!ret)
                return 0;

        switch (i->type) {

        case UNIT_FILE_TYPE_MASKED:
                r = path_is_runtime(paths, i->path, true);
                if (r < 0)
                        return r;

                state = r > 0 ? UNIT_FILE_MASKED_RUNTIME : UNIT_FILE_MASKED;
                break;

        case UNIT_FILE_TYPE_REGULAR:
                r = path_is_generator(paths, i->path);
                if (r < 0)
                        return r;
                if (r > 0) {
                        state = UNIT_FILE_GENERATED;
                        break;
                }

                r = path_is_transient(paths, i->path);
                if (r < 0)
                        return r;
                if (r > 0) {
                        state = UNIT_FILE_TRANSIENT;
                        break;
                }

                /* Check if any of the Alias= symlinks have been created.
                 * We ignore other aliases, and only check those that would
                 * be created by systemctl enable for this unit. */
                r = find_symlinks_in_scope(scope, paths, i, true, &state);
                if (r < 0)
                        return r;
                if (r > 0)
                        break;

                /* Check if the file is known under other names. If it is,
                 * it might be in use. Report that as UNIT_FILE_INDIRECT. */
                r = find_symlinks_in_scope(scope, paths, i, false, &state);
                if (r < 0)
                        return r;
                if (r > 0)
                        state = UNIT_FILE_INDIRECT;
                else {
                        if (unit_file_install_info_has_rules(i))
                                state = UNIT_FILE_DISABLED;
                        else if (unit_file_install_info_has_also(i))
                                state = UNIT_FILE_INDIRECT;
                        else
                                state = UNIT_FILE_STATIC;
                }

                break;

        default:
                assert_not_reached("Unexpect unit file type.");
        }

        *ret = state;
        return 0;
}

int unit_file_get_state(
                UnitFileScope scope,
                const char *root_dir,
                const char *name,
                UnitFileState *ret) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(name);

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        return unit_file_lookup_state(scope, &paths, name, ret);
}

int unit_file_exists(UnitFileScope scope, const LookupPaths *paths, const char *name) {
        _cleanup_(install_context_done) InstallContext c = {};
        int r;

        assert(paths);
        assert(name);

        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        r = install_info_discover(scope, &c, paths, name, 0, NULL, NULL, NULL);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        return 1;
}

static int split_pattern_into_name_and_instances(const char *pattern, char **out_unit_name, char ***out_instances) {
        _cleanup_strv_free_ char **instances = NULL;
        _cleanup_free_ char *unit_name = NULL;
        int r;

        assert(pattern);
        assert(out_instances);
        assert(out_unit_name);

        r = extract_first_word(&pattern, &unit_name, NULL, 0);
        if (r < 0)
                return r;

        /* We handle the instances logic when unit name is extracted */
        if (pattern) {
                /* We only create instances when a rule of templated unit
                 * is seen. A rule like enable foo@.service a b c will
                 * result in an array of (a, b, c) as instance names */
                if (!unit_name_is_valid(unit_name, UNIT_NAME_TEMPLATE))
                        return -EINVAL;

                instances = strv_split(pattern, WHITESPACE);
                if (!instances)
                        return -ENOMEM;

                *out_instances = TAKE_PTR(instances);
        }

        *out_unit_name = TAKE_PTR(unit_name);

        return 0;
}

static int read_presets(UnitFileScope scope, const char *root_dir, Presets *presets) {
        _cleanup_(presets_freep) Presets ps = {};
        size_t n_allocated = 0;
        _cleanup_strv_free_ char **files = NULL;
        char **p;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(presets);

        switch (scope) {
        case UNIT_FILE_SYSTEM:
                r = conf_files_list(&files, ".preset", root_dir, 0,
                                    "/etc/systemd/system-preset",
                                    "/run/systemd/system-preset",
                                    "/usr/local/lib/systemd/system-preset",
                                    "/usr/lib/systemd/system-preset",
#if HAVE_SPLIT_USR
                                    "/lib/systemd/system-preset",
#endif
                                    NULL);
                break;

        case UNIT_FILE_GLOBAL:
        case UNIT_FILE_USER:
                r = conf_files_list(&files, ".preset", root_dir, 0,
                                    "/etc/systemd/user-preset",
                                    "/run/systemd/user-preset",
                                    "/usr/local/lib/systemd/user-preset",
                                    "/usr/lib/systemd/user-preset",
                                    NULL);
                break;

        default:
                assert_not_reached("Invalid unit file scope");
        }

        if (r < 0)
                return r;

        STRV_FOREACH(p, files) {
                _cleanup_fclose_ FILE *f;
                int n = 0;

                f = fopen(*p, "re");
                if (!f) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                for (;;) {
                        _cleanup_free_ char *line = NULL;
                        PresetRule rule = {};
                        const char *parameter;
                        char *l;

                        r = read_line(f, LONG_LINE_MAX, &line);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        l = strstrip(line);
                        n++;

                        if (isempty(l))
                                continue;
                        if (strchr(COMMENTS, *l))
                                continue;

                        parameter = first_word(l, "enable");
                        if (parameter) {
                                char *unit_name;
                                char **instances = NULL;

                                /* Unit_name will remain the same as parameter when no instances are specified */
                                r = split_pattern_into_name_and_instances(parameter, &unit_name, &instances);
                                if (r < 0) {
                                        log_syntax(NULL, LOG_WARNING, *p, n, r, "Couldn't parse line '%s'. Ignoring.", line);
                                        continue;
                                }

                                rule = (PresetRule) {
                                        .pattern = unit_name,
                                        .action = PRESET_ENABLE,
                                        .instances = instances,
                                };
                        }

                        parameter = first_word(l, "disable");
                        if (parameter) {
                                char *pattern;

                                pattern = strdup(parameter);
                                if (!pattern)
                                        return -ENOMEM;

                                rule = (PresetRule) {
                                        .pattern = pattern,
                                        .action = PRESET_DISABLE,
                                };
                        }

                        if (rule.action) {
                                if (!GREEDY_REALLOC(ps.rules, n_allocated, ps.n_rules + 1))
                                        return -ENOMEM;

                                ps.rules[ps.n_rules++] = rule;
                                continue;
                        }

                        log_syntax(NULL, LOG_WARNING, *p, n, 0, "Couldn't parse line '%s'. Ignoring.", line);
                }
        }

        *presets = ps;
        ps = (Presets){};

        return 0;
}

static int pattern_match_multiple_instances(
                        const PresetRule rule,
                        const char *unit_name,
                        char ***ret) {

        _cleanup_free_ char *templated_name = NULL;
        int r;

        /* If no ret is needed or the rule itself does not have instances
         * initalized, we return not matching */
        if (!ret || !rule.instances)
                return 0;

        r = unit_name_template(unit_name, &templated_name);
        if (r < 0)
                return r;
        if (!streq(rule.pattern, templated_name))
                return 0;

        /* Compose a list of specified instances when unit name is a template  */
        if (unit_name_is_valid(unit_name, UNIT_NAME_TEMPLATE)) {
                _cleanup_free_ char *prefix = NULL;
                _cleanup_strv_free_ char **out_strv = NULL;
                char **iter;

                r = unit_name_to_prefix(unit_name, &prefix);
                if (r < 0)
                        return r;

                STRV_FOREACH(iter, rule.instances) {
                        _cleanup_free_ char *name = NULL;
                        r = unit_name_build(prefix, *iter, ".service", &name);
                        if (r < 0)
                                return r;
                        r = strv_extend(&out_strv, name);
                        if (r < 0)
                                return r;
                }

                *ret = TAKE_PTR(out_strv);
                return 1;
        } else {
                /* We now know the input unit name is an instance name */
                _cleanup_free_ char *instance_name = NULL;

                r = unit_name_to_instance(unit_name, &instance_name);
                if (r < 0)
                        return r;

                if (strv_find(rule.instances, instance_name))
                        return 1;
        }
        return 0;
}

static int query_presets(const char *name, const Presets presets, char ***instance_name_list) {
        PresetAction action = PRESET_UNKNOWN;
        size_t i;
        char **s;
        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        for (i = 0; i < presets.n_rules; i++)
                if (pattern_match_multiple_instances(presets.rules[i], name, instance_name_list) > 0 ||
                    fnmatch(presets.rules[i].pattern, name, FNM_NOESCAPE) == 0) {
                        action = presets.rules[i].action;
                        break;
                }

        switch (action) {
        case PRESET_UNKNOWN:
                log_debug("Preset files don't specify rule for %s. Enabling.", name);
                return 1;
        case PRESET_ENABLE:
                if (instance_name_list && *instance_name_list)
                        STRV_FOREACH(s, *instance_name_list)
                                log_debug("Preset files say enable %s.", *s);
                else
                        log_debug("Preset files say enable %s.", name);
                return 1;
        case PRESET_DISABLE:
                log_debug("Preset files say disable %s.", name);
                return 0;
        default:
                assert_not_reached("invalid preset action");
        }
}

int unit_file_query_preset(UnitFileScope scope, const char *root_dir, const char *name) {
        _cleanup_(presets_freep) Presets presets = {};
        int r;

        r = read_presets(scope, root_dir, &presets);
        if (r < 0)
                return r;

        return query_presets(name, presets, NULL);
}

static int execute_preset(
                UnitFileScope scope,
                UnitFileFlags flags,
                InstallContext *plus,
                InstallContext *minus,
                const LookupPaths *paths,
                char **files,
                UnitFilePresetMode mode,
                UnitFileChange **changes,
                size_t *n_changes) {

        const char *config_path;
        bool force = !!(flags & UNIT_FILE_FORCE);
        bool runtime = !!(flags & UNIT_FILE_RUNTIME);
        int r = 0, q;

        assert(plus);
        assert(minus);
        assert(paths);

        if (mode != UNIT_FILE_PRESET_ENABLE_ONLY) {
                _cleanup_set_free_free_ Set *remove_symlinks_to = NULL;

                q = install_context_mark_for_removal(scope, minus, paths, &remove_symlinks_to, changes, n_changes);
                if (q < 0)
                        return q;

                FOREACH_STRING(config_path, paths->runtime_config, paths->persistent_config) {
                        q = remove_marked_symlinks(remove_symlinks_to, config_path, paths, false, changes, n_changes);
                        if (r == 0)
                                r = q;
                }
        }

        if (mode != UNIT_FILE_PRESET_DISABLE_ONLY) {
                /* Returns number of symlinks that where supposed to be installed. */
                q = install_context_apply(scope, plus, paths,
                                          runtime ? paths->runtime_config : paths->persistent_config,
                                          force, SEARCH_LOAD, changes, n_changes);
                if (r == 0)
                        r = q;
        }

        return r;
}

static int preset_prepare_one(
                UnitFileScope scope,
                InstallContext *plus,
                InstallContext *minus,
                LookupPaths *paths,
                const char *name,
                Presets presets,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_(install_context_done) InstallContext tmp = {};
        _cleanup_strv_free_ char **instance_name_list = NULL;
        UnitFileInstallInfo *i;
        int r;

        if (install_info_find(plus, name) || install_info_find(minus, name))
                return 0;

        r = install_info_discover(scope, &tmp, paths, name, SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                  &i, changes, n_changes);
        if (r < 0)
                return r;
        if (!streq(name, i->name)) {
                log_debug("Skipping %s because it is an alias for %s.", name, i->name);
                return 0;
        }

        r = query_presets(name, presets, &instance_name_list);
        if (r < 0)
                return r;

        if (r > 0) {
                if (instance_name_list) {
                        char **s;
                        STRV_FOREACH(s, instance_name_list) {
                                r = install_info_discover_and_check(scope, plus, paths, *s, SEARCH_LOAD|SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                                                    &i, changes, n_changes);
                                if (r < 0)
                                        return r;
                        }
                } else {
                        r = install_info_discover_and_check(scope, plus, paths, name, SEARCH_LOAD|SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                                            &i, changes, n_changes);
                        if (r < 0)
                                return r;
                }

        } else
                r = install_info_discover(scope, minus, paths, name, SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                          &i, changes, n_changes);

        return r;
}

int unit_file_preset(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFilePresetMode mode,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_(install_context_done) InstallContext plus = {}, minus = {};
        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_(presets_freep) Presets presets = {};
        char **i;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(mode < _UNIT_FILE_PRESET_MAX);

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        r = read_presets(scope, root_dir, &presets);
        if (r < 0)
                return r;

        STRV_FOREACH(i, files) {
                r = preset_prepare_one(scope, &plus, &minus, &paths, *i, presets, changes, n_changes);
                if (r < 0)
                        return r;
        }

        return execute_preset(scope, flags, &plus, &minus, &paths, files, mode, changes, n_changes);
}

int unit_file_preset_all(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                UnitFilePresetMode mode,
                UnitFileChange **changes,
                size_t *n_changes) {

        _cleanup_(install_context_done) InstallContext plus = {}, minus = {};
        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        _cleanup_(presets_freep) Presets presets = {};
        char **i;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(mode < _UNIT_FILE_PRESET_MAX);

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        r = read_presets(scope, root_dir, &presets);
        if (r < 0)
                return r;

        STRV_FOREACH(i, paths.search_path) {
                _cleanup_closedir_ DIR *d = NULL;
                struct dirent *de;

                d = opendir(*i);
                if (!d) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                FOREACH_DIRENT(de, d, return -errno) {
                        if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                                continue;

                        dirent_ensure_type(d, de);

                        if (!IN_SET(de->d_type, DT_LNK, DT_REG))
                                continue;

                        /* we don't pass changes[] in, because we want to handle errors on our own */
                        r = preset_prepare_one(scope, &plus, &minus, &paths, de->d_name, presets, NULL, 0);
                        if (r == -ERFKILL)
                                r = unit_file_changes_add(changes, n_changes,
                                                          UNIT_FILE_IS_MASKED, de->d_name, NULL);
                        else if (r == -ENOLINK)
                                r = unit_file_changes_add(changes, n_changes,
                                                          UNIT_FILE_IS_DANGLING, de->d_name, NULL);
                        else if (r == -EADDRNOTAVAIL) /* Ignore generated/transient units when applying preset */
                                continue;
                        if (r < 0)
                                return r;
                }
        }

        return execute_preset(scope, flags, &plus, &minus, &paths, NULL, mode, changes, n_changes);
}

static void unit_file_list_free_one(UnitFileList *f) {
        if (!f)
                return;

        free(f->path);
        free(f);
}

Hashmap* unit_file_list_free(Hashmap *h) {
        return hashmap_free_with_destructor(h, unit_file_list_free_one);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UnitFileList*, unit_file_list_free_one);

int unit_file_get_list(
                UnitFileScope scope,
                const char *root_dir,
                Hashmap *h,
                char **states,
                char **patterns) {

        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        char **i;
        int r;

        assert(scope >= 0);
        assert(scope < _UNIT_FILE_SCOPE_MAX);
        assert(h);

        r = lookup_paths_init(&paths, scope, 0, root_dir);
        if (r < 0)
                return r;

        STRV_FOREACH(i, paths.search_path) {
                _cleanup_closedir_ DIR *d = NULL;
                struct dirent *de;

                d = opendir(*i);
                if (!d) {
                        if (errno == ENOENT)
                                continue;
                        if (IN_SET(errno, ENOTDIR, EACCES)) {
                                log_debug_errno(errno, "Failed to open \"%s\": %m", *i);
                                continue;
                        }

                        return -errno;
                }

                FOREACH_DIRENT(de, d, return -errno) {
                        _cleanup_(unit_file_list_free_onep) UnitFileList *f = NULL;

                        if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                                continue;

                        if (!strv_fnmatch_or_empty(patterns, de->d_name, FNM_NOESCAPE))
                                continue;

                        if (hashmap_get(h, de->d_name))
                                continue;

                        dirent_ensure_type(d, de);

                        if (!IN_SET(de->d_type, DT_LNK, DT_REG))
                                continue;

                        f = new0(UnitFileList, 1);
                        if (!f)
                                return -ENOMEM;

                        f->path = path_make_absolute(de->d_name, *i);
                        if (!f->path)
                                return -ENOMEM;

                        r = unit_file_lookup_state(scope, &paths, de->d_name, &f->state);
                        if (r < 0)
                                f->state = UNIT_FILE_BAD;

                        if (!strv_isempty(states) &&
                            !strv_contains(states, unit_file_state_to_string(f->state)))
                                continue;

                        r = hashmap_put(h, basename(f->path), f);
                        if (r < 0)
                                return r;

                        f = NULL; /* prevent cleanup */
                }
        }

        return 0;
}

static const char* const unit_file_state_table[_UNIT_FILE_STATE_MAX] = {
        [UNIT_FILE_ENABLED] = "enabled",
        [UNIT_FILE_ENABLED_RUNTIME] = "enabled-runtime",
        [UNIT_FILE_LINKED] = "linked",
        [UNIT_FILE_LINKED_RUNTIME] = "linked-runtime",
        [UNIT_FILE_MASKED] = "masked",
        [UNIT_FILE_MASKED_RUNTIME] = "masked-runtime",
        [UNIT_FILE_STATIC] = "static",
        [UNIT_FILE_DISABLED] = "disabled",
        [UNIT_FILE_INDIRECT] = "indirect",
        [UNIT_FILE_GENERATED] = "generated",
        [UNIT_FILE_TRANSIENT] = "transient",
        [UNIT_FILE_BAD] = "bad",
};

DEFINE_STRING_TABLE_LOOKUP(unit_file_state, UnitFileState);

static const char* const unit_file_change_type_table[_UNIT_FILE_CHANGE_TYPE_MAX] = {
        [UNIT_FILE_SYMLINK] = "symlink",
        [UNIT_FILE_UNLINK] = "unlink",
        [UNIT_FILE_IS_MASKED] = "masked",
        [UNIT_FILE_IS_DANGLING] = "dangling",
};

DEFINE_STRING_TABLE_LOOKUP(unit_file_change_type, UnitFileChangeType);

static const char* const unit_file_preset_mode_table[_UNIT_FILE_PRESET_MAX] = {
        [UNIT_FILE_PRESET_FULL] = "full",
        [UNIT_FILE_PRESET_ENABLE_ONLY] = "enable-only",
        [UNIT_FILE_PRESET_DISABLE_ONLY] = "disable-only",
};

DEFINE_STRING_TABLE_LOOKUP(unit_file_preset_mode, UnitFilePresetMode);
