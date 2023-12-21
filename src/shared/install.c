/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "constants.h"
#include "dirent-util.h"
#include "errno-list.h"
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
#include "mkdir-label.h"
#include "path-lookup.h"
#include "path-util.h"
#include "rm-rf.h"
#include "set.h"
#include "special.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit-file.h"

#define UNIT_FILE_FOLLOW_SYMLINK_MAX 64

typedef enum SearchFlags {
        SEARCH_LOAD                   = 1 << 0,
        SEARCH_FOLLOW_CONFIG_SYMLINKS = 1 << 1,
        SEARCH_DROPIN                 = 1 << 2,
} SearchFlags;

typedef struct {
        RuntimeScope scope;
        OrderedHashmap *will_process;
        OrderedHashmap *have_processed;
} InstallContext;

struct UnitFilePresetRule {
        char *pattern;
        PresetAction action;
        char **instances;
};

/* NB! strings use past tense. */
static const char *const preset_action_past_tense_table[_PRESET_ACTION_MAX] = {
        [PRESET_UNKNOWN] = "unknown",
        [PRESET_ENABLE]  = "enabled",
        [PRESET_DISABLE] = "disabled",
        [PRESET_IGNORE]  = "ignored",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(preset_action_past_tense, PresetAction);

static bool install_info_has_rules(const InstallInfo *i) {
        assert(i);

        return !strv_isempty(i->aliases) ||
               !strv_isempty(i->wanted_by) ||
               !strv_isempty(i->required_by) ||
               !strv_isempty(i->upheld_by);
}

static bool install_info_has_also(const InstallInfo *i) {
        assert(i);

        return !strv_isempty(i->also);
}

static void unit_file_preset_rule_done(UnitFilePresetRule *rule) {
        assert(rule);

        free(rule->pattern);
        strv_free(rule->instances);
}

void unit_file_presets_done(UnitFilePresets *p) {
        if (!p)
                return;

        FOREACH_ARRAY(rule, p->rules, p->n_rules)
                unit_file_preset_rule_done(rule);

        free(p->rules);
        p->n_rules = 0;
}

static const char *const install_mode_table[_INSTALL_MODE_MAX] = {
        [INSTALL_MODE_REGULAR] = "regular",
        [INSTALL_MODE_LINKED]  = "linked",
        [INSTALL_MODE_ALIAS]   = "alias",
        [INSTALL_MODE_MASKED]  = "masked",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(install_mode, InstallMode);

static int in_search_path(const LookupPaths *lp, const char *path) {
        _cleanup_free_ char *parent = NULL;
        int r;

        /* Check if 'path' is in lp->search_path. */

        r = path_extract_directory(ASSERT_PTR(path), &parent);
        if (r < 0)
                return r;

        return path_strv_contains(ASSERT_PTR(lp)->search_path, parent);
}

static int underneath_search_path(const LookupPaths *lp, const char *path) {
        /* Check if 'path' is underneath lp->search_path. */

        return !!path_startswith_strv(ASSERT_PTR(path), ASSERT_PTR(lp)->search_path);
}

static const char* skip_root(const char *root_dir, const char *path) {
        assert(path);

        if (!root_dir)
                return path;

        const char *e = path_startswith(path, root_dir);
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

static int path_is_generator(const LookupPaths *lp, const char *path) {
        _cleanup_free_ char *parent = NULL;
        int r;

        assert(lp);
        assert(path);

        r = path_extract_directory(path, &parent);
        if (r < 0)
                return r;

        return path_equal_ptr(parent, lp->generator) ||
               path_equal_ptr(parent, lp->generator_early) ||
               path_equal_ptr(parent, lp->generator_late);
}

static int path_is_transient(const LookupPaths *lp, const char *path) {
        _cleanup_free_ char *parent = NULL;
        int r;

        assert(lp);
        assert(path);

        r = path_extract_directory(path, &parent);
        if (r < 0)
                return r;

        return path_equal_ptr(parent, lp->transient);
}

static int path_is_control(const LookupPaths *lp, const char *path) {
        _cleanup_free_ char *parent = NULL;
        int r;

        assert(lp);
        assert(path);

        r = path_extract_directory(path, &parent);
        if (r < 0)
                return r;

        return path_equal_ptr(parent, lp->persistent_control) ||
               path_equal_ptr(parent, lp->runtime_control);
}

static int path_is_config(const LookupPaths *lp, const char *path, bool check_parent) {
        _cleanup_free_ char *parent = NULL;
        int r;

        assert(lp);
        assert(path);

        /* Note that we do *not* have generic checks for /etc or /run in place, since with
         * them we couldn't discern configuration from transient or generated units */

        if (check_parent) {
                r = path_extract_directory(path, &parent);
                if (r < 0)
                        return r;

                path = parent;
        }

        return path_equal_ptr(path, lp->persistent_config) ||
               path_equal_ptr(path, lp->runtime_config);
}

static int path_is_runtime(const LookupPaths *lp, const char *path, bool check_parent) {
        _cleanup_free_ char *parent = NULL;
        const char *rpath;
        int r;

        assert(lp);
        assert(path);

        /* Everything in /run is considered runtime. On top of that we also add
         * explicit checks for the various runtime directories, as safety net. */

        rpath = skip_root(lp->root_dir, path);
        if (rpath && path_startswith(rpath, "/run"))
                return true;

        if (check_parent) {
                r = path_extract_directory(path, &parent);
                if (r < 0)
                        return r;

                path = parent;
        }

        return path_equal_ptr(path, lp->runtime_config) ||
               path_equal_ptr(path, lp->generator) ||
               path_equal_ptr(path, lp->generator_early) ||
               path_equal_ptr(path, lp->generator_late) ||
               path_equal_ptr(path, lp->transient) ||
               path_equal_ptr(path, lp->runtime_control);
}

static int path_is_vendor_or_generator(const LookupPaths *lp, const char *path) {
        const char *rpath;

        assert(lp);
        assert(path);

        rpath = skip_root(lp->root_dir, path);
        if (!rpath)
                return 0;

        if (path_startswith(rpath, "/usr"))
                return true;

        if (path_is_generator(lp, rpath))
                return true;

        return path_equal(rpath, SYSTEM_DATA_UNIT_DIR);
}

static const char* config_path_from_flags(const LookupPaths *lp, UnitFileFlags flags) {
        assert(lp);

        if (FLAGS_SET(flags, UNIT_FILE_PORTABLE))
                return FLAGS_SET(flags, UNIT_FILE_RUNTIME) ? lp->runtime_attached : lp->persistent_attached;
        else
                return FLAGS_SET(flags, UNIT_FILE_RUNTIME) ? lp->runtime_config : lp->persistent_config;
}

InstallChangeType install_changes_add(
                InstallChange **changes,
                size_t *n_changes,
                InstallChangeType type, /* INSTALL_CHANGE_SYMLINK, _UNLINK, _IS_MASKED, _IS_DANGLING, … if positive or errno if negative */
                const char *path,
                const char *source) {

        _cleanup_free_ char *p = NULL, *s = NULL;
        InstallChange *c;
        int r;

        assert(!changes == !n_changes);
        assert(INSTALL_CHANGE_TYPE_VALID(type));

        /* Message formatting requires <path> to be set. */
        assert(path);

        /* Register a change or error. Note that the return value may be the error
         * that was passed in, or -ENOMEM generated internally. */

        if (!changes)
                return type;

        c = reallocarray(*changes, *n_changes + 1, sizeof(InstallChange));
        if (!c)
                return -ENOMEM;
        *changes = c;

        r = path_simplify_alloc(path, &p);
        if (r < 0)
                return r;

        r = path_simplify_alloc(source, &s);
        if (r < 0)
                return r;

        c[(*n_changes)++] = (InstallChange) {
                .type = type,
                .path = TAKE_PTR(p),
                .source = TAKE_PTR(s),
        };

        return type;
}

void install_changes_free(InstallChange *changes, size_t n_changes) {
        assert(changes || n_changes == 0);

        for (size_t i = 0; i < n_changes; i++) {
                free(changes[i].path);
                free(changes[i].source);
        }

        free(changes);
}

void install_changes_dump(int r, const char *verb, const InstallChange *changes, size_t n_changes, bool quiet) {
        int err = 0;

        assert(changes || n_changes == 0);
        /* If verb is not specified, errors are not allowed! */
        assert(verb || r >= 0);

        for (size_t i = 0; i < n_changes; i++) {
                if (changes[i].type < 0)
                        assert(verb);
                assert(changes[i].path);

                /* When making changes here, make sure to also change install_error() in dbus-manager.c. */

                switch (changes[i].type) {
                case INSTALL_CHANGE_SYMLINK:
                        if (!quiet)
                                log_info("Created symlink %s %s %s.",
                                         changes[i].path,
                                         special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                                         changes[i].source);
                        break;
                case INSTALL_CHANGE_UNLINK:
                        if (!quiet)
                                log_info("Removed \"%s\".", changes[i].path);
                        break;
                case INSTALL_CHANGE_IS_MASKED:
                        if (!quiet)
                                log_info("Unit %s is masked, ignoring.", changes[i].path);
                        break;
                case INSTALL_CHANGE_IS_MASKED_GENERATOR:
                        if (!quiet)
                                log_info("Unit %s is masked via a generator and cannot be unmasked.",
                                         changes[i].path);
                        break;
                case INSTALL_CHANGE_IS_DANGLING:
                        if (!quiet)
                                log_info("Unit %s is an alias to a unit that is not present, ignoring.",
                                         changes[i].path);
                        break;
                case INSTALL_CHANGE_DESTINATION_NOT_PRESENT:
                        if (!quiet)
                                log_warning("Unit %s is added as a dependency to a non-existent unit %s.",
                                            changes[i].source, changes[i].path);
                        break;
                case INSTALL_CHANGE_AUXILIARY_FAILED:
                        if (!quiet)
                                log_warning("Failed to enable auxiliary unit %s, ignoring.", changes[i].path);
                        break;
                case -EEXIST:
                        if (changes[i].source)
                                err = log_error_errno(changes[i].type,
                                                      "Failed to %s unit, file \"%s\" already exists and is a symlink to \"%s\".",
                                                      verb, changes[i].path, changes[i].source);
                        else
                                err = log_error_errno(changes[i].type,
                                                      "Failed to %s unit, file \"%s\" already exists.",
                                                      verb, changes[i].path);
                        break;
                case -ERFKILL:
                        err = log_error_errno(changes[i].type, "Failed to %s unit, unit %s is masked.",
                                              verb, changes[i].path);
                        break;
                case -EADDRNOTAVAIL:
                        err = log_error_errno(changes[i].type, "Failed to %s unit, unit %s is transient or generated.",
                                              verb, changes[i].path);
                        break;
                case -ETXTBSY:
                        err = log_error_errno(changes[i].type, "Failed to %s unit, file %s is under the systemd unit hierarchy already.",
                                              verb, changes[i].path);
                        break;
                case -EBADSLT:
                        err = log_error_errno(changes[i].type, "Failed to %s unit, invalid specifier in \"%s\".",
                                              verb, changes[i].path);
                        break;
                case -EIDRM:
                        err = log_error_errno(changes[i].type, "Failed to %s %s, destination unit %s is a non-template unit.",
                                              verb, changes[i].source, changes[i].path);
                        break;
                case -EUCLEAN:
                        err = log_error_errno(changes[i].type,
                                              "Failed to %s unit, \"%s\" is not a valid unit name.",
                                              verb, changes[i].path);
                        break;
                case -ELOOP:
                        err = log_error_errno(changes[i].type, "Failed to %s unit, refusing to operate on linked unit file %s.",
                                              verb, changes[i].path);
                        break;
                case -EXDEV:
                        if (changes[i].source)
                                err = log_error_errno(changes[i].type, "Failed to %s unit, cannot alias %s as %s.",
                                                      verb, changes[i].source, changes[i].path);
                        else
                                err = log_error_errno(changes[i].type, "Failed to %s unit, invalid unit reference \"%s\".",
                                                      verb, changes[i].path);
                        break;
                case -ENOENT:
                        err = log_error_errno(changes[i].type, "Failed to %s unit, unit %s does not exist.",
                                              verb, changes[i].path);
                        break;
                case -EUNATCH:
                        err = log_error_errno(changes[i].type, "Failed to %s unit, cannot resolve specifiers in \"%s\".",
                                              verb, changes[i].path);
                        break;
                default:
                        assert(changes[i].type < 0);
                        err = log_error_errno(changes[i].type, "Failed to %s unit, file \"%s\": %m",
                                              verb, changes[i].path);
                }
        }

        if (r < 0 && err >= 0)
                log_error_errno(r, "Failed to %s: %m.", verb);
}

/**
 * Checks if two symlink targets (starting from src) are equivalent as far as the unit enablement logic is
 * concerned. If the target is in the unit search path, then anything with the same name is equivalent.
 * If outside the unit search path, paths must be identical.
 */
static int chroot_unit_symlinks_equivalent(
                const LookupPaths *lp,
                const char *src,
                const char *target_a,
                const char *target_b) {

        assert(lp);
        assert(src);
        assert(target_a);
        assert(target_b);

        /* This will give incorrect results if the paths are relative and go outside
         * of the chroot. False negatives are possible. */

        const char *root = lp->root_dir ?: "/";
        _cleanup_free_ char *dirname = NULL;
        int r;

        if (!path_is_absolute(target_a) || !path_is_absolute(target_b)) {
                r = path_extract_directory(src, &dirname);
                if (r < 0)
                        return r;
        }

        _cleanup_free_ char *a = path_join(path_is_absolute(target_a) ? root : dirname, target_a);
        _cleanup_free_ char *b = path_join(path_is_absolute(target_b) ? root : dirname, target_b);
        if (!a || !b)
                return log_oom();

        r = path_equal_or_inode_same(a, b, 0);
        if (r != 0)
                return r;

        _cleanup_free_ char *a_name = NULL, *b_name = NULL;
        r = path_extract_filename(a, &a_name);
        if (r < 0)
                return r;
        r = path_extract_filename(b, &b_name);
        if (r < 0)
                return r;

        return streq(a_name, b_name) &&
               path_startswith_strv(a, lp->search_path) &&
               path_startswith_strv(b, lp->search_path);
}

static int create_symlink(
                const LookupPaths *lp,
                const char *old_path,
                const char *new_path,
                bool force,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_free_ char *dest = NULL;
        const char *rp;
        int r;

        assert(old_path);
        assert(new_path);

        rp = skip_root(lp->root_dir, old_path);
        if (rp)
                old_path = rp;

        /* Actually create a symlink, and remember that we did. This function is
         * smart enough to check if there's already a valid symlink in place.
         *
         * Returns 1 if a symlink was created or already exists and points to the
         * right place, or negative on error.
         */

        (void) mkdir_parents_label(new_path, 0755);

        if (symlink(old_path, new_path) >= 0) {
                r = install_changes_add(changes, n_changes, INSTALL_CHANGE_SYMLINK, new_path, old_path);
                if (r < 0)
                        return r;
                return 1;
        }

        if (errno != EEXIST)
                return install_changes_add(changes, n_changes, -errno, new_path, NULL);

        r = readlink_malloc(new_path, &dest);
        if (r < 0) {
                /* translate EINVAL (non-symlink exists) to EEXIST */
                if (r == -EINVAL)
                        r = -EEXIST;

                return install_changes_add(changes, n_changes, r, new_path, NULL);
        }

        if (chroot_unit_symlinks_equivalent(lp, new_path, dest, old_path)) {
                log_debug("Symlink %s %s %s already exists",
                          new_path, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), dest);
                return 1;
        }

        if (!force)
                return install_changes_add(changes, n_changes, -EEXIST, new_path, dest);

        r = symlink_atomic(old_path, new_path);
        if (r < 0)
                return install_changes_add(changes, n_changes, r, new_path, NULL);

        r = install_changes_add(changes, n_changes, INSTALL_CHANGE_UNLINK, new_path, NULL);
        if (r < 0)
                return r;
        r = install_changes_add(changes, n_changes, INSTALL_CHANGE_SYMLINK, new_path, old_path);
        if (r < 0)
                return r;

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

        r = path_simplify_alloc(p, &n);
        if (r < 0)
                return r;

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
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_closedir_ DIR *d = NULL;
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

        FOREACH_DIRENT(de, d, return -errno)

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
                        _cleanup_free_ char *p = NULL;
                        bool found;
                        int q;

                        if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                                continue;

                        p = path_make_absolute(de->d_name, path);
                        if (!p)
                                return -ENOMEM;
                        path_simplify(p);

                        /* We remove all links pointing to a file or path that is marked, as well as all
                         * files sharing the same name as a file that is marked, and files sharing the same
                         * name after the instance has been removed. Do path chasing only if we don't already
                         * know that we want to remove the symlink. */
                        found = set_contains(remove_symlinks_to, de->d_name);

                        if (!found) {
                                _cleanup_free_ char *template = NULL;

                                q = unit_name_template(de->d_name, &template);
                                if (q < 0 && q != -EINVAL)
                                        return q;
                                if (q >= 0)
                                        found = set_contains(remove_symlinks_to, template);
                        }

                        if (!found) {
                                _cleanup_free_ char *dest = NULL;

                                q = chase(p, lp->root_dir, CHASE_NONEXISTENT, &dest, NULL);
                                if (q == -ENOENT)
                                        continue;
                                if (q < 0) {
                                        log_debug_errno(q, "Failed to resolve symlink \"%s\": %m", p);
                                        install_changes_add(changes, n_changes, q, p, NULL);

                                        if (r == 0)
                                                r = q;
                                        continue;
                                }

                                found = set_contains(remove_symlinks_to, dest) ||
                                        set_contains(remove_symlinks_to, basename(dest));

                        }


                        if (!found)
                                continue;

                        if (!dry_run) {
                                if (unlinkat(fd, de->d_name, 0) < 0 && errno != ENOENT) {
                                        if (r == 0)
                                                r = -errno;
                                        install_changes_add(changes, n_changes, -errno, p, NULL);
                                        continue;
                                }

                                (void) rmdir_parents(p, config_path);
                        }

                        q = install_changes_add(changes, n_changes, INSTALL_CHANGE_UNLINK, p, NULL);
                        if (q < 0)
                                return q;

                        /* Now, remember the full path (but with the root prefix removed) of
                         * the symlink we just removed, and remove any symlinks to it, too. */

                        const char *rp = skip_root(lp->root_dir, p);
                        q = mark_symlink_for_removal(&remove_symlinks_to, rp ?: p);
                        if (q < 0)
                                return q;
                        if (q > 0 && !dry_run)
                                *restart = true;
                }

        return r;
}

static int remove_marked_symlinks(
                Set *remove_symlinks_to,
                const char *config_path,
                const LookupPaths *lp,
                bool dry_run,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_close_ int fd = -EBADF;
        bool restart;
        int r = 0;

        assert(config_path);
        assert(lp);

        if (set_isempty(remove_symlinks_to))
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

static int is_symlink_with_known_name(const InstallInfo *i, const char *name) {
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

static int find_symlinks_in_directory(
                DIR *dir,
                const char *dir_path,
                const char *root_dir,
                const InstallInfo *info,
                bool ignore_destination,
                bool match_name,
                bool ignore_same_name,
                const char *config_path,
                bool *same_name_link) {

        int r = 0;

        FOREACH_DIRENT(de, dir, return -errno) {
                bool found_path = false, found_dest = false, b = false;
                int q;

                if (de->d_type != DT_LNK)
                        continue;

                if (!ignore_destination) {
                        _cleanup_free_ char *dest = NULL;

                        /* Acquire symlink destination */
                        q = readlinkat_malloc(dirfd(dir), de->d_name, &dest);
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

                                x = path_join(dir_path, dest);
                                if (!x)
                                        return -ENOMEM;

                                free_and_replace(dest, x);
                        }

                        /* Check if what the symlink points to matches what we are looking for */
                        found_dest = streq(basename(dest), info->name);
                }

                assert(unit_name_is_valid(info->name, UNIT_NAME_ANY));

                /* Check if the symlink itself matches what we are looking for.
                 *
                 * If ignore_destination is specified, we only look at the source name.
                 *
                 * If ignore_same_name is specified, we are in one of the directories which
                 * have lower priority than the unit file, and even if a file or symlink with
                 * this name was found, we should ignore it. */

                if (ignore_destination || !ignore_same_name)
                        found_path = streq(de->d_name, info->name);

                if (!found_path && ignore_destination) {
                        _cleanup_free_ char *template = NULL;

                        q = unit_name_template(de->d_name, &template);
                        if (q < 0 && q != -EINVAL)
                                return q;
                        if (q >= 0)
                                found_dest = streq(template, info->name);
                }

                if (found_path && found_dest) {
                        _cleanup_free_ char *p = NULL, *t = NULL;

                        /* Filter out same name links in the main config path */
                        p = path_make_absolute(de->d_name, dir_path);
                        t = path_make_absolute(info->name, config_path);

                        if (!p || !t)
                                return -ENOMEM;

                        b = path_equal(p, t);
                }

                if (b)
                        *same_name_link = true;
                else if (found_path || found_dest) {
                        if (!match_name)
                                return 1;

                        /* Check if symlink name is in the set of names used by [Install] */
                        q = is_symlink_with_known_name(info, de->d_name);
                        if (q < 0)
                                return q;
                        if (q > 0)
                                return 1;
                }
        }

        return r;
}

static int find_symlinks(
                const char *root_dir,
                const InstallInfo *i,
                bool match_name,
                bool ignore_same_name,
                const char *config_path,
                bool *same_name_link) {

        _cleanup_closedir_ DIR *config_dir = NULL;
        int r = 0;

        assert(i);
        assert(config_path);
        assert(same_name_link);

        config_dir = opendir(config_path);
        if (!config_dir) {
                if (IN_SET(errno, ENOENT, ENOTDIR, EACCES))
                        return 0;
                return -errno;
        }

        FOREACH_DIRENT(de, config_dir, return -errno) {
                const char *suffix;
                _cleanup_free_ const char *path = NULL;
                _cleanup_closedir_ DIR *d = NULL;

                if (de->d_type != DT_DIR)
                        continue;

                suffix = strrchr(de->d_name, '.');
                if (!STRPTR_IN_SET(suffix, ".wants", ".requires", ".upholds"))
                        continue;

                path = path_join(config_path, de->d_name);
                if (!path)
                        return -ENOMEM;

                d = opendir(path);
                if (!d) {
                        log_error_errno(errno, "Failed to open directory \"%s\" while scanning for symlinks, ignoring: %m", path);
                        continue;
                }

                r = find_symlinks_in_directory(d, path, root_dir, i,
                                               /* ignore_destination= */ true,
                                               /* match_name= */ match_name,
                                               /* ignore_same_name= */ ignore_same_name,
                                               config_path,
                                               same_name_link);
                if (r > 0)
                        return 1;
                else if (r < 0)
                        log_debug_errno(r, "Failed to look up symlinks in \"%s\": %m", path);
        }

        /* We didn't find any suitable symlinks in .wants, .requires or .upholds directories,
         * let's look for linked unit files in this directory. */
        rewinddir(config_dir);
        return find_symlinks_in_directory(config_dir, config_path, root_dir, i,
                                          /* ignore_destination= */ false,
                                          /* match_name= */ match_name,
                                          /* ignore_same_name= */ ignore_same_name,
                                          config_path,
                                          same_name_link);
}

static int find_symlinks_in_scope(
                RuntimeScope scope,
                const LookupPaths *lp,
                const InstallInfo *info,
                bool match_name,
                UnitFileState *state) {

        bool same_name_link_runtime = false, same_name_link_config = false;
        bool enabled_in_runtime = false, enabled_at_all = false;
        bool ignore_same_name = false;
        int r;

        assert(lp);
        assert(info);

        /* As we iterate over the list of search paths in lp->search_path, we may encounter "same name"
         * symlinks. The ones which are "below" (i.e. have lower priority) than the unit file itself are
         * effectively masked, so we should ignore them. */

        STRV_FOREACH(p, lp->search_path)  {
                bool same_name_link = false;

                r = find_symlinks(lp->root_dir, info, match_name, ignore_same_name, *p, &same_name_link);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* We found symlinks in this dir? Yay! Let's see where precisely it is enabled. */

                        if (path_equal_ptr(*p, lp->persistent_config)) {
                                /* This is the best outcome, let's return it immediately. */
                                *state = UNIT_FILE_ENABLED;
                                return 1;
                        }

                        /* look for global enablement of user units */
                        if (scope == RUNTIME_SCOPE_USER && path_is_user_config_dir(*p)) {
                                *state = UNIT_FILE_ENABLED;
                                return 1;
                        }

                        r = path_is_runtime(lp, *p, false);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                enabled_in_runtime = true;
                        else
                                enabled_at_all = true;

                } else if (same_name_link) {
                        if (path_equal_ptr(*p, lp->persistent_config))
                                same_name_link_config = true;
                        else {
                                r = path_is_runtime(lp, *p, false);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        same_name_link_runtime = true;
                        }
                }

                /* Check if next iteration will be "below" the unit file (either a regular file
                 * or a symlink), and hence should be ignored */
                if (!ignore_same_name && path_startswith(info->path, *p))
                        ignore_same_name = true;
        }

        if (enabled_in_runtime) {
                *state = UNIT_FILE_ENABLED_RUNTIME;
                return 1;
        }

        /* Here's a special rule: if the unit we are looking for is an instance, and it symlinked in the search path
         * outside of runtime and configuration directory, then we consider it statically enabled. Note we do that only
         * for instance, not for regular names, as those are merely aliases, while instances explicitly instantiate
         * something, and hence are a much stronger concept. */
        if (enabled_at_all && unit_name_is_valid(info->name, UNIT_NAME_INSTANCE)) {
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

static void install_info_clear(InstallInfo *i) {
        if (!i)
                return;

        i->name = mfree(i->name);
        i->path = mfree(i->path);
        i->root = mfree(i->root);
        i->aliases = strv_free(i->aliases);
        i->wanted_by = strv_free(i->wanted_by);
        i->required_by = strv_free(i->required_by);
        i->upheld_by = strv_free(i->upheld_by);
        i->also = strv_free(i->also);
        i->default_instance = mfree(i->default_instance);
        i->symlink_target = mfree(i->symlink_target);
}

static InstallInfo* install_info_free(InstallInfo *i) {
        install_info_clear(i);
        return mfree(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(InstallInfo*, install_info_free);

static void install_context_done(InstallContext *ctx) {
        assert(ctx);

        ctx->will_process = ordered_hashmap_free_with_destructor(ctx->will_process, install_info_free);
        ctx->have_processed = ordered_hashmap_free_with_destructor(ctx->have_processed, install_info_free);
}

static InstallInfo *install_info_find(InstallContext *ctx, const char *name) {
        InstallInfo *i;

        i = ordered_hashmap_get(ctx->have_processed, name);
        if (i)
                return i;

        return ordered_hashmap_get(ctx->will_process, name);
}

static int install_info_may_process(
                const InstallInfo *i,
                const LookupPaths *lp,
                InstallChange **changes,
                size_t *n_changes) {
        assert(i);
        assert(lp);

        /* Checks whether the loaded unit file is one we should process, or is masked,
         * transient or generated and thus not subject to enable/disable operations. */

        if (i->install_mode == INSTALL_MODE_MASKED)
                return install_changes_add(changes, n_changes, -ERFKILL, i->path, NULL);
        if (path_is_generator(lp, i->path) ||
            path_is_transient(lp, i->path))
                return install_changes_add(changes, n_changes, -EADDRNOTAVAIL, i->path, NULL);

        return 0;
}

/**
 * Adds a new InstallInfo entry under name in the InstallContext.will_process
 * hashmap, or retrieves the existing one if already present.
 *
 * Returns negative on error, 0 if the unit was already known, 1 otherwise.
 */
static int install_info_add(
                InstallContext *ctx,
                const char *name,
                const char *path,
                const char *root,
                bool auxiliary,
                InstallInfo **ret) {

        int r;

        assert(ctx);

        if (!name) {
                /* 'name' and 'path' must not both be null. Check here 'path' using assert_se() to
                 * workaround a bug in gcc that generates a -Wnonnull warning when calling basename(),
                 * but this cannot be possible in any code path (See #6119). */
                assert_se(path);
                name = basename(path);
        }

        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        InstallInfo *i = install_info_find(ctx, name);
        if (i) {
                i->auxiliary = i->auxiliary && auxiliary;

                if (ret)
                        *ret = i;
                return 0;
        }

        _cleanup_(install_info_freep) InstallInfo *alloc = new(InstallInfo, 1);
        if (!alloc)
                return -ENOMEM;

        *alloc = (InstallInfo) {
                .install_mode = _INSTALL_MODE_INVALID,
                .auxiliary = auxiliary,
        };

        alloc->name = strdup(name);
        if (!alloc->name)
                return -ENOMEM;

        if (root) {
                alloc->root = strdup(root);
                if (!alloc->root)
                        return -ENOMEM;
        }

        if (path) {
                alloc->path = strdup(path);
                if (!alloc->path)
                        return -ENOMEM;
        }

        r = ordered_hashmap_ensure_put(&ctx->will_process, &string_hash_ops, alloc->name, alloc);
        if (r < 0)
                return r;
        i = TAKE_PTR(alloc);

        if (ret)
                *ret = i;
        return 1;
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

        InstallInfo *info = ASSERT_PTR(userdata);
        InstallContext *ctx = ASSERT_PTR(data);
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

                r = install_name_printf(ctx->scope, info, word, &printed);
                if (r < 0)
                        return log_syntax(unit, LOG_WARNING, filename, line, r,
                                          "Failed to resolve unit name in Also=\"%s\": %m", word);

                r = install_info_add(ctx, printed, NULL, info->root, /* auxiliary= */ true, NULL);
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

        InstallContext *ctx = ASSERT_PTR(data);
        InstallInfo *info = ASSERT_PTR(userdata);
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

        r = install_name_printf(ctx->scope, info, rvalue, &printed);
        if (r < 0)
                return log_syntax(unit, LOG_WARNING, filename, line, r,
                                  "Failed to resolve instance name in DefaultInstance=\"%s\": %m", rvalue);

        if (isempty(printed))
                printed = mfree(printed);

        if (printed && !unit_instance_is_valid(printed))
                return log_syntax(unit, LOG_WARNING, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                  "Invalid DefaultInstance= value \"%s\".", printed);

        return free_and_replace(info->default_instance, printed);
}

static int unit_file_load(
                InstallContext *ctx,
                InstallInfo *info,
                const char *path,
                const char *root_dir,
                SearchFlags flags) {

        const ConfigTableItem items[] = {
                { "Install", "Alias",           config_parse_alias,            0, &info->aliases           },
                { "Install", "WantedBy",        config_parse_strv,             0, &info->wanted_by         },
                { "Install", "RequiredBy",      config_parse_strv,             0, &info->required_by       },
                { "Install", "UpheldBy",        config_parse_strv,             0, &info->upheld_by         },
                { "Install", "DefaultInstance", config_parse_default_instance, 0, info                     },
                { "Install", "Also",            config_parse_also,             0, ctx                      },
                {}
        };

        UnitType type;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        int r;

        assert(info);
        assert(path);

        if (!(flags & SEARCH_DROPIN)) {
                /* Loading or checking for the main unit file… */

                type = unit_name_to_type(info->name);
                if (type < 0)
                        return -EINVAL;
                if (unit_name_is_valid(info->name, UNIT_NAME_TEMPLATE|UNIT_NAME_INSTANCE) && !unit_type_may_template(type))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "%s: unit type %s cannot be templated, ignoring.", path, unit_type_to_string(type));

                if (!(flags & SEARCH_LOAD)) {
                        if (lstat(path, &st) < 0)
                                return -errno;

                        if (null_or_empty(&st))
                                info->install_mode = INSTALL_MODE_MASKED;
                        else if (S_ISREG(st.st_mode))
                                info->install_mode = INSTALL_MODE_REGULAR;
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

                fd = chase_and_open(path, root_dir, 0, O_RDONLY|O_CLOEXEC|O_NOCTTY, NULL);
                if (fd < 0)
                        return fd;
        }

        if (fstat(fd, &st) < 0)
                return -errno;

        if (null_or_empty(&st)) {
                if ((flags & SEARCH_DROPIN) == 0)
                        info->install_mode = INSTALL_MODE_MASKED;

                return 0;
        }

        r = stat_verify_regular(&st);
        if (r < 0)
                return r;

        f = take_fdopen(&fd, "r");
        if (!f)
                return -errno;

        /* ctx is only needed if we actually load the file (it's referenced from items[] btw, in case you wonder.) */
        assert(ctx);

        r = config_parse(info->name, path, f,
                         "Install\0"
                         "-Unit\0"
                         "-Automount\0"
                         "-Device\0"
                         "-Mount\0"
                         "-Path\0"
                         "-Scope\0"
                         "-Service\0"
                         "-Slice\0"
                         "-Socket\0"
                         "-Swap\0"
                         "-Target\0"
                         "-Timer\0",
                         config_item_table_lookup, items,
                         0, info,
                         NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse \"%s\": %m", info->name);

        if ((flags & SEARCH_DROPIN) == 0)
                info->install_mode = INSTALL_MODE_REGULAR;

        return
                (int) strv_length(info->aliases) +
                (int) strv_length(info->wanted_by) +
                (int) strv_length(info->required_by) +
                (int) strv_length(info->upheld_by);
}

static int unit_file_load_or_readlink(
                InstallContext *ctx,
                InstallInfo *info,
                const char *path,
                const LookupPaths *lp,
                SearchFlags flags) {
        int r;

        r = unit_file_load(ctx, info, path, lp->root_dir, flags);
        if (r != -ELOOP || (flags & SEARCH_DROPIN))
                return r;

        /* This is a symlink, let's read and verify it. */
        r = unit_file_resolve_symlink(lp->root_dir, lp->search_path,
                                      NULL, AT_FDCWD, path,
                                      true, &info->symlink_target);
        if (r < 0)
                return r;
        bool outside_search_path = r > 0;

        r = null_or_empty_path_with_root(info->symlink_target, lp->root_dir);
        if (r < 0 && r != -ENOENT)
                return log_debug_errno(r, "Failed to stat %s: %m", info->symlink_target);
        if (r > 0)
                info->install_mode = INSTALL_MODE_MASKED;
        else if (outside_search_path)
                info->install_mode = INSTALL_MODE_LINKED;
        else
                info->install_mode = INSTALL_MODE_ALIAS;

        return 0;
}

static int unit_file_search(
                InstallContext *ctx,
                InstallInfo *info,
                const LookupPaths *lp,
                SearchFlags flags) {

        const char *dropin_dir_name = NULL, *dropin_template_dir_name = NULL;
        _cleanup_strv_free_ char **dirs = NULL, **files = NULL;
        _cleanup_free_ char *template = NULL;
        bool found_unit = false;
        int r, result;

        assert(info);
        assert(lp);

        /* Was this unit already loaded? */
        if (info->install_mode != _INSTALL_MODE_INVALID)
                return 0;

        if (info->path)
                return unit_file_load_or_readlink(ctx, info, info->path, lp, flags);

        assert(info->name);

        if (unit_name_is_valid(info->name, UNIT_NAME_INSTANCE)) {
                r = unit_name_template(info->name, &template);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(p, lp->search_path) {
                _cleanup_free_ char *path = NULL;

                path = path_join(*p, info->name);
                if (!path)
                        return -ENOMEM;

                r = unit_file_load_or_readlink(ctx, info, path, lp, flags);
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

                STRV_FOREACH(p, lp->search_path) {
                        _cleanup_free_ char *path = NULL;

                        path = path_join(*p, template);
                        if (!path)
                                return -ENOMEM;

                        r = unit_file_load_or_readlink(ctx, info, path, lp, flags);
                        if (r >= 0) {
                                info->path = TAKE_PTR(path);
                                result = r;
                                found_unit = true;
                                break;
                        } else if (!IN_SET(r, -ENOENT, -ENOTDIR, -EACCES))
                                return r;
                }
        }

        if (!found_unit)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Cannot find unit %s%s%s.",
                                       info->name, template ? " or " : "", strempty(template));

        if (info->install_mode == INSTALL_MODE_MASKED)
                return result;

        /* Search for drop-in directories */

        dropin_dir_name = strjoina(info->name, ".d");
        STRV_FOREACH(p, lp->search_path) {
                char *path;

                path = path_join(*p, dropin_dir_name);
                if (!path)
                        return -ENOMEM;

                r = strv_consume(&dirs, path);
                if (r < 0)
                        return r;
        }

        if (template) {
                dropin_template_dir_name = strjoina(template, ".d");
                STRV_FOREACH(p, lp->search_path) {
                        char *path;

                        path = path_join(*p, dropin_template_dir_name);
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
                r = unit_file_load_or_readlink(ctx, info, *p, lp, flags | SEARCH_DROPIN);
                if (r < 0)
                        return log_debug_errno(r, "Failed to load conf file \"%s\": %m", *p);
        }

        return result;
}

static int install_info_follow(
                InstallContext *ctx,
                InstallInfo *info,
                const LookupPaths *lp,
                SearchFlags flags,
                bool ignore_different_name) {

        assert(ctx);
        assert(info);

        if (!IN_SET(info->install_mode, INSTALL_MODE_ALIAS, INSTALL_MODE_LINKED))
                return -EINVAL;
        if (!info->symlink_target)
                return -EINVAL;

        /* If the basename doesn't match, the caller should add a complete new entry for this. */

        if (!ignore_different_name && !streq(basename(info->symlink_target), info->name))
                return -EXDEV;

        free_and_replace(info->path, info->symlink_target);
        info->install_mode = _INSTALL_MODE_INVALID;

        return unit_file_load_or_readlink(ctx, info, info->path, lp, flags);
}

/**
 * Search for the unit file. If the unit name is a symlink, follow the symlink to the
 * target, maybe more than once. Propagate the instance name if present.
 */
static int install_info_traverse(
                InstallContext *ctx,
                const LookupPaths *lp,
                InstallInfo *start,
                SearchFlags flags,
                InstallInfo **ret) {

        InstallInfo *i;
        unsigned k = 0;
        int r;

        assert(lp);
        assert(start);
        assert(ctx);

        r = unit_file_search(ctx, start, lp, flags);
        if (r < 0)
                return r;

        i = start;
        while (IN_SET(i->install_mode, INSTALL_MODE_ALIAS, INSTALL_MODE_LINKED)) {
                /* Follow the symlink */

                if (++k > UNIT_FILE_FOLLOW_SYMLINK_MAX)
                        return -ELOOP;

                if (!(flags & SEARCH_FOLLOW_CONFIG_SYMLINKS)) {
                        r = path_is_config(lp, i->path, true);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                return -ELOOP;
                }

                r = install_info_follow(ctx, i, lp, flags,
                                        /* If linked, don't look at the target name */
                                        /* ignore_different_name= */ i->install_mode == INSTALL_MODE_LINKED);
                if (r == -EXDEV && i->symlink_target) {
                        _cleanup_free_ char *buffer = NULL;
                        const char *bn;

                        /* Target is an alias, create a new install info object and continue with that. */

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

                                        /* We filled in the instance, and the target stayed the same? If so,
                                         * then let's honour the link as it is. */

                                        r = install_info_follow(ctx, i, lp, flags, true);
                                        if (r < 0)
                                                return r;

                                        continue;
                                }

                                bn = buffer;
                        }

                        r = install_info_add(ctx, bn, NULL, lp->root_dir, /* auxiliary= */ false, &i);
                        if (r < 0)
                                return r;

                        /* Try again, with the new target we found. */
                        r = unit_file_search(ctx, i, lp, flags);
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
                InstallContext *ctx,
                const LookupPaths *lp,
                const char *name_or_path,
                InstallInfo **ret) {

        assert(ctx);
        assert(name_or_path);

        if (path_is_absolute(name_or_path)) {
                const char *pp;

                pp = prefix_roota(lp->root_dir, name_or_path);

                return install_info_add(ctx, NULL, pp, lp->root_dir, /* auxiliary= */ false, ret);
        } else
                return install_info_add(ctx, name_or_path, NULL, lp->root_dir, /* auxiliary= */ false, ret);
}

static int install_info_discover(
                InstallContext *ctx,
                const LookupPaths *lp,
                const char *name_or_path,
                SearchFlags flags,
                InstallInfo **ret,
                InstallChange **changes,
                size_t *n_changes) {

        InstallInfo *info;
        int r;

        assert(ctx);
        assert(lp);
        assert(name_or_path);

        r = install_info_add_auto(ctx, lp, name_or_path, &info);
        if (r >= 0)
                r = install_info_traverse(ctx, lp, info, flags, ret);

        if (r < 0)
                install_changes_add(changes, n_changes, r, name_or_path, NULL);
        return r;
}

static int install_info_discover_and_check(
                InstallContext *ctx,
                const LookupPaths *lp,
                const char *name_or_path,
                SearchFlags flags,
                InstallInfo **ret,
                InstallChange **changes,
                size_t *n_changes) {

        int r;

        r = install_info_discover(ctx, lp, name_or_path, flags, ret, changes, n_changes);
        if (r < 0)
                return r;

        return install_info_may_process(ret ? *ret : NULL, lp, changes, n_changes);
}

int unit_file_verify_alias(
                const InstallInfo *info,
                const char *dst,
                char **ret_dst,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_free_ char *dst_updated = NULL;
        int r;

        /* Verify that dst is a valid either a valid alias or a valid .wants/.requires symlink for the target
         * unit *i. Return negative on error or if not compatible, zero on success.
         *
         * ret_dst is set in cases where "instance propagation" happens, i.e. when the instance part is
         * inserted into dst. It is not normally set, even on success, so that the caller can easily
         * distinguish the case where instance propagation occurred.
         *
         * Returns:
         * -EXDEV when the alias doesn't match the unit,
         * -EUCLEAN when the name is invalid,
         * -ELOOP when the alias it to the unit itself.
         */

        const char *path_alias = strrchr(dst, '/');
        if (path_alias) {
                /* This branch covers legacy Alias= function of creating .wants and .requires symlinks. */
                _cleanup_free_ char *dir = NULL;
                char *p;

                path_alias ++; /* skip over slash */

                r = path_extract_directory(dst, &dir);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract parent directory from '%s': %m", dst);

                p = endswith(dir, ".wants");
                if (!p)
                        p = endswith(dir, ".requires");
                if (!p) {
                        install_changes_add(changes, n_changes, -EXDEV, dst, NULL);
                        return log_debug_errno(SYNTHETIC_ERRNO(EXDEV), "Invalid path \"%s\" in alias.", dir);
                }

                *p = '\0'; /* dir should now be a unit name */

                UnitNameFlags type = unit_name_classify(dir);
                if (type < 0) {
                        install_changes_add(changes, n_changes, -EXDEV, dst, NULL);
                        return log_debug_errno(SYNTHETIC_ERRNO(EXDEV),
                                               "Invalid unit name component \"%s\" in alias.", dir);
                }

                const bool instance_propagation = type == UNIT_NAME_TEMPLATE;

                /* That's the name we want to use for verification. */
                r = unit_symlink_name_compatible(path_alias, info->name, instance_propagation);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify alias validity: %m");
                if (r == 0) {
                        install_changes_add(changes, n_changes, -EXDEV, dst, info->name);
                        return log_debug_errno(SYNTHETIC_ERRNO(EXDEV),
                                               "Invalid unit \"%s\" symlink \"%s\".",
                                               info->name, dst);
                }

        } else {
                /* If the symlink target has an instance set and the symlink source doesn't, we "propagate
                 * the instance", i.e. instantiate the symlink source with the target instance. */
                if (unit_name_is_valid(dst, UNIT_NAME_TEMPLATE)) {
                        _cleanup_free_ char *inst = NULL;

                        UnitNameFlags type = unit_name_to_instance(info->name, &inst);
                        if (type < 0) {
                                install_changes_add(changes, n_changes, -EUCLEAN, info->name, NULL);
                                return log_debug_errno(type, "Failed to extract instance name from \"%s\": %m", info->name);
                        }

                        if (type == UNIT_NAME_INSTANCE) {
                                r = unit_name_replace_instance(dst, inst, &dst_updated);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to build unit name from %s+%s: %m",
                                                               dst, inst);
                        }
                }

                r = unit_validate_alias_symlink_or_warn(LOG_DEBUG, dst_updated ?: dst, info->name);
                if (r == -ELOOP)  /* -ELOOP means self-alias, which we (quietly) ignore */
                        return r;
                if (r < 0)
                        return install_changes_add(changes, n_changes,
                                                   r == -EINVAL ? -EXDEV : r,
                                                   dst_updated ?: dst,
                                                   info->name);
        }

        *ret_dst = TAKE_PTR(dst_updated);
        return 0;
}

static int install_info_symlink_alias(
                RuntimeScope scope,
                InstallInfo *info,
                const LookupPaths *lp,
                const char *config_path,
                bool force,
                InstallChange **changes,
                size_t *n_changes) {

        int r = 0, q;

        assert(info);
        assert(lp);
        assert(config_path);

        STRV_FOREACH(s, info->aliases) {
                _cleanup_free_ char *alias_path = NULL, *dst = NULL, *dst_updated = NULL;
                bool broken;

                q = install_name_printf(scope, info, *s, &dst);
                if (q < 0) {
                        install_changes_add(changes, n_changes, q, *s, NULL);
                        r = r < 0 ? r : q;
                        continue;
                }

                q = unit_file_verify_alias(info, dst, &dst_updated, changes, n_changes);
                if (q == -ELOOP)
                        continue;
                if (q < 0) {
                        r = r < 0 ? r : q;
                        continue;
                }

                alias_path = path_make_absolute(dst_updated ?: dst, config_path);
                if (!alias_path)
                        return -ENOMEM;

                q = chase(alias_path, lp->root_dir, CHASE_NONEXISTENT, NULL, NULL);
                if (q < 0 && q != -ENOENT) {
                        r = r < 0 ? r : q;
                        continue;
                }
                broken = q == 0; /* symlink target does not exist? */

                q = create_symlink(lp, info->path, alias_path, force || broken, changes, n_changes);
                r = r < 0 ? r : q;
        }

        return r;
}

static int install_info_symlink_wants(
                RuntimeScope scope,
                UnitFileFlags file_flags,
                InstallInfo *info,
                const LookupPaths *lp,
                const char *config_path,
                char **list,
                const char *suffix,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(install_info_clear) InstallInfo instance = {
                .install_mode = _INSTALL_MODE_INVALID,
        };

        UnitNameFlags valid_dst_type = UNIT_NAME_ANY;
        const char *n;
        int r = 0, q;

        assert(info);
        assert(lp);
        assert(config_path);

        if (strv_isempty(list))
                return 0;

        if (unit_name_is_valid(info->name, UNIT_NAME_PLAIN | UNIT_NAME_INSTANCE))
                /* Not a template unit. Use the name directly. */
                n = info->name;

        else if (info->default_instance) {
                /* If this is a template, and we have a default instance, use it. */

                r = unit_name_replace_instance(info->name, info->default_instance, &instance.name);
                if (r < 0)
                        return r;

                r = unit_file_search(NULL, &instance, lp, SEARCH_FOLLOW_CONFIG_SYMLINKS);
                if (r < 0)
                        return r;

                if (instance.install_mode == INSTALL_MODE_MASKED)
                        return install_changes_add(changes, n_changes, -ERFKILL, instance.path, NULL);

                n = instance.name;

        } else {
                /* We have a template, but no instance yet. When used with an instantiated unit, we will get
                 * the instance from that unit. Cannot be used with non-instance units. */

                valid_dst_type = UNIT_NAME_INSTANCE | UNIT_NAME_TEMPLATE;
                n = info->name;
        }

        r = 0;
        STRV_FOREACH(s, list) {
                _cleanup_free_ char *path = NULL, *dst = NULL;

                q = install_name_printf(scope, info, *s, &dst);
                if (q < 0) {
                        install_changes_add(changes, n_changes, q, *s, NULL);
                        if (r >= 0)
                                r = q;

                        continue;
                }

                if (!unit_name_is_valid(dst, valid_dst_type)) {
                        /* Generate a proper error here: EUCLEAN if the name is generally bad, EIDRM if the
                         * template status doesn't match. If we are doing presets don't bother reporting the
                         * error. This also covers cases like 'systemctl preset serial-getty@.service', which
                         * has no DefaultInstance, so there is nothing we can do. At the same time,
                         * 'systemctl enable serial-getty@.service' should fail, the user should specify an
                         * instance like in 'systemctl enable serial-getty@ttyS0.service'.
                         */
                        if (file_flags & UNIT_FILE_IGNORE_AUXILIARY_FAILURE)
                                continue;

                        if (unit_name_is_valid(dst, UNIT_NAME_ANY))
                                q = install_changes_add(changes, n_changes, -EIDRM, dst, n);
                        else
                                q = install_changes_add(changes, n_changes, -EUCLEAN, dst, NULL);
                        if (r >= 0)
                                r = q;

                        continue;
                }

                path = strjoin(config_path, "/", dst, suffix, n);
                if (!path)
                        return -ENOMEM;

                q = create_symlink(lp, info->path, path, true, changes, n_changes);
                if ((q < 0 && r >= 0) || r == 0)
                        r = q;

                if (unit_file_exists(scope, lp, dst) == 0) {
                        q = install_changes_add(changes, n_changes, INSTALL_CHANGE_DESTINATION_NOT_PRESENT, dst, info->path);
                        if (q < 0)
                                return q;
                }
        }

        return r;
}

static int install_info_symlink_link(
                InstallInfo *info,
                const LookupPaths *lp,
                const char *config_path,
                bool force,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_free_ char *path = NULL;
        int r;

        assert(info);
        assert(lp);
        assert(config_path);
        assert(info->path);

        r = in_search_path(lp, info->path);
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        path = path_join(config_path, info->name);
        if (!path)
                return -ENOMEM;

        return create_symlink(lp, info->path, path, force, changes, n_changes);
}

static int install_info_apply(
                RuntimeScope scope,
                UnitFileFlags file_flags,
                InstallInfo *info,
                const LookupPaths *lp,
                const char *config_path,
                InstallChange **changes,
                size_t *n_changes) {

        int r, q;

        assert(info);
        assert(lp);
        assert(config_path);

        if (info->install_mode != INSTALL_MODE_REGULAR)
                return 0;

        bool force = file_flags & UNIT_FILE_FORCE;

        r = install_info_symlink_link(info, lp, config_path, force, changes, n_changes);
        /* Do not count links to the unit file towards the "carries_install_info" count */
        if (r < 0)
                /* If linking of the file failed, do not try to create other symlinks,
                 * because they might would pointing to a non-existent or wrong unit. */
                return r;

        r = install_info_symlink_alias(scope, info, lp, config_path, force, changes, n_changes);

        q = install_info_symlink_wants(scope, file_flags, info, lp, config_path, info->wanted_by, ".wants/", changes, n_changes);
        if (r == 0)
                r = q;

        q = install_info_symlink_wants(scope, file_flags, info, lp, config_path, info->required_by, ".requires/", changes, n_changes);
        if (r == 0)
                r = q;

        q = install_info_symlink_wants(scope, file_flags, info, lp, config_path, info->upheld_by, ".upholds/", changes, n_changes);
        if (r == 0)
                r = q;

        return r;
}

static int install_context_apply(
                InstallContext *ctx,
                const LookupPaths *lp,
                UnitFileFlags file_flags,
                const char *config_path,
                SearchFlags flags,
                InstallChange **changes,
                size_t *n_changes) {

        InstallInfo *i;
        int r;

        assert(ctx);
        assert(lp);
        assert(config_path);

        if (ordered_hashmap_isempty(ctx->will_process))
                return 0;

        r = ordered_hashmap_ensure_allocated(&ctx->have_processed, &string_hash_ops);
        if (r < 0)
                return r;

        r = 0;
        while ((i = ordered_hashmap_first(ctx->will_process))) {
                int q;

                q = ordered_hashmap_move_one(ctx->have_processed, ctx->will_process, i->name);
                if (q < 0)
                        return q;

                q = install_info_traverse(ctx, lp, i, flags, NULL);
                if (q < 0) {
                        if (i->auxiliary) {
                                q = install_changes_add(changes, n_changes, INSTALL_CHANGE_AUXILIARY_FAILED, i->name, NULL);
                                if (q < 0)
                                        return q;
                                continue;
                        }

                        return install_changes_add(changes, n_changes, q, i->name, NULL);
                }

                /* We can attempt to process a masked unit when a different unit
                 * that we were processing specifies it in Also=. */
                if (i->install_mode == INSTALL_MODE_MASKED) {
                        q = install_changes_add(changes, n_changes, INSTALL_CHANGE_IS_MASKED, i->path, NULL);
                        if (q < 0)
                                return q;
                        if (r >= 0)
                                /* Assume that something *could* have been enabled here,
                                 * avoid "empty [Install] section" warning. */
                                r += 1;
                        continue;
                }

                if (i->install_mode != INSTALL_MODE_REGULAR)
                        continue;

                q = install_info_apply(ctx->scope, file_flags, i, lp, config_path, changes, n_changes);
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
                InstallContext *ctx,
                const LookupPaths *lp,
                Set **remove_symlinks_to,
                const char *config_path,
                InstallChange **changes,
                size_t *n_changes) {

        InstallInfo *i;
        int r;

        assert(ctx);
        assert(lp);
        assert(config_path);

        /* Marks all items for removal */

        if (ordered_hashmap_isempty(ctx->will_process))
                return 0;

        r = ordered_hashmap_ensure_allocated(&ctx->have_processed, &string_hash_ops);
        if (r < 0)
                return r;

        while ((i = ordered_hashmap_first(ctx->will_process))) {

                r = ordered_hashmap_move_one(ctx->have_processed, ctx->will_process, i->name);
                if (r < 0)
                        return r;

                r = install_info_traverse(ctx, lp, i, SEARCH_LOAD|SEARCH_FOLLOW_CONFIG_SYMLINKS, NULL);
                if (r == -ENOLINK) {
                        log_debug_errno(r, "Name %s leads to a dangling symlink, removing name.", i->name);
                        r = install_changes_add(changes, n_changes, INSTALL_CHANGE_IS_DANGLING, i->path ?: i->name, NULL);
                        if (r < 0)
                                return r;
                } else if (r == -ENOENT) {
                        if (i->auxiliary)  /* some unit specified in Also= or similar is missing */
                                log_debug_errno(r, "Auxiliary unit of %s not found, removing name.", i->name);
                        else {
                                log_debug_errno(r, "Unit %s not found, removing name.", i->name);
                                r = install_changes_add(changes, n_changes, r, i->path ?: i->name, NULL);
                                if (r < 0)
                                        return r;
                        }
                } else if (r < 0) {
                        log_debug_errno(r, "Failed to find unit %s, removing name: %m", i->name);
                        install_changes_add(changes, n_changes, r, i->path ?: i->name, NULL);
                } else if (i->install_mode == INSTALL_MODE_MASKED) {
                        log_debug("Unit file %s is masked, ignoring.", i->name);
                        install_changes_add(changes, n_changes, INSTALL_CHANGE_IS_MASKED, i->path ?: i->name, NULL);
                        continue;
                } else if (i->install_mode != INSTALL_MODE_REGULAR) {
                        log_debug("Unit %s has install mode %s, ignoring.",
                                  i->name, install_mode_to_string(i->install_mode) ?: "invalid");
                        continue;
                }

                r = mark_symlink_for_removal(remove_symlinks_to, i->name);
                if (r < 0)
                        return r;
        }

        return 0;
}

int unit_file_mask(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **names,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        const char *config_path;
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        config_path = (flags & UNIT_FILE_RUNTIME) ? lp.runtime_config : lp.persistent_config;
        if (!config_path)
                return -ENXIO;

        r = 0;

        STRV_FOREACH(name, names) {
                _cleanup_free_ char *path = NULL;

                if (!unit_name_is_valid(*name, UNIT_NAME_ANY)) {
                        RET_GATHER(r, -EINVAL);
                        continue;
                }

                path = path_make_absolute(*name, config_path);
                if (!path)
                        return -ENOMEM;

                RET_GATHER(r, create_symlink(&lp, "/dev/null", path, flags & UNIT_FILE_FORCE, changes, n_changes));
        }

        return r;
}

int unit_file_unmask(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **names,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_set_free_free_ Set *remove_symlinks_to = NULL;
        _cleanup_strv_free_ char **todo = NULL;
        const char *config_path;
        size_t n_todo = 0;
        int r, q;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        config_path = (flags & UNIT_FILE_RUNTIME) ? lp.runtime_config : lp.persistent_config;
        if (!config_path)
                return -ENXIO;

        bool dry_run = flags & UNIT_FILE_DRY_RUN;

        STRV_FOREACH(name, names) {
                if (!unit_name_is_valid(*name, UNIT_NAME_ANY))
                        return -EINVAL;

                /* If root_dir is set, we don't care about kernel command line or generators.
                 * But if it is not set, we need to check for interference. */
                if (!root_dir) {
                        _cleanup_(install_info_clear) InstallInfo info = {
                                .name = *name,  /* We borrow *name temporarily… */
                                .install_mode = _INSTALL_MODE_INVALID,
                        };

                        r = unit_file_search(NULL, &info, &lp, 0);
                        if (r < 0) {
                                if (r != -ENOENT)
                                        log_debug_errno(r, "Failed to look up unit %s, ignoring: %m", info.name);
                        } else if (info.install_mode == INSTALL_MODE_MASKED &&
                                   path_is_generator(&lp, info.path)) {
                                r = install_changes_add(changes, n_changes,
                                                        INSTALL_CHANGE_IS_MASKED_GENERATOR, info.name, info.path);
                                if (r < 0)
                                        return r;
                        }

                        TAKE_PTR(info.name);  /* … and give it back here */
                }

                _cleanup_free_ char *path = path_make_absolute(*name, config_path);
                if (!path)
                        return -ENOMEM;

                r = null_or_empty_path(path);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (!GREEDY_REALLOC0(todo, n_todo + 2))
                        return -ENOMEM;

                todo[n_todo] = strdup(*name);
                if (!todo[n_todo])
                        return -ENOMEM;

                n_todo++;
        }

        strv_uniq(todo);

        r = 0;
        STRV_FOREACH(i, todo) {
                _cleanup_free_ char *path = NULL;
                const char *rp;

                path = path_make_absolute(*i, config_path);
                if (!path)
                        return -ENOMEM;

                if (!dry_run && unlink(path) < 0) {
                        if (errno != ENOENT) {
                                RET_GATHER(r, -errno);
                                install_changes_add(changes, n_changes, -errno, path, NULL);
                        }

                        continue;
                }

                q = install_changes_add(changes, n_changes, INSTALL_CHANGE_UNLINK, path, NULL);
                if (q < 0)
                        return q;

                rp = skip_root(lp.root_dir, path);
                q = mark_symlink_for_removal(&remove_symlinks_to, rp ?: path);
                if (q < 0)
                        return q;
        }

        RET_GATHER(r, remove_marked_symlinks(remove_symlinks_to, config_path, &lp, dry_run, changes, n_changes));

        return r;
}

int unit_file_link(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_strv_free_ char **todo = NULL;
        const char *config_path;
        size_t n_todo = 0;
        int r, q;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        config_path = (flags & UNIT_FILE_RUNTIME) ? lp.runtime_config : lp.persistent_config;
        if (!config_path)
                return -ENXIO;

        STRV_FOREACH(file, files) {
                _cleanup_free_ char *full = NULL;
                struct stat st;
                char *fn;

                if (!path_is_absolute(*file))
                        return install_changes_add(changes, n_changes, -EINVAL, *file, NULL);

                fn = basename(*file);
                if (!unit_name_is_valid(fn, UNIT_NAME_ANY))
                        return install_changes_add(changes, n_changes, -EUCLEAN, *file, NULL);

                full = path_join(lp.root_dir, *file);
                if (!full)
                        return -ENOMEM;

                if (lstat(full, &st) < 0)
                        return install_changes_add(changes, n_changes, -errno, *file, NULL);

                r = stat_verify_regular(&st);
                if (r < 0)
                        return install_changes_add(changes, n_changes, r, *file, NULL);

                r = in_search_path(&lp, *file);
                if (r < 0)
                        return install_changes_add(changes, n_changes, r, *file, NULL);
                if (r > 0)
                        /* A silent noop if the file is already in the search path. */
                        continue;

                r = underneath_search_path(&lp, *file);
                if (r > 0)
                        r = -ETXTBSY;
                if (r < 0)
                        return install_changes_add(changes, n_changes, r, *file, NULL);

                if (!GREEDY_REALLOC0(todo, n_todo + 2))
                        return -ENOMEM;

                todo[n_todo] = strdup(*file);
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

                q = create_symlink(&lp, *i, new_path, flags & UNIT_FILE_FORCE, changes, n_changes);
                if (q < 0 && r >= 0)
                        r = q;
        }

        return r;
}

static int path_shall_revert(const LookupPaths *lp, const char *path) {
        int r;

        assert(lp);
        assert(path);

        /* Checks whether the path is one where the drop-in directories shall be removed. */

        r = path_is_config(lp, path, true);
        if (r != 0)
                return r;

        r = path_is_control(lp, path);
        if (r != 0)
                return r;

        return path_is_transient(lp, path);
}

int unit_file_revert(
                RuntimeScope scope,
                const char *root_dir,
                char **names,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_set_free_free_ Set *remove_symlinks_to = NULL;
        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_strv_free_ char **todo = NULL;
        size_t n_todo = 0;
        int r, q;

        /* Puts a unit file back into vendor state. This means:
         *
         * a) we remove all drop-in snippets added by the user ("config"), add to transient units
         *    ("transient"), and added via "systemctl set-property" ("control"), but not if the drop-in is
         *    generated ("generated").
         *
         * c) if there's a vendor unit file (i.e. one in /usr) we remove any configured overriding unit files
         *    (i.e. in "config", but not in "transient" or "control" or even "generated").
         *
         * We remove all that in both the runtime and the persistent directories, if that applies.
         */

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        STRV_FOREACH(name, names) {
                bool has_vendor = false;

                if (!unit_name_is_valid(*name, UNIT_NAME_ANY))
                        return -EINVAL;

                STRV_FOREACH(p, lp.search_path) {
                        _cleanup_free_ char *path = NULL, *dropin = NULL;
                        struct stat st;

                        path = path_make_absolute(*name, *p);
                        if (!path)
                                return -ENOMEM;

                        r = RET_NERRNO(lstat(path, &st));
                        if (r < 0) {
                                if (r != -ENOENT)
                                        return install_changes_add(changes, n_changes, r, path, NULL);
                        } else if (S_ISREG(st.st_mode)) {
                                /* Check if there's a vendor version */
                                r = path_is_vendor_or_generator(&lp, path);
                                if (r < 0)
                                        return install_changes_add(changes, n_changes, r, path, NULL);
                                if (r > 0)
                                        has_vendor = true;
                        }

                        dropin = strjoin(path, ".d");
                        if (!dropin)
                                return -ENOMEM;

                        r = RET_NERRNO(lstat(dropin, &st));
                        if (r < 0) {
                                if (r != -ENOENT)
                                        return install_changes_add(changes, n_changes, r, dropin, NULL);
                        } else if (S_ISDIR(st.st_mode)) {
                                /* Remove the drop-ins */
                                r = path_shall_revert(&lp, dropin);
                                if (r < 0)
                                        return install_changes_add(changes, n_changes, r, dropin, NULL);
                                if (r > 0) {
                                        if (!GREEDY_REALLOC0(todo, n_todo + 2))
                                                return -ENOMEM;

                                        todo[n_todo++] = TAKE_PTR(dropin);
                                }
                        }
                }

                if (!has_vendor)
                        continue;

                /* OK, there's a vendor version, hence drop all configuration versions */
                STRV_FOREACH(p, lp.search_path) {
                        _cleanup_free_ char *path = NULL;
                        struct stat st;

                        path = path_make_absolute(*name, *p);
                        if (!path)
                                return -ENOMEM;

                        r = RET_NERRNO(lstat(path, &st));
                        if (r < 0) {
                                if (r != -ENOENT)
                                        return install_changes_add(changes, n_changes, r, path, NULL);
                        } else if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
                                r = path_is_config(&lp, path, true);
                                if (r < 0)
                                        return install_changes_add(changes, n_changes, r, path, NULL);
                                if (r > 0) {
                                        if (!GREEDY_REALLOC0(todo, n_todo + 2))
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

                (void) get_files_in_directory(*i, &fs);

                q = rm_rf(*i, REMOVE_ROOT|REMOVE_PHYSICAL);
                if (q < 0 && q != -ENOENT && r >= 0) {
                        r = q;
                        continue;
                }

                STRV_FOREACH(j, fs) {
                        _cleanup_free_ char *t = NULL;

                        t = path_join(*i, *j);
                        if (!t)
                                return -ENOMEM;

                        q = install_changes_add(changes, n_changes, INSTALL_CHANGE_UNLINK, t, NULL);
                        if (q < 0)
                                return q;
                }

                q = install_changes_add(changes, n_changes, INSTALL_CHANGE_UNLINK, *i, NULL);
                if (q < 0)
                        return q;

                rp = skip_root(lp.root_dir, *i);
                q = mark_symlink_for_removal(&remove_symlinks_to, rp ?: *i);
                if (q < 0)
                        return q;
        }

        q = remove_marked_symlinks(remove_symlinks_to, lp.runtime_config, &lp, false, changes, n_changes);
        if (r >= 0)
                r = q;

        q = remove_marked_symlinks(remove_symlinks_to, lp.persistent_config, &lp, false, changes, n_changes);
        if (r >= 0)
                r = q;

        return r;
}

int unit_file_add_dependency(
                RuntimeScope scope,
                UnitFileFlags file_flags,
                const char *root_dir,
                char **names,
                const char *target,
                UnitDependency dep,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_(install_context_done) InstallContext ctx = { .scope = scope };
        InstallInfo *info, *target_info;
        const char *config_path;
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(target);
        assert(IN_SET(dep, UNIT_WANTS, UNIT_REQUIRES));

        if (!unit_name_is_valid(target, UNIT_NAME_ANY))
                return install_changes_add(changes, n_changes, -EUCLEAN, target, NULL);

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        config_path = (file_flags & UNIT_FILE_RUNTIME) ? lp.runtime_config : lp.persistent_config;
        if (!config_path)
                return -ENXIO;

        r = install_info_discover_and_check(&ctx, &lp, target, SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                            &target_info, changes, n_changes);
        if (r < 0)
                return r;

        assert(target_info->install_mode == INSTALL_MODE_REGULAR);

        STRV_FOREACH(name, names) {
                char ***l;

                r = install_info_discover_and_check(&ctx, &lp, *name,
                                                    SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                                    &info, changes, n_changes);
                if (r < 0)
                        return r;

                assert(info->install_mode == INSTALL_MODE_REGULAR);

                /* We didn't actually load anything from the unit
                 * file, but instead just add in our new symlink to
                 * create. */

                if (dep == UNIT_WANTS)
                        l = &info->wanted_by;
                else if (dep == UNIT_REQUIRES)
                        l = &info->required_by;
                else
                        l = &info->upheld_by;

                strv_free(*l);
                *l = strv_new(target_info->name);
                if (!*l)
                        return -ENOMEM;
        }

        return install_context_apply(&ctx, &lp, file_flags, config_path,
                                     SEARCH_FOLLOW_CONFIG_SYMLINKS, changes, n_changes);
}

static int do_unit_file_enable(
                const LookupPaths *lp,
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *config_path,
                char **names_or_paths,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(install_context_done) InstallContext ctx = { .scope = scope };
        InstallInfo *info;
        int r;

        STRV_FOREACH(name, names_or_paths) {
                r = install_info_discover_and_check(&ctx, lp, *name,
                                                    SEARCH_LOAD | SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                                    &info, changes, n_changes);
                if (r < 0)
                        return r;

                assert(info->install_mode == INSTALL_MODE_REGULAR);
        }

        /* This will return the number of symlink rules that were
           supposed to be created, not the ones actually created. This
           is useful to determine whether the passed units had any
           installation data at all. */

        return install_context_apply(&ctx, lp, flags, config_path,
                                     SEARCH_LOAD, changes, n_changes);
}

int unit_file_enable(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **names_or_paths,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        const char *config_path = config_path_from_flags(&lp, flags);
        if (!config_path)
                return -ENXIO;

        return do_unit_file_enable(&lp, scope, flags, config_path, names_or_paths, changes, n_changes);
}

static int do_unit_file_disable(
                const LookupPaths *lp,
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *config_path,
                char **names,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(install_context_done) InstallContext ctx = { .scope = scope };
        _cleanup_set_free_free_ Set *remove_symlinks_to = NULL;
        InstallInfo *info;
        bool has_install_info = false;
        int r;

        STRV_FOREACH(name, names) {
                if (!unit_name_is_valid(*name, UNIT_NAME_ANY))
                        return install_changes_add(changes, n_changes, -EUCLEAN, *name, NULL);

                r = install_info_add(&ctx, *name, NULL, lp->root_dir, /* auxiliary= */ false, &info);
                if (r >= 0)
                        r = install_info_traverse(&ctx, lp, info, SEARCH_LOAD|SEARCH_FOLLOW_CONFIG_SYMLINKS, NULL);

                if (r < 0)
                        return install_changes_add(changes, n_changes, r, *name, NULL);

                /* If we enable multiple units, some with install info and others without,
                 * the "empty [Install] section" warning is not shown. Let's make the behavior
                 * of disable align with that. */
                has_install_info = has_install_info || install_info_has_rules(info) || install_info_has_also(info);
        }

        r = install_context_mark_for_removal(&ctx, lp, &remove_symlinks_to, config_path, changes, n_changes);
        if (r >= 0)
                r = remove_marked_symlinks(remove_symlinks_to, config_path, lp, flags & UNIT_FILE_DRY_RUN, changes, n_changes);

        if (r < 0)
                return r;

        /* The warning is shown only if it's a no-op */
        return install_changes_have_modification(*changes, *n_changes) || has_install_info;
}

int unit_file_disable(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        const char *config_path = config_path_from_flags(&lp, flags);
        if (!config_path)
                return -ENXIO;

        return do_unit_file_disable(&lp, scope, flags, config_path, files, changes, n_changes);
}

static int normalize_linked_files(
                RuntimeScope scope,
                const LookupPaths *lp,
                char **names_or_paths,
                char ***ret_names,
                char ***ret_files) {

        /* This is similar to normalize_filenames()/normalize_names() in src/systemctl/,
         * but operates on real unit names. For each argument we look up the actual path
         * where the unit is found. This way linked units can be re-enabled successfully. */

        _cleanup_strv_free_ char **files = NULL, **names = NULL;
        int r;

        STRV_FOREACH(a, names_or_paths) {
                _cleanup_(install_context_done) InstallContext ctx = { .scope = scope };
                InstallInfo *i = NULL;
                _cleanup_free_ char *n = NULL;

                r = path_extract_filename(*a, &n);
                if (r < 0)
                        return r;
                if (r == O_DIRECTORY)
                        return log_debug_errno(SYNTHETIC_ERRNO(EISDIR),
                                               "Unexpected path to a directory \"%s\", refusing.", *a);

                if (!is_path(*a) && !unit_name_is_valid(*a, UNIT_NAME_INSTANCE)) {
                        r = install_info_discover(&ctx, lp, n, SEARCH_LOAD|SEARCH_FOLLOW_CONFIG_SYMLINKS, &i, NULL, NULL);
                        if (r < 0)
                                log_debug_errno(r, "Failed to discover unit \"%s\", operating on name: %m", n);
                }

                r = strv_consume(&names, TAKE_PTR(n));
                if (r < 0)
                        return r;

                const char *p = NULL;
                if (i && i->path && i->root)
                        /* Use startswith here, because we know that paths are normalized, and
                         * path_startswith() would give us a relative path, but we need an absolute path
                         * relative to i->root.
                         *
                         * In other words: /var/tmp/instroot.1234/etc/systemd/system/frobnicator.service
                         * is replaced by /etc/systemd/system/frobnicator.service, which is "absolute"
                         * in a sense, but only makes sense "relative" to /var/tmp/instroot.1234/.
                         */
                        p = startswith(i->path, i->root);

                r = strv_extend(&files, p ?: *a);
                if (r < 0)
                        return r;
        }

        *ret_names = TAKE_PTR(names);
        *ret_files = TAKE_PTR(files);
        return 0;
}

int unit_file_reenable(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **names_or_paths,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_strv_free_ char **names = NULL, **files = NULL;
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        const char *config_path = config_path_from_flags(&lp, flags);
        if (!config_path)
                return -ENXIO;

        r = normalize_linked_files(scope, &lp, names_or_paths, &names, &files);
        if (r < 0)
                return r;

        /* First, we invoke the disable command with only the basename... */
        r = do_unit_file_disable(&lp, scope, flags, config_path, names, changes, n_changes);
        if (r < 0)
                return r;

        /* But the enable command with the full name */
        return do_unit_file_enable(&lp, scope, flags, config_path, files, changes, n_changes);
}

int unit_file_set_default(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                const char *name,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_(install_context_done) InstallContext ctx = { .scope = scope };
        InstallInfo *info;
        const char *new_path;
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(name);

        if (unit_name_to_type(name) != UNIT_TARGET) /* this also validates the name */
                return -EINVAL;
        if (streq(name, SPECIAL_DEFAULT_TARGET))
                return -EINVAL;

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        r = install_info_discover_and_check(&ctx, &lp, name, 0, &info, changes, n_changes);
        if (r < 0)
                return r;

        new_path = strjoina(lp.persistent_config, "/" SPECIAL_DEFAULT_TARGET);
        return create_symlink(&lp, info->path, new_path, flags & UNIT_FILE_FORCE, changes, n_changes);
}

int unit_file_get_default(
                RuntimeScope scope,
                const char *root_dir,
                char **name) {

        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_(install_context_done) InstallContext ctx = { .scope = scope };
        InstallInfo *info;
        char *n;
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(name);

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        r = install_info_discover(&ctx, &lp, SPECIAL_DEFAULT_TARGET, SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                  &info, NULL, NULL);
        if (r < 0)
                return r;

        n = strdup(info->name);
        if (!n)
                return -ENOMEM;

        *name = n;
        return 0;
}

int unit_file_lookup_state(
                RuntimeScope scope,
                const LookupPaths *lp,
                const char *name,
                UnitFileState *ret) {

        _cleanup_(install_context_done) InstallContext ctx = { .scope = scope };
        InstallInfo *info;
        UnitFileState state;
        int r;

        assert(lp);
        assert(name);

        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        r = install_info_discover(&ctx, lp, name, SEARCH_LOAD|SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                  &info, NULL, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to discover unit %s: %m", name);

        assert(IN_SET(info->install_mode, INSTALL_MODE_REGULAR, INSTALL_MODE_MASKED));
        log_debug("Found unit %s at %s (%s)", name, strna(info->path),
                  info->install_mode == INSTALL_MODE_REGULAR ? "regular file" : "mask");

        /* Shortcut things, if the caller just wants to know if this unit exists. */
        if (!ret)
                return 0;

        switch (info->install_mode) {

        case INSTALL_MODE_MASKED:
                r = path_is_runtime(lp, info->path, true);
                if (r < 0)
                        return r;

                state = r > 0 ? UNIT_FILE_MASKED_RUNTIME : UNIT_FILE_MASKED;
                break;

        case INSTALL_MODE_REGULAR:
                /* Check if the name we were querying is actually an alias */
                if (!streq(name, basename(info->path)) && !unit_name_is_valid(info->name, UNIT_NAME_INSTANCE)) {
                        state = UNIT_FILE_ALIAS;
                        break;
                }

                r = path_is_generator(lp, info->path);
                if (r < 0)
                        return r;
                if (r > 0) {
                        state = UNIT_FILE_GENERATED;
                        break;
                }

                r = path_is_transient(lp, info->path);
                if (r < 0)
                        return r;
                if (r > 0) {
                        state = UNIT_FILE_TRANSIENT;
                        break;
                }

                /* Check if any of the Alias= symlinks have been created.
                 * We ignore other aliases, and only check those that would
                 * be created by systemctl enable for this unit. */
                r = find_symlinks_in_scope(scope, lp, info, true, &state);
                if (r < 0)
                        return r;
                if (r > 0)
                        break;

                /* Check if the file is known under other names. If it is,
                 * it might be in use. Report that as UNIT_FILE_INDIRECT. */
                r = find_symlinks_in_scope(scope, lp, info, false, &state);
                if (r < 0)
                        return r;
                if (r > 0)
                        state = UNIT_FILE_INDIRECT;
                else {
                        if (install_info_has_rules(info))
                                state = UNIT_FILE_DISABLED;
                        else if (install_info_has_also(info))
                                state = UNIT_FILE_INDIRECT;
                        else
                                state = UNIT_FILE_STATIC;
                }

                break;

        default:
                assert_not_reached();
        }

        *ret = state;
        return 0;
}

int unit_file_get_state(
                RuntimeScope scope,
                const char *root_dir,
                const char *name,
                UnitFileState *ret) {

        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(name);

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        return unit_file_lookup_state(scope, &lp, name, ret);
}

int unit_file_exists(RuntimeScope scope, const LookupPaths *lp, const char *name) {
        _cleanup_(install_context_done) InstallContext c = { .scope = scope };
        int r;

        assert(lp);
        assert(name);

        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        r = install_info_discover(&c, lp, name, 0, NULL, NULL, NULL);
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

        r = extract_first_word(&pattern, &unit_name, NULL, EXTRACT_RETAIN_ESCAPE);
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

static int presets_find_config(RuntimeScope scope, const char *root_dir, char ***files) {
        static const char* const system_dirs[] = {CONF_PATHS("systemd/system-preset"), NULL};
        static const char* const user_dirs[] = {CONF_PATHS_USR("systemd/user-preset"), NULL};
        const char* const* dirs;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);

        if (scope == RUNTIME_SCOPE_SYSTEM)
                dirs = system_dirs;
        else if (IN_SET(scope, RUNTIME_SCOPE_GLOBAL, RUNTIME_SCOPE_USER))
                dirs = user_dirs;
        else
                assert_not_reached();

        return conf_files_list_strv(files, ".preset", root_dir, 0, dirs);
}

static int read_presets(RuntimeScope scope, const char *root_dir, UnitFilePresets *presets) {
        _cleanup_(unit_file_presets_done) UnitFilePresets ps = {};
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(presets);

        r = presets_find_config(scope, root_dir, &files);
        if (r < 0)
                return r;

        STRV_FOREACH(p, files) {
                _cleanup_fclose_ FILE *f = NULL;
                int n = 0;

                f = fopen(*p, "re");
                if (!f) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                for (;;) {
                        _cleanup_free_ char *line = NULL;
                        _cleanup_(unit_file_preset_rule_done) UnitFilePresetRule rule = {};
                        const char *parameter;

                        r = read_stripped_line(f, LONG_LINE_MAX, &line);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        n++;

                        if (isempty(line))
                                continue;
                        if (strchr(COMMENTS, line[0]))
                                continue;

                        parameter = first_word(line, "enable");
                        if (parameter) {
                                char *unit_name;
                                char **instances = NULL;

                                /* Unit_name will remain the same as parameter when no instances are specified */
                                r = split_pattern_into_name_and_instances(parameter, &unit_name, &instances);
                                if (r < 0) {
                                        log_syntax(NULL, LOG_WARNING, *p, n, r, "Couldn't parse line '%s'. Ignoring.", line);
                                        continue;
                                }

                                rule = (UnitFilePresetRule) {
                                        .pattern = unit_name,
                                        .action = PRESET_ENABLE,
                                        .instances = instances,
                                };
                        }

                        parameter = first_word(line, "disable");
                        if (parameter) {
                                char *pattern;

                                pattern = strdup(parameter);
                                if (!pattern)
                                        return -ENOMEM;

                                rule = (UnitFilePresetRule) {
                                        .pattern = pattern,
                                        .action = PRESET_DISABLE,
                                };
                        }

                        parameter = first_word(line, "ignore");
                        if (parameter) {
                                char *pattern;

                                pattern = strdup(parameter);
                                if (!pattern)
                                        return -ENOMEM;

                                rule = (UnitFilePresetRule) {
                                        .pattern = pattern,
                                        .action = PRESET_IGNORE,
                                };
                        }

                        if (rule.action) {
                                if (!GREEDY_REALLOC(ps.rules, ps.n_rules + 1))
                                        return -ENOMEM;

                                ps.rules[ps.n_rules++] = TAKE_STRUCT(rule);
                                continue;
                        }

                        log_syntax(NULL, LOG_WARNING, *p, n, 0, "Couldn't parse line '%s'. Ignoring.", line);
                }
        }

        ps.initialized = true;
        *presets = TAKE_STRUCT(ps);

        return 0;
}

static int pattern_match_multiple_instances(
                        const UnitFilePresetRule rule,
                        const char *unit_name,
                        char ***ret) {

        _cleanup_free_ char *templated_name = NULL;
        int r;

        /* If no ret is needed or the rule itself does not have instances
         * initialized, we return not matching */
        if (!ret || !rule.instances)
                return 0;

        r = unit_name_template(unit_name, &templated_name);
        if (r < 0)
                return r;
        if (!streq(rule.pattern, templated_name))
                return 0;

        /* Compose a list of specified instances when unit name is a template  */
        if (unit_name_is_valid(unit_name, UNIT_NAME_TEMPLATE)) {
                _cleanup_strv_free_ char **out_strv = NULL;

                STRV_FOREACH(iter, rule.instances) {
                        _cleanup_free_ char *name = NULL;

                        r = unit_name_replace_instance(unit_name, *iter, &name);
                        if (r < 0)
                                return r;

                        r = strv_consume(&out_strv, TAKE_PTR(name));
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

static int query_presets(const char *name, const UnitFilePresets *presets, char ***instance_name_list) {
        PresetAction action = PRESET_UNKNOWN;

        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        for (size_t i = 0; i < presets->n_rules; i++)
                if (pattern_match_multiple_instances(presets->rules[i], name, instance_name_list) > 0 ||
                    fnmatch(presets->rules[i].pattern, name, FNM_NOESCAPE) == 0) {
                        action = presets->rules[i].action;
                        break;
                }

        switch (action) {
        case PRESET_UNKNOWN:
                log_debug("Preset files don't specify rule for %s. Enabling.", name);
                return PRESET_ENABLE;
        case PRESET_ENABLE:
                if (instance_name_list && *instance_name_list)
                        STRV_FOREACH(s, *instance_name_list)
                                log_debug("Preset files say enable %s.", *s);
                else
                        log_debug("Preset files say enable %s.", name);
                return PRESET_ENABLE;
        case PRESET_DISABLE:
                log_debug("Preset files say disable %s.", name);
                return PRESET_DISABLE;
        case PRESET_IGNORE:
                log_debug("Preset files say ignore %s.", name);
                return PRESET_IGNORE;
        default:
                assert_not_reached();
        }
}

PresetAction unit_file_query_preset(RuntimeScope scope, const char *root_dir, const char *name, UnitFilePresets *cached) {
        _cleanup_(unit_file_presets_done) UnitFilePresets tmp = {};
        int r;

        if (!cached)
                cached = &tmp;
        if (!cached->initialized) {
                r = read_presets(scope, root_dir, cached);
                if (r < 0)
                        return r;
        }

        return query_presets(name, cached, NULL);
}

static int execute_preset(
                UnitFileFlags file_flags,
                InstallContext *plus,
                InstallContext *minus,
                const LookupPaths *lp,
                const char *config_path,
                char **files,
                UnitFilePresetMode mode,
                InstallChange **changes,
                size_t *n_changes) {

        int r;

        assert(plus);
        assert(minus);
        assert(lp);
        assert(config_path);

        if (mode != UNIT_FILE_PRESET_ENABLE_ONLY) {
                _cleanup_set_free_free_ Set *remove_symlinks_to = NULL;

                r = install_context_mark_for_removal(minus, lp, &remove_symlinks_to, config_path, changes, n_changes);
                if (r < 0)
                        return r;

                r = remove_marked_symlinks(remove_symlinks_to, config_path, lp, false, changes, n_changes);
        } else
                r = 0;

        if (mode != UNIT_FILE_PRESET_DISABLE_ONLY) {
                int q;

                /* Returns number of symlinks that where supposed to be installed. */
                q = install_context_apply(plus, lp,
                                          file_flags | UNIT_FILE_IGNORE_AUXILIARY_FAILURE,
                                          config_path,
                                          SEARCH_LOAD, changes, n_changes);
                if (r >= 0) {
                        if (q < 0)
                                r = q;
                        else
                                r += q;
                }
        }

        return r;
}

static int preset_prepare_one(
                RuntimeScope scope,
                InstallContext *plus,
                InstallContext *minus,
                LookupPaths *lp,
                const char *name,
                const UnitFilePresets *presets,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(install_context_done) InstallContext tmp = { .scope = scope };
        _cleanup_strv_free_ char **instance_name_list = NULL;
        InstallInfo *info;
        int r;

        if (install_info_find(plus, name) || install_info_find(minus, name))
                return 0;

        r = install_info_discover(&tmp, lp, name, SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                  &info, changes, n_changes);
        if (r < 0)
                return r;
        if (!streq(name, info->name)) {
                log_debug("Skipping %s because it is an alias for %s.", name, info->name);
                return 0;
        }

        r = query_presets(name, presets, &instance_name_list);
        if (r < 0)
                return r;

        if (r == PRESET_ENABLE) {
                if (instance_name_list)
                        STRV_FOREACH(s, instance_name_list) {
                                r = install_info_discover_and_check(plus, lp, *s, SEARCH_LOAD|SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                                                    &info, changes, n_changes);
                                if (r < 0)
                                        return r;
                        }
                else {
                        r = install_info_discover_and_check(plus, lp, name, SEARCH_LOAD|SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                                            &info, changes, n_changes);
                        if (r < 0)
                                return r;
                }

        } else if (r == PRESET_DISABLE)
                r = install_info_discover(minus, lp, name, SEARCH_FOLLOW_CONFIG_SYMLINKS,
                                          &info, changes, n_changes);

        return r;
}

int unit_file_preset(
                RuntimeScope scope,
                UnitFileFlags file_flags,
                const char *root_dir,
                char **names,
                UnitFilePresetMode mode,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(install_context_done) InstallContext plus = {}, minus = {};
        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_(unit_file_presets_done) UnitFilePresets presets = {};
        const char *config_path;
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(mode < _UNIT_FILE_PRESET_MODE_MAX);

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        config_path = (file_flags & UNIT_FILE_RUNTIME) ? lp.runtime_config : lp.persistent_config;
        if (!config_path)
                return -ENXIO;

        r = read_presets(scope, root_dir, &presets);
        if (r < 0)
                return r;

        STRV_FOREACH(name, names) {
                r = preset_prepare_one(scope, &plus, &minus, &lp, *name, &presets, changes, n_changes);
                if (r < 0)
                        return r;
        }

        return execute_preset(file_flags, &plus, &minus, &lp, config_path, names, mode, changes, n_changes);
}

int unit_file_preset_all(
                RuntimeScope scope,
                UnitFileFlags file_flags,
                const char *root_dir,
                UnitFilePresetMode mode,
                InstallChange **changes,
                size_t *n_changes) {

        _cleanup_(install_context_done) InstallContext plus = {}, minus = {};
        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_(unit_file_presets_done) UnitFilePresets presets = {};
        const char *config_path = NULL;
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(mode < _UNIT_FILE_PRESET_MODE_MAX);

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        config_path = (file_flags & UNIT_FILE_RUNTIME) ? lp.runtime_config : lp.persistent_config;
        if (!config_path)
                return -ENXIO;

        r = read_presets(scope, root_dir, &presets);
        if (r < 0)
                return r;

        STRV_FOREACH(i, lp.search_path) {
                _cleanup_closedir_ DIR *d = NULL;

                d = opendir(*i);
                if (!d) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                FOREACH_DIRENT(de, d, return -errno) {

                        if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                                continue;

                        if (!IN_SET(de->d_type, DT_LNK, DT_REG))
                                continue;

                        r = preset_prepare_one(scope, &plus, &minus, &lp, de->d_name, &presets, changes, n_changes);
                        if (r < 0 &&
                            !IN_SET(r, -EEXIST, -ERFKILL, -EADDRNOTAVAIL, -EBADSLT, -EIDRM, -EUCLEAN, -ELOOP, -ENOENT, -EUNATCH, -EXDEV))
                                /* Ignore generated/transient/missing/invalid units when applying preset, propagate other errors.
                                 * Coordinate with install_changes_dump() above. */
                                return r;
                }
        }

        return execute_preset(file_flags, &plus, &minus, &lp, config_path, NULL, mode, changes, n_changes);
}

static UnitFileList* unit_file_list_free(UnitFileList *f) {
        if (!f)
                return NULL;

        free(f->path);
        return mfree(f);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UnitFileList*, unit_file_list_free);

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        unit_file_list_hash_ops_free,
        char,
        string_hash_func,
        string_compare_func,
        UnitFileList,
        unit_file_list_free);

int unit_file_get_list(
                RuntimeScope scope,
                const char *root_dir,
                Hashmap *h,
                char **states,
                char **patterns) {

        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(h);

        r = lookup_paths_init(&lp, scope, 0, root_dir);
        if (r < 0)
                return r;

        STRV_FOREACH(dirname, lp.search_path) {
                _cleanup_closedir_ DIR *d = NULL;

                d = opendir(*dirname);
                if (!d) {
                        if (errno == ENOENT)
                                continue;
                        if (IN_SET(errno, ENOTDIR, EACCES)) {
                                log_debug_errno(errno, "Failed to open \"%s\": %m", *dirname);
                                continue;
                        }

                        return -errno;
                }

                FOREACH_DIRENT(de, d, return -errno) {
                        _cleanup_(unit_file_list_freep) UnitFileList *f = NULL;

                        if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                                continue;

                        if (!strv_fnmatch_or_empty(patterns, de->d_name, FNM_NOESCAPE))
                                continue;

                        if (hashmap_get(h, de->d_name))
                                continue;

                        if (!IN_SET(de->d_type, DT_LNK, DT_REG))
                                continue;

                        f = new0(UnitFileList, 1);
                        if (!f)
                                return -ENOMEM;

                        f->path = path_make_absolute(de->d_name, *dirname);
                        if (!f->path)
                                return -ENOMEM;

                        r = unit_file_lookup_state(scope, &lp, de->d_name, &f->state);
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
        [UNIT_FILE_ENABLED]         = "enabled",
        [UNIT_FILE_ENABLED_RUNTIME] = "enabled-runtime",
        [UNIT_FILE_LINKED]          = "linked",
        [UNIT_FILE_LINKED_RUNTIME]  = "linked-runtime",
        [UNIT_FILE_ALIAS]           = "alias",
        [UNIT_FILE_MASKED]          = "masked",
        [UNIT_FILE_MASKED_RUNTIME]  = "masked-runtime",
        [UNIT_FILE_STATIC]          = "static",
        [UNIT_FILE_DISABLED]        = "disabled",
        [UNIT_FILE_INDIRECT]        = "indirect",
        [UNIT_FILE_GENERATED]       = "generated",
        [UNIT_FILE_TRANSIENT]       = "transient",
        [UNIT_FILE_BAD]             = "bad",
};

DEFINE_STRING_TABLE_LOOKUP(unit_file_state, UnitFileState);

static const char* const install_change_type_table[_INSTALL_CHANGE_TYPE_MAX] = {
        [INSTALL_CHANGE_SYMLINK]                 = "symlink",
        [INSTALL_CHANGE_UNLINK]                  = "unlink",
        [INSTALL_CHANGE_IS_MASKED]               = "masked",
        [INSTALL_CHANGE_IS_MASKED_GENERATOR]     = "masked by generator",
        [INSTALL_CHANGE_IS_DANGLING]             = "dangling",
        [INSTALL_CHANGE_DESTINATION_NOT_PRESENT] = "destination not present",
        [INSTALL_CHANGE_AUXILIARY_FAILED]        = "auxiliary unit failed",
};

DEFINE_STRING_TABLE_LOOKUP(install_change_type, InstallChangeType);

static const char* const unit_file_preset_mode_table[_UNIT_FILE_PRESET_MODE_MAX] = {
        [UNIT_FILE_PRESET_FULL]         = "full",
        [UNIT_FILE_PRESET_ENABLE_ONLY]  = "enable-only",
        [UNIT_FILE_PRESET_DISABLE_ONLY] = "disable-only",
};

DEFINE_STRING_TABLE_LOOKUP(unit_file_preset_mode, UnitFilePresetMode);
