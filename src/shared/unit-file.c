/* SPDX-License-Identifier: LGPL-2.1+ */

#include "dirent-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "path-lookup.h"
#include "set.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit-file.h"

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

int unit_validate_alias_symlink_and_warn(const char *filename, const char *target) {
        const char *src, *dst;
        _cleanup_free_ char *src_instance = NULL, *dst_instance = NULL;
        UnitType src_unit_type, dst_unit_type;
        int src_name_type, dst_name_type;

        /* Check if the *alias* symlink is valid. This applies to symlinks like
         * /etc/systemd/system/dbus.service → dbus-broker.service, but not to .wants or .requires symlinks
         * and such. Neither does this apply to symlinks which *link* units, i.e. symlinks to outside of the
         * unit lookup path.
         *
         * -EINVAL is returned if the something is wrong with the source filename or the source unit type is
         *         not allowed to symlink,
         * -EXDEV if the target filename is not a valid unit name or doesn't match the source.
         */

        src = basename(filename);
        dst = basename(target);

        /* src checks */

        src_name_type = unit_name_to_instance(src, &src_instance);
        if (src_name_type < 0)
                return log_notice_errno(src_name_type,
                                        "%s: not a valid unit name \"%s\": %m", filename, src);

        src_unit_type = unit_name_to_type(src);
        assert(src_unit_type >= 0); /* unit_name_to_instance() checked the suffix already */

        if (!unit_type_may_alias(src_unit_type))
                return log_notice_errno(SYNTHETIC_ERRNO(EINVAL),
                                        "%s: symlinks are not allowed for units of this type, rejecting.",
                                        filename);

        if (src_name_type != UNIT_NAME_PLAIN &&
            !unit_type_may_template(src_unit_type))
                return log_notice_errno(SYNTHETIC_ERRNO(EINVAL),
                                        "%s: templates not allowed for %s units, rejecting.",
                                        filename, unit_type_to_string(src_unit_type));

        /* dst checks */

        dst_name_type = unit_name_to_instance(dst, &dst_instance);
        if (dst_name_type < 0)
                return log_notice_errno(dst_name_type == -EINVAL ? SYNTHETIC_ERRNO(EXDEV) : dst_name_type,
                                        "%s points to \"%s\" which is not a valid unit name: %m",
                                        filename, dst);

        if (!(dst_name_type == src_name_type ||
              (src_name_type == UNIT_NAME_INSTANCE && dst_name_type == UNIT_NAME_TEMPLATE)))
                return log_notice_errno(SYNTHETIC_ERRNO(EXDEV),
                                        "%s: symlink target name type \"%s\" does not match source, rejecting.",
                                        filename, dst);

        if (dst_name_type == UNIT_NAME_INSTANCE) {
                assert(src_instance);
                assert(dst_instance);
                if (!streq(src_instance, dst_instance))
                        return log_notice_errno(SYNTHETIC_ERRNO(EXDEV),
                                                "%s: unit symlink target \"%s\" instance name doesn't match, rejecting.",
                                                filename, dst);
        }

        dst_unit_type = unit_name_to_type(dst);
        if (dst_unit_type != src_unit_type)
                return log_notice_errno(SYNTHETIC_ERRNO(EXDEV),
                                        "%s: symlink target \"%s\" has incompatible suffix, rejecting.",
                                        filename, dst);

        return 0;
}

#define FOLLOW_MAX 8

static int unit_ids_map_get(
                Hashmap *unit_ids_map,
                const char *unit_name,
                const char **ret_fragment_path) {

        /* Resolve recursively until we hit an absolute path, i.e. a non-aliased unit.
         *
         * We distinguish the case where unit_name was not found in the hashmap at all, and the case where
         * some symlink was broken.
         *
         * If a symlink target points to an instance name, then we also check for the template. */

        const char *id = NULL;
        int r;

        for (unsigned n = 0; n < FOLLOW_MAX; n++) {
                const char *t = hashmap_get(unit_ids_map, id ?: unit_name);
                if (!t) {
                        _cleanup_free_ char *template = NULL;

                        if (!id)
                                return -ENOENT;

                        r = unit_name_template(id, &template);
                        if (r == -EINVAL)
                                return -ENXIO; /* we failed to find the symlink target */
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine template name for %s: %m", id);

                        t = hashmap_get(unit_ids_map, template);
                        if (!t)
                                return -ENXIO;

                        /* We successfully switched from instanced name to a template, let's continue */
                }

                if (path_is_absolute(t)) {
                        if (ret_fragment_path)
                                *ret_fragment_path = t;
                        return 0;
                }

                id = t;
        }

        return -ELOOP;
}

static bool lookup_paths_mtime_exclude(const LookupPaths *lp, const char *path) {
        /* Paths that are under our exclusive control. Users shall not alter those directly. */

        return streq_ptr(path, lp->generator) ||
               streq_ptr(path, lp->generator_early) ||
               streq_ptr(path, lp->generator_late) ||
               streq_ptr(path, lp->transient) ||
               streq_ptr(path, lp->persistent_control) ||
               streq_ptr(path, lp->runtime_control);
}

static bool lookup_paths_mtime_good(const LookupPaths *lp, usec_t mtime) {
        char **dir;

        STRV_FOREACH(dir, (char**) lp->search_path) {
                struct stat st;

                if (lookup_paths_mtime_exclude(lp, *dir))
                        continue;

                /* Determine the latest lookup path modification time */
                if (stat(*dir, &st) < 0) {
                        if (errno == ENOENT)
                                continue;

                        log_debug_errno(errno, "Failed to stat %s, ignoring: %m", *dir);
                        continue;
                }

                if (timespec_load(&st.st_mtim) > mtime) {
                        log_debug_errno(errno, "Unit dir %s has changed, need to update cache.", *dir);
                        return false;
                }
        }

        return true;
}

int unit_file_build_name_map(
                const LookupPaths *lp,
                usec_t *cache_mtime,
                Hashmap **ret_unit_ids_map,
                Hashmap **ret_unit_names_map,
                Set **ret_path_cache) {

        /* Build two mappings: any name → main unit (i.e. the end result of symlink resolution), unit name →
         * all aliases (i.e. the entry for a given key is a a list of all names which point to this key). The
         * key is included in the value iff we saw a file or symlink with that name. In other words, if we
         * have a key, but it is not present in the value for itself, there was an alias pointing to it, but
         * the unit itself is not loadable.
         *
         * At the same, build a cache of paths where to find units.
         */

        _cleanup_hashmap_free_ Hashmap *ids = NULL, *names = NULL;
        _cleanup_set_free_free_ Set *paths = NULL;
        char **dir;
        int r;
        usec_t mtime = 0;

        /* Before doing anything, check if the mtime that was passed is still valid. If
         * yes, do nothing. If *cache_time == 0, always build the cache. */
        if (cache_mtime && *cache_mtime > 0 && lookup_paths_mtime_good(lp, *cache_mtime))
                return 0;

        if (ret_path_cache) {
                paths = set_new(&path_hash_ops);
                if (!paths)
                        return log_oom();
        }

        STRV_FOREACH(dir, (char**) lp->search_path) {
                struct dirent *de;
                _cleanup_closedir_ DIR *d = NULL;
                struct stat st;

                d = opendir(*dir);
                if (!d) {
                        if (errno != ENOENT)
                                log_warning_errno(errno, "Failed to open \"%s\", ignoring: %m", *dir);
                        continue;
                }

                /* Determine the latest lookup path modification time */
                if (fstat(dirfd(d), &st) < 0)
                        return log_error_errno(errno, "Failed to fstat %s: %m", *dir);

                if (!lookup_paths_mtime_exclude(lp, *dir))
                        mtime = MAX(mtime, timespec_load(&st.st_mtim));

                FOREACH_DIRENT_ALL(de, d, log_warning_errno(errno, "Failed to read \"%s\", ignoring: %m", *dir)) {
                        char *filename;
                        _cleanup_free_ char *_filename_free = NULL, *simplified = NULL;
                        const char *suffix, *dst = NULL;
                        bool valid_unit_name;

                        valid_unit_name = unit_name_is_valid(de->d_name, UNIT_NAME_ANY);

                        /* We only care about valid units and dirs with certain suffixes, let's ignore the
                         * rest. */
                        if (!valid_unit_name &&
                            !ENDSWITH_SET(de->d_name, ".wants", ".requires", ".d"))
                                continue;

                        filename = path_join(*dir, de->d_name);
                        if (!filename)
                                return log_oom();

                        if (ret_path_cache) {
                                r = set_consume(paths, filename);
                                if (r < 0)
                                        return log_oom();
                                /* We will still use filename below. This is safe because we know the set
                                 * holds a reference. */
                        } else
                                _filename_free = filename; /* Make sure we free the filename. */

                        if (!valid_unit_name)
                                continue;
                        assert_se(suffix = strrchr(de->d_name, '.'));

                        /* search_path is ordered by priority (highest first). If the name is already mapped
                         * to something (incl. itself), it means that we have already seen it, and we should
                         * ignore it here. */
                        if (hashmap_contains(ids, de->d_name))
                                continue;

                        if (de->d_type == DT_LNK) {
                                /* We don't explicitly check for alias loops here. unit_ids_map_get() which
                                 * limits the number of hops should be used to access the map. */

                                _cleanup_free_ char *target = NULL, *target_abs = NULL;

                                r = readlinkat_malloc(dirfd(d), de->d_name, &target);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to read symlink %s/%s, ignoring: %m",
                                                          *dir, de->d_name);
                                        continue;
                                }

                                if (!path_is_absolute(target)) {
                                        target_abs = path_join(*dir, target);
                                        if (!target_abs)
                                                return log_oom();

                                        free_and_replace(target, target_abs);
                                }

                                /* Get rid of "." and ".." components in target path */
                                r = chase_symlinks(target, lp->root_dir, CHASE_NOFOLLOW | CHASE_NONEXISTENT, &simplified);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to resolve symlink %s pointing to %s, ignoring: %m",
                                                          filename, target);
                                        continue;
                                }

                                /* Check if the symlink goes outside of our search path.
                                 * If yes, it's a linked unit file or mask, and we don't care about the target name.
                                 * Let's just store the link destination directly.
                                 * If not, let's verify that it's a good symlink. */
                                char *tail = path_startswith_strv(simplified, lp->search_path);
                                if (tail) {
                                        bool self_alias;

                                        dst = basename(simplified);
                                        self_alias = streq(dst, de->d_name);

                                        if (is_path(tail))
                                                log_full(self_alias ? LOG_DEBUG : LOG_WARNING,
                                                         "Suspicious symlink %s→%s, treating as alias.",
                                                         filename, simplified);

                                        r = unit_validate_alias_symlink_and_warn(filename, simplified);
                                        if (r < 0)
                                                continue;

                                        if (self_alias) {
                                                /* A self-alias that has no effect */
                                                log_debug("%s: self-alias: %s/%s → %s, ignoring.",
                                                          __func__, *dir, de->d_name, dst);
                                                continue;
                                        }

                                        log_debug("%s: alias: %s/%s → %s", __func__, *dir, de->d_name, dst);
                                } else {
                                        dst  = simplified;

                                        log_debug("%s: linked unit file: %s/%s → %s", __func__, *dir, de->d_name, dst);
                                }

                        } else {
                                dst = filename;
                                log_debug("%s: normal unit file: %s", __func__, dst);
                        }

                        r = hashmap_put_strdup(&ids, de->d_name, dst);
                        if (r < 0)
                                return log_warning_errno(r, "Failed to add entry to hashmap (%s→%s): %m",
                                                         de->d_name, dst);
                }
        }

        /* Let's also put the names in the reverse db. */
        Iterator it;
        const char *dummy, *src;
        HASHMAP_FOREACH_KEY(dummy, src, ids, it) {
                const char *dst;

                r = unit_ids_map_get(ids, src, &dst);
                if (r < 0)
                        continue;

                if (null_or_empty_path(dst) != 0)
                        continue;

                /* Do not treat instance symlinks that point to the template as aliases */
                if (unit_name_is_valid(basename(dst), UNIT_NAME_TEMPLATE) &&
                    unit_name_is_valid(src, UNIT_NAME_INSTANCE))
                        continue;

                r = string_strv_hashmap_put(&names, basename(dst), src);
                if (r < 0)
                        return log_warning_errno(r, "Failed to add entry to hashmap (%s→%s): %m",
                                                 basename(dst), src);
        }

        if (cache_mtime)
                *cache_mtime = mtime;
        *ret_unit_ids_map = TAKE_PTR(ids);
        *ret_unit_names_map = TAKE_PTR(names);
        if (ret_path_cache)
                *ret_path_cache = TAKE_PTR(paths);

        return 1;
}

int unit_file_find_fragment(
                Hashmap *unit_ids_map,
                Hashmap *unit_name_map,
                const char *unit_name,
                const char **ret_fragment_path,
                Set **ret_names) {

        const char *fragment = NULL;
        _cleanup_free_ char *template = NULL, *instance = NULL;
        _cleanup_set_free_free_ Set *names = NULL;
        char **t, **nnn;
        int r, name_type;

        /* Finds a fragment path, and returns the set of names:
         * if we have …/foo.service and …/foo-alias.service→foo.service,
         * and …/foo@.service and …/foo-alias@.service→foo@.service,
         * and …/foo@inst.service,
         * this should return:
         * foo.service → …/foo.service, {foo.service, foo-alias.service},
         * foo-alias.service → …/foo.service, {foo.service, foo-alias.service},
         * foo@.service → …/foo@.service, {foo@.service, foo-alias@.service},
         * foo-alias@.service → …/foo@.service, {foo@.service, foo-alias@.service},
         * foo@bar.service → …/foo@.service, {foo@bar.service, foo-alias@bar.service},
         * foo-alias@bar.service → …/foo@.service, {foo@bar.service, foo-alias@bar.service},
         * foo-alias@inst.service → …/foo@inst.service, {foo@inst.service, foo-alias@inst.service}.
         */

        name_type = unit_name_to_instance(unit_name, &instance);
        if (name_type < 0)
                return name_type;

        names = set_new(&string_hash_ops);
        if (!names)
                return -ENOMEM;

        /* The unit always has its own name if it's not a template. */
        if (IN_SET(name_type, UNIT_NAME_PLAIN, UNIT_NAME_INSTANCE)) {
                r = set_put_strdup(names, unit_name);
                if (r < 0)
                        return r;
        }

        /* First try to load fragment under the original name */
        r = unit_ids_map_get(unit_ids_map, unit_name, &fragment);
        if (r < 0 && !IN_SET(r, -ENOENT, -ENXIO))
                return log_debug_errno(r, "Cannot load unit %s: %m", unit_name);

        if (fragment) {
                /* Add any aliases of the original name to the set of names */
                nnn = hashmap_get(unit_name_map, basename(fragment));
                STRV_FOREACH(t, nnn) {
                        if (name_type == UNIT_NAME_INSTANCE && unit_name_is_valid(*t, UNIT_NAME_TEMPLATE)) {
                                char *inst;

                                r = unit_name_replace_instance(*t, instance, &inst);
                                if (r < 0)
                                        return log_debug_errno(r, "Cannot build instance name %s+%s: %m", *t, instance);

                                if (!streq(unit_name, inst))
                                        log_debug("%s: %s has alias %s", __func__, unit_name, inst);

                                log_info("%s: %s+%s → %s", __func__, *t, instance, inst);
                                r = set_consume(names, inst);
                        } else {
                                if (!streq(unit_name, *t))
                                        log_debug("%s: %s has alias %s", __func__, unit_name, *t);

                                r = set_put_strdup(names, *t);
                        }
                        if (r < 0)
                                return r;
                }
        }

        if (!fragment && name_type == UNIT_NAME_INSTANCE) {
                /* Look for a fragment under the template name */

                r = unit_name_template(unit_name, &template);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine template name: %m");

                r = unit_ids_map_get(unit_ids_map, template, &fragment);
                if (r < 0 && !IN_SET(r, -ENOENT, -ENXIO))
                        return log_debug_errno(r, "Cannot load template %s: %m", template);

                if (fragment) {
                        /* Add any aliases of the original name to the set of names */
                        nnn = hashmap_get(unit_name_map, basename(fragment));
                        STRV_FOREACH(t, nnn) {
                                _cleanup_free_ char *inst = NULL;
                                const char *inst_fragment = NULL;

                                r = unit_name_replace_instance(*t, instance, &inst);
                                if (r < 0)
                                        return log_debug_errno(r, "Cannot build instance name %s+%s: %m", template, instance);

                                /* Exclude any aliases that point in some other direction. */
                                r = unit_ids_map_get(unit_ids_map, inst, &inst_fragment);
                                if (r < 0 && !IN_SET(r, -ENOENT, -ENXIO))
                                        return log_debug_errno(r, "Cannot find instance fragment %s: %m", inst);

                                if (inst_fragment &&
                                    !streq(basename(inst_fragment), basename(fragment))) {
                                        log_debug("Instance %s has fragment %s and is not an alias of %s.",
                                                  inst, inst_fragment, unit_name);
                                        continue;
                                }

                                if (!streq(unit_name, inst))
                                        log_debug("%s: %s has alias %s", __func__, unit_name, inst);
                                r = set_consume(names, TAKE_PTR(inst));
                                if (r < 0)
                                        return r;
                        }
                }
        }

        *ret_fragment_path = fragment;
        *ret_names = TAKE_PTR(names);

        // FIXME: if instance, consider any unit names with different template name
        return 0;
}
