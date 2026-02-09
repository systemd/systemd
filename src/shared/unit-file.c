/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"

#include "alloc-util.h"
#include "chase.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "initrd-util.h"
#include "log.h"
#include "path-lookup.h"
#include "set.h"
#include "siphash24.h"
#include "special.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "unit-file.h"
#include "unit-name.h"

int unit_symlink_name_compatible(const char *symlink, const char *target, bool instance_propagation) {
        _cleanup_free_ char *template = NULL;
        int r, un_type1, un_type2;

        un_type1 = unit_name_classify(symlink);

        /* The straightforward case: the symlink name matches the target and we have a valid unit */
        if (streq(symlink, target) &&
            (un_type1 & (UNIT_NAME_PLAIN | UNIT_NAME_INSTANCE)))
                return 1;

        r = unit_name_template(symlink, &template);
        if (r == -EINVAL)
                return 0; /* Not a template */
        if (r < 0)
                return r;

        un_type2 = unit_name_classify(target);

        /* An instance name points to a target that is just the template name */
        if (un_type1 == UNIT_NAME_INSTANCE &&
            un_type2 == UNIT_NAME_TEMPLATE &&
            streq(template, target))
                return 1;

        /* foo@.target.requires/bar@.service: instance will be propagated */
        if (instance_propagation &&
            un_type1 == UNIT_NAME_TEMPLATE &&
            un_type2 == UNIT_NAME_TEMPLATE &&
            streq(template, target))
                return 1;

        return 0;
}

int unit_validate_alias_symlink_or_warn(int log_level, const char *filename, const char *target) {
        _cleanup_free_ char *src = NULL, *dst = NULL;
        _cleanup_free_ char *src_instance = NULL, *dst_instance = NULL;
        UnitType src_unit_type, dst_unit_type;
        UnitNameFlags src_name_type, dst_name_type;
        int r;

        /* Check if the *alias* symlink is valid. This applies to symlinks like
         * /etc/systemd/system/dbus.service → dbus-broker.service, but not to .wants or .requires symlinks
         * and such. Neither does this apply to symlinks which *link* units, i.e. symlinks to outside of the
         * unit lookup path.
         *
         * -EINVAL is returned if the something is wrong with the source filename or the source unit type is
         *         not allowed to symlink,
         * -EXDEV if the target filename is not a valid unit name or doesn't match the source,
         * -ELOOP for an alias to self.
         */

        r = path_extract_filename(filename, &src);
        if (r < 0)
                return r;

        r = path_extract_filename(target, &dst);
        if (r < 0)
                return r;

        /* src checks */

        src_name_type = unit_name_to_instance(src, &src_instance);
        if (src_name_type < 0)
                return log_full_errno(log_level, src_name_type,
                                      "%s: not a valid unit name \"%s\": %m", filename, src);

        src_unit_type = unit_name_to_type(src);
        assert(src_unit_type >= 0); /* unit_name_to_instance() checked the suffix already */

        if (!unit_type_may_alias(src_unit_type))
                return log_full_errno(log_level, SYNTHETIC_ERRNO(EINVAL),
                                      "%s: symlinks are not allowed for units of this type, rejecting.",
                                      filename);

        if (src_name_type != UNIT_NAME_PLAIN &&
            !unit_type_may_template(src_unit_type))
                return log_full_errno(log_level, SYNTHETIC_ERRNO(EINVAL),
                                      "%s: templates not allowed for %s units, rejecting.",
                                      filename, unit_type_to_string(src_unit_type));

        /* dst checks */

        if (streq(src, dst))
                return log_debug_errno(SYNTHETIC_ERRNO(ELOOP),
                                       "%s: unit self-alias: %s → %s, ignoring.",
                                       filename, src, dst);

        dst_name_type = unit_name_to_instance(dst, &dst_instance);
        if (dst_name_type < 0)
                return log_full_errno(log_level, dst_name_type == -EINVAL ? SYNTHETIC_ERRNO(EXDEV) : dst_name_type,
                                      "%s points to \"%s\" which is not a valid unit name: %m",
                                      filename, dst);

        if (!(dst_name_type == src_name_type ||
              (src_name_type == UNIT_NAME_INSTANCE && dst_name_type == UNIT_NAME_TEMPLATE)))
                return log_full_errno(log_level, SYNTHETIC_ERRNO(EXDEV),
                                      "%s: symlink target name type \"%s\" does not match source, rejecting.",
                                      filename, dst);

        if (dst_name_type == UNIT_NAME_INSTANCE) {
                assert(src_instance);
                assert(dst_instance);
                if (!streq(src_instance, dst_instance))
                        return log_full_errno(log_level, SYNTHETIC_ERRNO(EXDEV),
                                              "%s: unit symlink target \"%s\" instance name doesn't match, rejecting.",
                                              filename, dst);
        }

        dst_unit_type = unit_name_to_type(dst);
        if (dst_unit_type != src_unit_type)
                return log_full_errno(log_level, SYNTHETIC_ERRNO(EXDEV),
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

#define HASH_KEY SD_ID128_MAKE(4e,86,1b,e3,39,b3,40,46,98,5d,b8,11,34,8f,c3,c1)

bool lookup_paths_timestamp_hash_same(const LookupPaths *lp, uint64_t timestamp_hash, uint64_t *ret_new) {
        struct siphash state;

        siphash24_init(&state, HASH_KEY.bytes);

        STRV_FOREACH(dir, lp->search_path) {
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

                siphash24_compress_usec_t(timespec_load(&st.st_mtim), &state);
        }

        uint64_t updated = siphash24_finalize(&state);
        if (ret_new)
                *ret_new = updated;
        if (updated != timestamp_hash)
                log_debug("Modification times have changed, need to update cache.");
        return updated == timestamp_hash;
}

static int directory_name_is_valid(const char *name) {

        /* Accept a directory whose name is a valid unit file name ending in .wants/, .requires/,
         * .upholds/ or .d/ */

        FOREACH_STRING(suffix, ".wants", ".requires", ".upholds", ".d") {
                _cleanup_free_ char *chopped = NULL;
                const char *e;

                e = endswith(name, suffix);
                if (!e)
                        continue;

                chopped = strndup(name, e - name);
                if (!chopped)
                        return log_oom();

                if (unit_name_is_valid(chopped, UNIT_NAME_ANY) ||
                    unit_type_from_string(chopped) >= 0)
                        return true;
        }

        return false;
}

int unit_file_resolve_symlink(
                const char *root_dir,
                char **search_path,
                const char *dir,
                int dirfd,
                const char *filename,
                bool resolve_destination_target,
                char **ret_destination) {

        _cleanup_free_ char *target = NULL, *simplified = NULL, *dst = NULL, *_dir = NULL, *_filename = NULL;
        int r;

        /* This can be called with either dir+dirfd valid and filename just a name,
         * or !dir && dirfd==AT_FDCWD, and filename being a full path.
         *
         * If resolve_destination_target is true, an absolute path will be returned.
         * If not, an absolute path is returned for linked unit files, and a relative
         * path otherwise.
         *
         * Returns an error, false if this is an alias, true if it's a linked unit file. */

        assert(filename);
        assert(ret_destination);
        assert(dir || path_is_absolute(filename));
        assert(dirfd >= 0 || dirfd == AT_FDCWD);

        r = readlinkat_malloc(dirfd, filename, &target);
        if (r < 0)
                return log_warning_errno(r, "Failed to read symlink %s%s%s: %m",
                                         dir, dir ? "/" : "", filename);

        if (!dir) {
                r = path_split_prefix_filename(filename, &_dir, &_filename);
                if (r < 0)
                        return r;
                if (r == O_DIRECTORY)
                        return log_warning_errno(SYNTHETIC_ERRNO(EISDIR),
                                                 "Unexpected path to a directory \"%s\", refusing.", filename);

                /* We validate that the path is absolute above, hence dir must be extractable. */
                dir = ASSERT_PTR(_dir);
                filename = _filename;
        }

        bool is_abs = path_is_absolute(target);
        if (root_dir || !is_abs) {
                char *target_abs = path_join(is_abs ? root_dir : dir, target);
                if (!target_abs)
                        return log_oom();

                free_and_replace(target, target_abs);
        }

        /* Get rid of "." and ".." components in target path */
        r = chase(target, root_dir, CHASE_NOFOLLOW | CHASE_NONEXISTENT, &simplified, NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to resolve symlink %s/%s pointing to %s: %m",
                                         dir, filename, target);

        assert(path_is_absolute(simplified));

        /* Check if the symlink remain inside of our search path.
         * If yes, it is an alias. Verify that it is valid.
         *
         * If no, then this is a linked unit file or mask, and we don't care about the target name
         * when loading units, and we return the link *source* (resolve_destination_target == false);
         * When this is called for installation purposes, we want the final destination,
         * so we return the *target*.
         */
        const char *tail = path_startswith_strv(simplified, search_path);
        if (tail) {  /* An alias */
                _cleanup_free_ char *target_name = NULL;

                r = path_extract_filename(simplified, &target_name);
                if (r < 0)
                        return r;

                r = unit_validate_alias_symlink_or_warn(LOG_NOTICE, filename, simplified);
                if (r < 0)
                        return r;
                if (is_path(tail))
                        log_warning("Suspicious symlink %s/%s %s %s, treating as alias.",
                                    dir, filename, glyph(GLYPH_ARROW_RIGHT), simplified);

                dst = resolve_destination_target ? TAKE_PTR(simplified) : TAKE_PTR(target_name);

        } else {
                log_debug("Linked unit file: %s/%s %s %s", dir, filename, glyph(GLYPH_ARROW_RIGHT), simplified);

                if (resolve_destination_target)
                        dst = TAKE_PTR(simplified);
                else {
                        dst = path_join(dir, filename);
                        if (!dst)
                                return log_oom();
                }
        }

        *ret_destination = TAKE_PTR(dst);
        return !tail;  /* true if linked unit file */
}

int unit_file_build_name_map(
                const LookupPaths *lp,
                uint64_t *cache_timestamp_hash,
                Hashmap **unit_ids_map,
                Hashmap **unit_names_map,
                Set **path_cache) {

        /* Build two mappings: any name → main unit (i.e. the end result of symlink resolution), unit name →
         * all aliases (i.e. the entry for a given key is a list of all names which point to this key). The
         * key is included in the value iff we saw a file or symlink with that name. In other words, if we
         * have a key, but it is not present in the value for itself, there was an alias pointing to it, but
         * the unit itself is not loadable.
         *
         * At the same, build a cache of paths where to find units. The non-const parameters are for input
         * and output. Existing contents will be freed before the new contents are stored.
         */

        _cleanup_hashmap_free_ Hashmap *ids = NULL, *names = NULL;
        _cleanup_set_free_ Set *paths = NULL;
        _cleanup_strv_free_ char **expanded_search_path = NULL;
        uint64_t timestamp_hash;
        int r;

        /* Before doing anything, check if the timestamp hash that was passed is still valid.
         * If yes, do nothing. */
        if (cache_timestamp_hash &&
            lookup_paths_timestamp_hash_same(lp, *cache_timestamp_hash, &timestamp_hash))
                return 0;

        /* The timestamp hash is now set based on the mtimes from before when we start reading files.
         * If anything is modified concurrently, we'll consider the cache outdated. */

        if (path_cache) {
                paths = set_new(&path_hash_ops_free);
                if (!paths)
                        return log_oom();
        }

        /* Go over all our search paths, chase their symlinks and store the result in the
         * expanded_search_path list.
         *
         * This is important for cases where any of the unit directories itself are symlinks into other
         * directories and would therefore cause all of the unit files to be recognized as linked units.
         *
         * This is important for distributions such as NixOS where most paths in /etc/ are symlinks to some
         * other location on the filesystem (e.g.  into /nix/store/).
         *
         * Search paths are ordered by priority (highest first), and we need to maintain this order.
         * If a resolved path is already in the list, we don't need to include.
         *
         * Note that we build a list that contains both the original paths and the resolved symlinks:
         * we need the latter for the case where the directory is symlinked, as described above, and
         * the former for the case where some unit file alias is a dangling symlink that points to one
         * of the "original" directories (and can't be followed).
         */
        STRV_FOREACH(dir, lp->search_path) {
                _cleanup_free_ char *resolved_dir = NULL;

                r = strv_extend(&expanded_search_path, *dir);
                if (r < 0)
                        return log_oom();

                r = chase(*dir, NULL, 0, &resolved_dir, NULL);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_warning_errno(r, "Failed to resolve symlink %s, ignoring: %m", *dir);
                        continue;
                }

                if (strv_contains(expanded_search_path, resolved_dir))
                        continue;

                if (strv_consume(&expanded_search_path, TAKE_PTR(resolved_dir)) < 0)
                        return log_oom();
        }

        STRV_FOREACH(dir, lp->search_path) {
                _cleanup_closedir_ DIR *d = NULL;

                d = opendir(*dir);
                if (!d) {
                        if (errno != ENOENT)
                                log_warning_errno(errno, "Failed to open \"%s\", ignoring: %m", *dir);
                        continue;
                }

                FOREACH_DIRENT_ALL(de, d, log_warning_errno(errno, "Failed to read \"%s\", ignoring: %m", *dir)) {
                        _unused_ _cleanup_free_ char *_filename_free = NULL;
                        char *filename;
                        _cleanup_free_ char *dst = NULL;
                        bool symlink_to_dir = false;

                        /* We only care about valid units and dirs with certain suffixes, let's ignore the
                         * rest. */

                        if (de->d_type == DT_REG) {

                                /* Accept a regular file whose name is a valid unit file name. */
                                if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY))
                                        continue;

                        } else if (de->d_type == DT_DIR) {

                                if (!paths) /* Skip directories early unless path_cache is requested */
                                        continue;

                                r = directory_name_is_valid(de->d_name);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;

                        } else if (de->d_type == DT_LNK) {

                                /* Accept a symlink file whose name is a valid unit file name or
                                 * ending in .wants/, .requires/ or .d/. */

                                if (!unit_name_is_valid(de->d_name, UNIT_NAME_ANY)) {
                                        _cleanup_free_ char *target = NULL;

                                        if (!paths) /* Skip symlink to a directory early unless path_cache is requested */
                                                continue;

                                        r = directory_name_is_valid(de->d_name);
                                        if (r < 0)
                                                return r;
                                        if (r == 0)
                                                continue;

                                        r = readlinkat_malloc(dirfd(d), de->d_name, &target);
                                        if (r < 0) {
                                                log_warning_errno(r, "Failed to read symlink %s/%s, ignoring: %m",
                                                                  *dir, de->d_name);
                                                continue;
                                        }

                                        r = is_dir(target, /* follow= */ true);
                                        if (r <= 0)
                                                continue;

                                        symlink_to_dir = true;
                                }

                        } else
                                continue;

                        filename = path_join(*dir, de->d_name);
                        if (!filename)
                                return log_oom();

                        if (paths) {
                                r = set_put(paths, filename);
                                if (r < 0)
                                        return log_oom();
                                if (r == 0)
                                        _filename_free = filename; /* Make sure we free the filename. */
                        } else
                                _filename_free = filename; /* Make sure we free the filename. */

                        if (de->d_type == DT_DIR || (de->d_type == DT_LNK && symlink_to_dir))
                                continue;

                        assert(IN_SET(de->d_type, DT_REG, DT_LNK));

                        /* search_path is ordered by priority (highest first). If the name is already mapped
                         * to something (incl. itself), it means that we have already seen it, and we should
                         * ignore it here. */
                        if (hashmap_contains(ids, de->d_name))
                                continue;

                        if (de->d_type == DT_LNK) {
                                /* We don't explicitly check for alias loops here. unit_ids_map_get() which
                                 * limits the number of hops should be used to access the map. */

                                r = unit_file_resolve_symlink(lp->root_dir, expanded_search_path,
                                                              *dir, dirfd(d), de->d_name,
                                                              /* resolve_destination_target= */ false,
                                                              &dst);
                                if (r == -ENOMEM)
                                        return r;
                                if (r < 0)  /* we ignore other errors here */
                                        continue;

                        } else {
                                dst = TAKE_PTR(_filename_free); /* Grab the copy we made previously, if available. */
                                if (!dst) {
                                        dst = strdup(filename);
                                        if (!dst)
                                                return log_oom();
                                }

                                log_debug("%s: normal unit file: %s", __func__, dst);
                        }

                        _cleanup_free_ char *key = strdup(de->d_name);
                        if (!key)
                                return log_oom();

                        r = hashmap_ensure_put(&ids, &string_hash_ops_free_free, key, dst);
                        if (r < 0)
                                return log_warning_errno(r, "Failed to add entry to hashmap (%s%s%s): %m",
                                                         de->d_name, glyph(GLYPH_ARROW_RIGHT), dst);
                        key = dst = NULL;
                }
        }

        /* Let's also put the names in the reverse db. */
        const char *dummy, *src;
        HASHMAP_FOREACH_KEY(dummy, src, ids) {
                _cleanup_free_ char *inst = NULL, *dst = NULL;
                const char *dst_path;

                r = unit_ids_map_get(ids, src, &dst_path);
                if (r < 0)
                        continue;

                if (null_or_empty_path(dst_path) != 0)
                        continue;

                r = path_extract_filename(dst_path, &dst);
                if (r < 0) {
                        log_debug_errno(r, "Failed to extract file name from %s, ignoring: %m", dst_path);
                        continue;
                }

                /* If we have an symlink from an instance name to a template name, it is an alias just for
                 * this specific instance, foo@id.service ↔ template@id.service. */
                if (unit_name_is_valid(dst, UNIT_NAME_TEMPLATE)) {
                        UnitNameFlags t = unit_name_to_instance(src, &inst);
                        if (t < 0)
                                return log_error_errno(t, "Failed to extract instance part from %s: %m", src);
                        if (t == UNIT_NAME_INSTANCE) {
                                _cleanup_free_ char *dst_inst = NULL;

                                r = unit_name_replace_instance(dst, inst, &dst_inst);
                                if (r < 0) {
                                        /* This might happen e.g. if the combined length is too large.
                                         * Let's not make too much of a fuss. */
                                        log_debug_errno(r, "Failed to build alias name (%s + %s), ignoring: %m",
                                                        dst, inst);
                                        continue;
                                }

                                free_and_replace(dst, dst_inst);
                        }
                }

                r = string_strv_hashmap_put(&names, dst, src);
                if (r < 0)
                        return log_warning_errno(r, "Failed to add entry to hashmap (%s%s%s): %m",
                                                 dst, glyph(GLYPH_ARROW_RIGHT), src);
        }

        if (cache_timestamp_hash)
                *cache_timestamp_hash = timestamp_hash;

        hashmap_free_and_replace(*unit_ids_map, ids);
        hashmap_free_and_replace(*unit_names_map, names);
        if (path_cache)
                set_free_and_replace(*path_cache, paths);

        return 1;
}

int unit_file_remove_from_name_map(
                const LookupPaths *lp,
                uint64_t *cache_timestamp_hash,
                Hashmap **unit_ids_map,
                Hashmap **unit_names_map,
                Set **path_cache,
                const char *path) {

        int r;

        assert(path);

        /* This assumes the specified path is already removed, and drops the relevant entries from the maps. */

        /* If one of the lookup paths we are monitoring is already changed, let's rebuild the map. Then, the
         * new map should not contain entries relevant to the specified path. */
        r = unit_file_build_name_map(lp, cache_timestamp_hash, unit_ids_map, unit_names_map, path_cache);
        if (r != 0)
                return r;

        /* If not, drop the relevant entries. */

        _cleanup_free_ char *name = NULL;
        r = path_extract_filename(path, &name);
        if (r < 0)
                return log_warning_errno(r, "Failed to extract file name from '%s': %m", path);

        _unused_ _cleanup_free_ char *key = NULL;
        free(hashmap_remove2(*unit_ids_map, name, (void**) &key));
        string_strv_hashmap_remove(*unit_names_map, name, name);
        free(set_remove(*path_cache, path));

        return 0;
}

static int add_name(
                const char *unit_name,
                Set **names,
                const char *name) {
        int r;

        assert(names);
        assert(name);

        r = set_put_strdup(names, name);
        if (r < 0)
                return r;
        if (r > 0 && !streq(unit_name, name))
                log_debug("Unit %s has alias %s.", unit_name, name);
        return r;
}

static int add_names(
                Hashmap *unit_ids_map,
                Hashmap *unit_name_map,
                const char *unit_name,
                const char *fragment_basename,  /* Only set when adding additional names based on fragment path */
                UnitNameFlags name_type,
                const char *instance,
                Set **names,
                const char *name) {

        char **aliases;
        int r;

        assert(name_type == UNIT_NAME_PLAIN || instance);

        /* The unit has its own name if it's not a template. If we're looking at a fragment, the fragment
         * name (possibly with instance inserted), is also always one of the unit names. */
        if (name_type != UNIT_NAME_TEMPLATE) {
                r = add_name(unit_name, names, name);
                if (r < 0)
                        return r;
        }

        /* Add any aliases of the name to the set of names.
         *
         * We don't even need to know which fragment we will use. The unit_name_map should return the same
         * set of names for any of the aliases. */
        aliases = hashmap_get(unit_name_map, name);
        STRV_FOREACH(alias, aliases) {
                if (name_type == UNIT_NAME_INSTANCE && unit_name_is_valid(*alias, UNIT_NAME_TEMPLATE)) {
                        _cleanup_free_ char *inst = NULL;
                        const char *inst_fragment = NULL;

                        r = unit_name_replace_instance(*alias, instance, &inst);
                        if (r < 0)
                                return log_debug_errno(r, "Cannot build instance name %s + %s: %m",
                                                       *alias, instance);

                        /* Exclude any aliases that point in some other direction.
                         *
                         * See https://github.com/systemd/systemd/pull/13119#discussion_r308145418. */
                        r = unit_ids_map_get(unit_ids_map, inst, &inst_fragment);
                        if (r < 0 && !IN_SET(r, -ENOENT, -ENXIO))
                                return log_debug_errno(r, "Cannot find instance fragment %s: %m", inst);

                        if (inst_fragment &&
                            fragment_basename &&
                            !path_equal_filename(inst_fragment, fragment_basename)) {
                                log_debug("Instance %s has fragment %s and is not an alias of %s.",
                                          inst, inst_fragment, unit_name);
                                continue;
                        }

                        r = add_name(unit_name, names, inst);
                } else
                        r = add_name(unit_name, names, *alias);
                if (r < 0)
                        return r;
        }

        return 0;
}

int unit_file_find_fragment(
                Hashmap *unit_ids_map,
                Hashmap *unit_name_map,
                const char *unit_name,
                const char **ret_fragment_path,
                Set **ret_names) {

        const char *fragment = NULL;
        _cleanup_free_ char *template = NULL, *instance = NULL;
        _cleanup_set_free_ Set *names = NULL;
        int r;

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

        UnitNameFlags name_type = unit_name_to_instance(unit_name, &instance);
        if (name_type < 0)
                return name_type;

        if (ret_names) {
                r = add_names(unit_ids_map, unit_name_map, unit_name, NULL, name_type, instance, &names, unit_name);
                if (r < 0)
                        return r;
        }

        /* First try to load fragment under the original name */
        r = unit_ids_map_get(unit_ids_map, unit_name, &fragment);
        if (r < 0 && !IN_SET(r, -ENOENT, -ENXIO))
                return log_debug_errno(r, "Cannot load unit %s: %m", unit_name);

        if (!fragment && name_type == UNIT_NAME_INSTANCE) {
                /* Look for a fragment under the template name */

                r = unit_name_template(unit_name, &template);
                if (r < 0)
                        return log_debug_errno(r, "Failed to determine template name: %m");

                r = unit_ids_map_get(unit_ids_map, template, &fragment);
                if (r < 0 && !IN_SET(r, -ENOENT, -ENXIO))
                        return log_debug_errno(r, "Cannot load template %s: %m", template);
        }

        if (fragment && ret_names) {
                _cleanup_free_ char *fragment_basename = NULL;
                r = path_extract_filename(fragment, &fragment_basename);
                if (r < 0)
                        return r;

                if (!streq(fragment_basename, unit_name)) {
                        /* Add names based on the fragment name to the set of names */
                        r = add_names(unit_ids_map, unit_name_map, unit_name, fragment_basename, name_type, instance, &names, fragment_basename);
                        if (r < 0)
                                return r;
                }
        }

        *ret_fragment_path = fragment;
        if (ret_names)
                *ret_names = TAKE_PTR(names);

        return 0;
}

static const char * const rlmap[] = {
        "emergency", SPECIAL_EMERGENCY_TARGET,
        "-b",        SPECIAL_EMERGENCY_TARGET,
        "rescue",    SPECIAL_RESCUE_TARGET,
        "single",    SPECIAL_RESCUE_TARGET,
        "-s",        SPECIAL_RESCUE_TARGET,
        "s",         SPECIAL_RESCUE_TARGET,
        "S",         SPECIAL_RESCUE_TARGET,
        "1",         SPECIAL_RESCUE_TARGET,
        "2",         SPECIAL_MULTI_USER_TARGET,
        "3",         SPECIAL_MULTI_USER_TARGET,
        "4",         SPECIAL_MULTI_USER_TARGET,
        "5",         SPECIAL_GRAPHICAL_TARGET,
        NULL
};

static const char * const rlmap_initrd[] = {
        "emergency", SPECIAL_EMERGENCY_TARGET,
        "rescue",    SPECIAL_RESCUE_TARGET,
        NULL
};

const char* runlevel_to_target(const char *word) {
        const char * const *rlmap_ptr;

        if (!word)
                return NULL;

        if (in_initrd()) {
                word = startswith(word, "rd.");
                if (!word)
                        return NULL;

                rlmap_ptr = rlmap_initrd;
        } else
                rlmap_ptr = rlmap;

        STRV_FOREACH_PAIR(rl, target, rlmap_ptr)
                if (streq(word, *rl))
                        return *target;

        return NULL;
}
