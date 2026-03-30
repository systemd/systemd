/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "cgroup.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "luo-util.h"
#include "luo.h"
#include "manager.h"
#include "path-util.h"
#include "serialize.h"
#include "set.h"
#include "service.h"
#include "unit.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(ServiceExtraFD*, service_extra_fd_free);

static void service_extra_fd_set_free(Set *s) {
        ServiceExtraFD *fd;

        if (!s)
                return;

        while ((fd = set_steal_first(s)))
                service_extra_fd_free(fd);

        set_free(s);
}

void manager_luo_held_fds_clear(Manager *m) {
        Set *s;

        assert(m);

        while ((s = hashmap_steal_first(m->luo_held_fds)))
                service_extra_fd_set_free(s);

        m->luo_held_fds = hashmap_free(m->luo_held_fds);
}

static int luo_read_mapping(int session_fd, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *text = NULL;
        _cleanup_close_ int mapping_fd = -EBADF;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(session_fd >= 0);
        assert(ret);

        mapping_fd = luo_session_retrieve_fd(session_fd, LUO_MAPPING_INDEX);
        if (mapping_fd < 0)
                return log_warning_errno(mapping_fd, "Failed to retrieve LUO mapping fd (fd_index 0): %m");

        r = fdopen_independent(mapping_fd, "r", &f);
        if (r < 0)
                return log_warning_errno(r, "Failed to open LUO mapping fd for reading: %m");

        r = read_full_stream(f, &text, /* ret_size= */ NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to read LUO mapping: %m");

        r = sd_json_parse(text, SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse LUO mapping JSON: %m");

        *ret = TAKE_PTR(v);
        return 0;
}

static Unit *manager_find_unit_by_cgroup_path(Manager *m, const char *cgroup_path) {
        Unit *u;

        assert(m);
        assert(cgroup_path);

        HASHMAP_FOREACH(u, m->units) {
                _cleanup_free_ char *path = NULL;

                if (unit_get_cgroup_path_with_fallback(u, &path) < 0)
                        continue;

                if (path_equal(path, cgroup_path))
                        return u;
        }

        return NULL;
}

static int luo_hold_fd(Manager *m, const char *cgroup_path, const char *fdname, int fd) {
        _cleanup_(service_extra_fd_freep) ServiceExtraFD *entry = NULL;
        Set *s;
        int r;

        assert(m);
        assert(cgroup_path);
        assert(fdname);
        assert(fd >= 0);

        entry = new(ServiceExtraFD, 1);
        if (!entry)
                return log_oom();

        *entry = (ServiceExtraFD) {
                .fd = fd,
                .fdname = strdup(fdname),
        };

        if (!entry->fdname)
                return log_oom();

        s = hashmap_get(m->luo_held_fds, cgroup_path);
        if (!s) {
                _cleanup_set_free_ Set *new_set = NULL;
                _cleanup_free_ char *key = NULL;

                new_set = set_new(NULL);
                if (!new_set)
                        return log_oom();

                key = strdup(cgroup_path);
                if (!key)
                        return log_oom();

                r = hashmap_ensure_put(&m->luo_held_fds, &string_hash_ops_free, key, new_set);
                if (r < 0)
                        return log_oom();

                s = TAKE_PTR(new_set);
                TAKE_PTR(key);
        }

        r = set_put(s, entry);
        if (r < 0)
                return log_oom();

        TAKE_PTR(entry);
        return 0;
}

static int luo_try_restore_fd(Manager *m, const char *cgroup_path, const char *fdname, int fd) {
        Unit *u;
        Service *s;
        int r;

        assert(m);
        assert(cgroup_path);
        assert(fdname);
        assert(fd >= 0);

        u = manager_find_unit_by_cgroup_path(m, cgroup_path);
        if (!u)
                return -ENOENT; /* unit not found, caller should hold the fd */

        if (u->type != UNIT_SERVICE) {
                log_warning("LUO mapping references cgroup '%s' which is not a service (unit '%s'), skipping.", cgroup_path, u->id);
                return -EINVAL;
        }

        s = SERVICE(u);

        r = service_add_fd_store(s, fd, fdname, /* do_poll= */ true);
        if (r < 0)
                return log_warning_errno(r, "Failed to add LUO fd to fd store of unit '%s' name '%s': %m",
                                         u->id, fdname);

        log_debug("Restored LUO fd '%s' for unit '%s'.", fdname, u->id);
        return 1; /* fd consumed */
}

int manager_luo_restore_fd_stores(Manager *m) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mapping = NULL;
        _cleanup_close_ int device_fd = -EBADF, session_fd = -EBADF;
        const char *cgroup_path;
        sd_json_variant *fds_json;
        int r, n_total = 0;

        assert(m);

        if (MANAGER_IS_USER(m))
                return 0;

        device_fd = luo_open_device();
        if (IN_SET(device_fd, -ENOENT, -ENODEV)) {
                log_debug("No /dev/liveupdate device found, skipping LUO fd store restoration.");
                return 0;
        }
        if (device_fd < 0)
                return log_warning_errno(device_fd, "Failed to open /dev/liveupdate: %m");

        session_fd = luo_retrieve_session(device_fd, LUO_SESSION_NAME);
        if (session_fd == -ENOENT) {
                log_debug("No LUO session '%s' found, skipping fd store restoration.", LUO_SESSION_NAME);
                return 0;
        }
        if (session_fd < 0)
                return log_warning_errno(session_fd, "Failed to retrieve LUO session '%s': %m", LUO_SESSION_NAME);

        log_debug("Found LUO session '%s', restoring fd stores.", LUO_SESSION_NAME);

        r = luo_read_mapping(session_fd, &mapping);
        if (r < 0)
                return r;

        /* Retrieve all fds from the session. For units that exist, add to their fd store directly.
         * For units not yet loaded (e.g. in initrd before switch-root), hold the fds until later. */
        JSON_VARIANT_OBJECT_FOREACH(cgroup_path, fds_json, mapping) {
                sd_json_variant *entry;

                if (!sd_json_variant_is_array(fds_json)) {
                        log_warning("LUO mapping for cgroup '%s' is not a JSON array, skipping.", cgroup_path);
                        continue;
                }

                JSON_VARIANT_ARRAY_FOREACH(entry, fds_json) {
                        _cleanup_close_ int fd = -EBADF;
                        sd_json_variant *type_json, *name_json;
                        const char *type, *fdname;

                        type_json = sd_json_variant_by_key(entry, "type");
                        name_json = sd_json_variant_by_key(entry, "name");
                        if (!type_json || !name_json)
                                continue;

                        type = sd_json_variant_string(type_json);
                        fdname = sd_json_variant_string(name_json);

                        if (streq(type, "fd")) {
                                sd_json_variant *idx_json = sd_json_variant_by_key(entry, "fd_index");
                                if (!idx_json || !sd_json_variant_is_unsigned(idx_json)) {
                                        log_warning("LUO mapping for cgroup '%s' fd '%s': missing or invalid fd_index.", cgroup_path, fdname);
                                        continue;
                                }

                                uint64_t idx = sd_json_variant_unsigned(idx_json);
                                fd = luo_session_retrieve_fd(session_fd, idx);
                                if (fd < 0) {
                                        log_warning_errno(fd, "Failed to retrieve LUO fd for cgroup '%s' name '%s' fd_index %" PRIu64 ": %m",
                                                          cgroup_path, fdname, idx);
                                        continue;
                                }
                        } else {
                                log_warning("LUO mapping for cgroup '%s' fd '%s': unknown type '%s', skipping.",
                                            cgroup_path, fdname, type);
                                continue;
                        }

                        r = luo_try_restore_fd(m, cgroup_path, fdname, fd);
                        if (r == -ENOENT) {
                                /* Unit not found yet, hold the fd for after switch-root */
                                log_debug("LUO: holding fd '%s' for cgroup '%s' until unit is loaded.", fdname, cgroup_path);
                                r = luo_hold_fd(m, cgroup_path, fdname, TAKE_FD(fd));
                                if (r < 0)
                                        continue;
                        } else if (r < 0)
                                continue;
                        else {
                                TAKE_FD(fd); /* consumed by luo_try_restore_fd */
                                n_total++;
                        }
                }
        }

        r = luo_session_finish(session_fd);
        if (r < 0)
                return log_warning_errno(r, "Failed to finish LUO session '%s': %m", LUO_SESSION_NAME);

        if (n_total > 0)
                log_debug("Restored %d fd(s) total from LUO session.", n_total);

        if (!hashmap_isempty(m->luo_held_fds))
                log_debug("Holding LUO fd(s) for units not yet loaded.");

        return n_total;
}

int manager_luo_process_held_fds(Manager *m) {
        int n_restored = 0;

        assert(m);

        if (hashmap_isempty(m->luo_held_fds)) {
                log_debug("No LUO held fds to process.");
                return 0;
        }

        log_debug("Processing pending LUO held fd(s)...");

        const char *cgroup_path;
        Set *s;

        HASHMAP_FOREACH_KEY(s, cgroup_path, m->luo_held_fds) {
                ServiceExtraFD *entry;

                SET_FOREACH(entry, s) {
                        int r = luo_try_restore_fd(m, cgroup_path, entry->fdname, entry->fd);
                        if (r == -ENOENT)
                                continue; /* still not loaded */

                        if (r >= 0) {
                                entry->fd = -EBADF;
                                n_restored++;
                        }

                        set_remove(s, entry);
                        service_extra_fd_free(entry);
                }

                if (set_isempty(s)) {
                        hashmap_remove(m->luo_held_fds, cgroup_path);
                        set_free(s);
                }
        }

        if (n_restored > 0)
                log_debug("Restored %d held LUO fd(s).", n_restored);

        return n_restored;
}

int manager_luo_try_restore_held_fds_for_unit(Unit *u) {
        _cleanup_free_ char *cgroup_path = NULL;
        Set *s;
        int r, n_restored = 0;

        assert(u);
        assert(u->manager);

        if (hashmap_isempty(u->manager->luo_held_fds))
                return 0;

        r = unit_get_cgroup_path_with_fallback(u, &cgroup_path);
        if (r < 0)
                return 0;

        s = hashmap_get(u->manager->luo_held_fds, cgroup_path);
        if (!s)
                return 0;

        ServiceExtraFD *entry;
        SET_FOREACH(entry, s) {
                r = luo_try_restore_fd(u->manager, cgroup_path, entry->fdname, entry->fd);
                if (r >= 0) {
                        entry->fd = -EBADF;
                        n_restored++;
                }

                set_remove(s, entry);
                service_extra_fd_free(entry);
        }

        /* All fds for this cgroup consumed, remove the hashmap entry */
        hashmap_remove(u->manager->luo_held_fds, cgroup_path);
        set_free(s);

        if (n_restored > 0)
                log_unit_debug(u, "Restored %d held LUO fd(s).", n_restored);

        return n_restored;
}

int manager_luo_serialize_held_fds(Manager *m, FILE *f, FDSet *fds) {
        const char *cgroup_path;
        Set *s;

        assert(m);
        assert(f);
        assert(fds);

        HASHMAP_FOREACH_KEY(s, cgroup_path, m->luo_held_fds) {
                ServiceExtraFD *entry;

                SET_FOREACH(entry, s) {
                        _cleanup_free_ char *escaped_path = NULL, *escaped_name = NULL;
                        int copy;

                        copy = fdset_put_dup(fds, entry->fd);
                        if (copy < 0)
                                return log_error_errno(copy, "Failed to dup LUO held fd for serialization: %m");

                        escaped_path = cescape(cgroup_path);
                        escaped_name = cescape(entry->fdname);
                        if (!escaped_path || !escaped_name)
                                return log_oom();

                        (void) serialize_item_format(f, "luo-held-fd", "%i %s %s", copy, escaped_path, escaped_name);
                }
        }

        return 0;
}

int manager_luo_deserialize_held_fd(Manager *m, const char *value, FDSet *fds) {
        _cleanup_free_ char *fd_str = NULL, *escaped_path = NULL, *escaped_name = NULL;
        _cleanup_free_ char *cgroup_path = NULL, *fdname = NULL;
        int fd, r;

        assert(m);
        assert(value);
        assert(fds);

        const char *p = value;
        r = extract_first_word(&p, &fd_str, NULL, 0);
        if (r <= 0)
                return log_warning_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL), "Failed to parse LUO held fd: %m");

        r = extract_first_word(&p, &escaped_path, NULL, 0);
        if (r <= 0)
                return log_warning_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL), "Failed to parse LUO held fd cgroup path: %m");

        r = extract_first_word(&p, &escaped_name, NULL, 0);
        if (r <= 0)
                return log_warning_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL), "Failed to parse LUO held fd name: %m");

        fd = deserialize_fd(fds, fd_str);
        if (fd < 0)
                return log_warning_errno(fd, "Failed to deserialize LUO held fd: %m");

        if (cunescape(escaped_path, 0, &cgroup_path) < 0)
                return log_oom();
        if (cunescape(escaped_name, 0, &fdname) < 0) {
                safe_close(fd);
                return log_oom();
        }

        r = luo_hold_fd(m, cgroup_path, fdname, fd);
        if (r < 0)
                return r;

        return 0;
}

int manager_luo_serialize_fd_stores(Manager *m, FILE **ret_f, FDSet **ret_fds) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *root = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_fdset_free_ FDSet *fds = NULL;
        _cleanup_free_ char *text = NULL;
        Unit *u;
        int r, n_serialized = 0;

        assert(m);
        assert(ret_f);
        assert(ret_fds);

        if (MANAGER_IS_USER(m)) {
                *ret_f = NULL;
                *ret_fds = NULL;
                return 0;
        }

        fds = fdset_new();
        if (!fds)
                return log_oom();

        /* Build a JSON object: { "cgroup_path": [ { "type": "fd", "name": "...", "fd_index": N }, ... ], ... }
         * This is passed to systemd-shutdown which will create a LUO session and preserve the fds. */
        HASHMAP_FOREACH(u, m->units) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entries = NULL;
                _cleanup_free_ char *cgroup_path = NULL;
                Service *s;

                if (u->type != UNIT_SERVICE)
                        continue;

                s = SERVICE(u);

                if (s->fd_store_preserve_mode != EXEC_PRESERVE_YES)
                        continue;

                if (!s->fd_store)
                        continue;

                r = unit_get_cgroup_path_with_fallback(u, &cgroup_path);
                if (r < 0) {
                        log_unit_warning_errno(u, r, "Failed to get cgroup path, skipping LUO serialization: %m");
                        continue;
                }

                LIST_FOREACH(fd_store, fs, s->fd_store) {
                        int copy;

                        copy = fdset_put_dup(fds, fs->fd);
                        if (copy < 0)
                                return log_error_errno(copy, "Failed to duplicate fd for LUO serialization: %m");

                        r = sd_json_variant_append_arraybo(
                                        &entries,
                                        SD_JSON_BUILD_PAIR_STRING("type", "fd"),
                                        SD_JSON_BUILD_PAIR_STRING("name", fs->fdname),
                                        SD_JSON_BUILD_PAIR_INTEGER("fd_index", copy));
                        if (r < 0)
                                return log_error_errno(r, "Failed to build JSON for LUO serialization: %m");

                        n_serialized++;
                }

                r = sd_json_variant_set_field(&root, cgroup_path, entries);
                if (r < 0)
                        return log_error_errno(r, "Failed to add unit to LUO serialization JSON: %m");
        }

        if (n_serialized == 0) {
                log_debug("No fd store entries to serialize for LUO.");
                *ret_f = NULL;
                *ret_fds = NULL;
                return 0;
        }

        r = sd_json_variant_format(root, /* flags= */ 0, &text);
        if (r < 0)
                return log_error_errno(r, "Failed to format LUO serialization JSON: %m");

        r = open_serialization_file("luo-fd-store", &f);
        if (r < 0)
                return log_error_errno(r, "Failed to create LUO serialization file: %m");

        fputs(text, f);

        r = finish_serialization_file(f);
        if (r < 0)
                return log_error_errno(r, "Failed to finish LUO serialization file: %m");

        r = fd_cloexec(fileno(f), false);
        if (r < 0)
                return log_error_errno(r, "Failed to disable O_CLOEXEC for LUO serialization: %m");

        r = fdset_cloexec(fds, false);
        if (r < 0)
                return log_error_errno(r, "Failed to disable O_CLOEXEC for LUO serialization fds: %m");

        log_info("Serialized %d fd store entries for LUO.", n_serialized);

        *ret_f = TAKE_PTR(f);
        *ret_fds = TAKE_PTR(fds);
        return n_serialized;
}
