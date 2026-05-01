/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "errno-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "json-util.h"
#include "log.h"
#include "luo.h"
#include "luo-util.h"
#include "manager.h"
#include "serialize.h"
#include "service.h"
#include "unit.h"
#include "unit-name.h"

static int luo_read_mapping(int session_fd, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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

        r = sd_json_parse_file(f, "luo-mapping", SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse LUO mapping JSON: %m");

        *ret = TAKE_PTR(v);
        return 0;
}

static void luo_session_finishp(int *fd) {
        assert(fd);

        if (*fd >= 0)
                (void) luo_session_finish(*fd);
        safe_close(*fd);
}

int manager_luo_restore_fd_stores(Manager *m) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mapping = NULL;
        _cleanup_close_ int device_fd = -EBADF;
        _cleanup_(luo_session_finishp) int session_fd = -EBADF;
        const char *unit_id;
        sd_json_variant *fds_json;
        int r, n_total = 0;

        assert(m);

        if (MANAGER_IS_USER(m))
                return 0;

        device_fd = luo_open_device();
        if (ERRNO_IS_NEG_DEVICE_ABSENT(device_fd)) {
                log_debug_errno(device_fd, "No /dev/liveupdate device found, skipping LUO fd store restoration.");
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

        /* Retrieve all fds from the session and dispatch each to the named unit, eagerly loading the
         * unit if necessary. */
        JSON_VARIANT_OBJECT_FOREACH(unit_id, fds_json, mapping) {
                sd_json_variant *entry;

                if (!unit_name_is_valid(unit_id, UNIT_NAME_ANY)) {
                        log_warning("Invalid unit name '%s' in LUO mapping, skipping.", unit_id);
                        continue;
                }

                if (!sd_json_variant_is_array(fds_json)) {
                        log_warning("LUO mapping for unit '%s' is not a JSON array, skipping.", unit_id);
                        continue;
                }

                JSON_VARIANT_ARRAY_FOREACH(entry, fds_json) {
                        struct {
                                const char *type;
                                const char *name;
                                uint64_t token;
                        } p = {
                                .token = UINT64_MAX,
                        };

                        static const sd_json_dispatch_field dispatch_table[] = {
                                { "type",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, type),         SD_JSON_MANDATORY },
                                { "name",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, name),         SD_JSON_MANDATORY },
                                { "token",       _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       voffsetof(p, token),        0                 },
                                {}
                        };

                        _cleanup_close_ int fd = -EBADF;

                        r = sd_json_dispatch(entry, dispatch_table, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG|SD_JSON_WARNING, &p);
                        if (r < 0)
                                continue;

                        if (streq(p.type, "fd")) {
                                if (p.token == UINT64_MAX) {
                                        log_warning("LUO mapping for unit '%s' fd '%s': missing 'token' field.", unit_id, p.name);
                                        continue;
                                }
                                if (p.token == LUO_MAPPING_INDEX) {
                                        log_warning("LUO mapping for unit '%s' fd '%s': token %" PRIu64 " is reserved for the mapping memfd.", unit_id, p.name, p.token);
                                        continue;
                                }

                                fd = luo_session_retrieve_fd(session_fd, p.token);
                                if (fd < 0) {
                                        log_warning_errno(fd, "Failed to retrieve LUO fd for unit '%s' name '%s' token %" PRIu64 ": %m",
                                                          unit_id, p.name, p.token);
                                        continue;
                                }
                        } else {
                                log_warning("LUO mapping for unit '%s' fd '%s': unknown type '%s', skipping.",
                                            unit_id, p.name, p.type);
                                continue;
                        }

                        r = manager_dispatch_external_fd_to_unit(m, unit_id, p.name, /* index= */ 0, TAKE_FD(fd), "LUO");
                        if (r > 0)
                                n_total++;
                        /* On error fd is already consumed by manager_dispatch_external_fd_to_unit. */
                }
        }

        if (n_total > 0)
                log_debug("Restored %d fd(s) total from LUO session.", n_total);

        return n_total;
}

int manager_luo_serialize_fd_stores(Manager *m, FILE **ret_f, FDSet **ret_fds) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *root = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_fdset_free_ FDSet *fds = NULL;
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

        /* Build a JSON object: { "unit_id": [ { "type": "fd", "name": "...", "fd": N }, ... ], ... }
         * This is passed to systemd-shutdown which will create a LUO session and preserve the fds. */
        HASHMAP_FOREACH(u, m->units) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entries = NULL;
                Service *s;

                if (u->type != UNIT_SERVICE)
                        continue;

                s = SERVICE(u);

                if (s->fd_store_preserve_mode != EXEC_PRESERVE_YES)
                        continue;

                if (!s->fd_store)
                        continue;

                LIST_FOREACH(fd_store, fs, s->fd_store) {
                        int copy;

                        copy = fdset_put_dup(fds, fs->fd);
                        if (copy < 0)
                                return log_error_errno(copy, "Failed to duplicate fd for LUO serialization: %m");

                        r = sd_json_variant_append_arraybo(
                                        &entries,
                                        SD_JSON_BUILD_PAIR_STRING("type", "fd"),
                                        SD_JSON_BUILD_PAIR_STRING("name", fs->fdname),
                                        SD_JSON_BUILD_PAIR_INTEGER("fd", copy));
                        if (r < 0)
                                return log_error_errno(r, "Failed to build JSON for LUO serialization: %m");

                        n_serialized++;
                }

                r = sd_json_variant_set_field(&root, u->id, entries);
                if (r < 0)
                        return log_error_errno(r, "Failed to add unit to LUO serialization JSON: %m");
        }

        if (n_serialized == 0) {
                log_debug("No fd store entries to serialize for LUO.");
                *ret_f = NULL;
                *ret_fds = NULL;
                return 0;
        }

        r = open_serialization_file("luo-fd-store", &f);
        if (r < 0)
                return log_error_errno(r, "Failed to create LUO serialization file: %m");

        r = sd_json_variant_dump(root, /* flags= */ 0, f, /* prefix= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to dump LUO serialization JSON: %m");

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
