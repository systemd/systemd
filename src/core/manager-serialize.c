/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dbus.h"
#include "dynamic-user.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "format-util.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "initrd-util.h"
#include "manager.h"
#include "manager-serialize.h"
#include "parse-util.h"
#include "serialize.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "unit-serialize.h"
#include "user-util.h"
#include "varlink.h"
#include "varlink-serialize.h"

int manager_open_serialization(Manager *m, FILE **ret_f) {
        assert(ret_f);

        return open_serialization_file("systemd-state", ret_f);
}

static bool manager_timestamp_shall_serialize(ManagerObjective o, ManagerTimestamp t) {
        if (!in_initrd() && o != MANAGER_SOFT_REBOOT)
                return true;

        /* The following timestamps only apply to the host system (or first boot in case of soft-reboot),
         * hence only serialize them there. */
        return !IN_SET(t,
                       MANAGER_TIMESTAMP_USERSPACE, MANAGER_TIMESTAMP_FINISH,
                       MANAGER_TIMESTAMP_SECURITY_START, MANAGER_TIMESTAMP_SECURITY_FINISH,
                       MANAGER_TIMESTAMP_GENERATORS_START, MANAGER_TIMESTAMP_GENERATORS_FINISH,
                       MANAGER_TIMESTAMP_UNITS_LOAD_START, MANAGER_TIMESTAMP_UNITS_LOAD_FINISH);
}

static void manager_serialize_uid_refs_internal(
                FILE *f,
                Hashmap *uid_refs,
                const char *field_name) {

        void *p, *k;

        assert(f);
        assert(field_name);

        /* Serialize the UID reference table. Or actually, just the IPC destruction flag of it, as
         * the actual counter of it is better rebuild after a reload/reexec. */

        HASHMAP_FOREACH_KEY(p, k, uid_refs) {
                uint32_t c;
                uid_t uid;

                uid = PTR_TO_UID(k);
                c = PTR_TO_UINT32(p);

                if (!(c & DESTROY_IPC_FLAG))
                        continue;

                (void) serialize_item_format(f, field_name, UID_FMT, uid);
        }
}

static void manager_serialize_uid_refs(Manager *m, FILE *f) {
        manager_serialize_uid_refs_internal(f, m->uid_refs, "destroy-ipc-uid");
}

static void manager_serialize_gid_refs(Manager *m, FILE *f) {
        manager_serialize_uid_refs_internal(f, m->gid_refs, "destroy-ipc-gid");
}

int manager_serialize(
                Manager *m,
                FILE *f,
                FDSet *fds,
                bool switching_root) {

        const char *t;
        Unit *u;
        int r;

        assert(m);
        assert(f);
        assert(fds);

        _cleanup_(manager_reloading_stopp) _unused_ Manager *reloading = manager_reloading_start(m);

        (void) serialize_item_format(f, "last-transaction-id", "%" PRIu64, m->last_transaction_id);

        (void) serialize_item_format(f, "current-job-id", "%" PRIu32, m->current_job_id);
        (void) serialize_item_format(f, "n-installed-jobs", "%u", m->n_installed_jobs);
        (void) serialize_item_format(f, "n-failed-jobs", "%u", m->n_failed_jobs);
        (void) serialize_bool(f, "taint-logged", m->taint_logged);
        (void) serialize_bool(f, "service-watchdogs", m->service_watchdogs);

        if (m->show_status_overridden != _SHOW_STATUS_INVALID)
                (void) serialize_item(f, "show-status-overridden",
                                      show_status_to_string(m->show_status_overridden));

        if (m->log_level_overridden)
                (void) serialize_item_format(f, "log-level-override", "%i", log_get_max_level());
        if (m->log_target_overridden)
                (void) serialize_item(f, "log-target-override", log_target_to_string(log_get_target()));

        (void) serialize_usec(f, "runtime-watchdog-overridden", m->watchdog_overridden[WATCHDOG_RUNTIME]);
        (void) serialize_usec(f, "reboot-watchdog-overridden", m->watchdog_overridden[WATCHDOG_REBOOT]);
        (void) serialize_usec(f, "kexec-watchdog-overridden", m->watchdog_overridden[WATCHDOG_KEXEC]);
        (void) serialize_usec(f, "pretimeout-watchdog-overridden", m->watchdog_overridden[WATCHDOG_PRETIMEOUT]);
        (void) serialize_item(f, "pretimeout-watchdog-governor-overridden", m->watchdog_pretimeout_governor_overridden);

        (void) serialize_item(f, "previous-objective", manager_objective_to_string(m->objective));
        (void) serialize_item_format(f, "soft-reboots-count", "%u", m->soft_reboots_count);

        for (ManagerTimestamp q = 0; q < _MANAGER_TIMESTAMP_MAX; q++) {
                _cleanup_free_ char *joined = NULL;

                if (!manager_timestamp_shall_serialize(m->objective, q))
                        continue;

                joined = strjoin(manager_timestamp_to_string(q), "-timestamp");
                if (!joined)
                        return log_oom();

                (void) serialize_dual_timestamp(f, joined, m->timestamps + q);
        }

        if (!switching_root)
                (void) serialize_strv(f, "env", m->client_environment);

        if (m->notify_fd >= 0) {
                r = serialize_fd(f, fds, "notify-fd", m->notify_fd);
                if (r < 0)
                        return r;

                (void) serialize_item(f, "notify-socket", m->notify_socket);
        }

        if (m->user_lookup_fds[0] >= 0) {
                r = serialize_fd_many(f, fds, "user-lookup", m->user_lookup_fds, 2);
                if (r < 0)
                        return r;
        }

        if (m->handoff_timestamp_fds[0] >= 0) {
                r = serialize_fd_many(f, fds, "handoff-timestamp-fds", m->handoff_timestamp_fds, 2);
                if (r < 0)
                        return r;
        }

        (void) serialize_ratelimit(f, "dump-ratelimit", &m->dump_ratelimit);
        (void) serialize_ratelimit(f, "reload-reexec-ratelimit", &m->reload_reexec_ratelimit);

        (void) serialize_id128(f, "bus-id", m->bus_id);
        bus_track_serialize(m->subscribed, f, "subscribed");

        r = dynamic_user_serialize(m, f, fds);
        if (r < 0)
                return r;

        manager_serialize_uid_refs(m, f);
        manager_serialize_gid_refs(m, f);

        r = exec_shared_runtime_serialize(m, f, fds);
        if (r < 0)
                return r;

        r = varlink_server_serialize(m->varlink_server, /* name = */ NULL, f, fds);
        if (r < 0)
                return r;

        r = varlink_server_serialize(m->metrics_varlink_server, "metrics", f, fds);
        if (r < 0)
                return r;

        (void) fputc('\n', f);

        HASHMAP_FOREACH_KEY(u, t, m->units) {
                if (u->id != t)
                        continue;

                r = unit_serialize_state(u, f, fds, switching_root);
                if (r < 0)
                        return r;
        }

        r = bus_fdset_add_all(m, fds);
        if (r < 0)
                return log_error_errno(r, "Failed to add bus sockets to serialization: %m");

        return 0;
}

static int manager_deserialize_one_unit(Manager *m, const char *name, FILE *f, FDSet *fds) {
        Unit *u;
        int r;

        r = manager_load_unit(m, name, NULL, NULL, &u);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_notice_errno(r, "Failed to load unit \"%s\", skipping deserialization: %m", name);

        r = unit_deserialize_state(u, f, fds);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_notice_errno(r, "Failed to deserialize unit \"%s\", skipping: %m", name);

        return 0;
}

static int manager_deserialize_units(Manager *m, FILE *f, FDSet *fds) {
        int r;

        for (;;) {
                _cleanup_free_ char *line = NULL;

                /* Start marker */
                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read serialization line: %m");
                if (r == 0)
                        break;

                r = manager_deserialize_one_unit(m, line, f, fds);
                if (r == -ENOMEM)
                        return r;
                if (r < 0) {
                        r = unit_deserialize_state_skip(f);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static void manager_deserialize_uid_refs_one_internal(
                Hashmap** uid_refs,
                const char *value) {

        uid_t uid;
        uint32_t c;
        int r;

        assert(uid_refs);
        assert(value);

        r = parse_uid(value, &uid);
        if (r < 0 || uid == 0) {
                log_debug("Unable to parse UID/GID reference serialization: %s", value);
                return;
        }

        if (hashmap_ensure_allocated(uid_refs, &trivial_hash_ops) < 0) {
                log_oom();
                return;
        }

        c = PTR_TO_UINT32(hashmap_get(*uid_refs, UID_TO_PTR(uid)));
        if (c & DESTROY_IPC_FLAG)
                return;

        c |= DESTROY_IPC_FLAG;

        r = hashmap_replace(*uid_refs, UID_TO_PTR(uid), UINT32_TO_PTR(c));
        if (r < 0) {
                log_debug_errno(r, "Failed to add UID/GID reference entry: %m");
                return;
        }
}

static void manager_deserialize_uid_refs_one(Manager *m, const char *value) {
        manager_deserialize_uid_refs_one_internal(&m->uid_refs, value);
}

static void manager_deserialize_gid_refs_one(Manager *m, const char *value) {
        manager_deserialize_uid_refs_one_internal(&m->gid_refs, value);
}

int manager_deserialize(Manager *m, FILE *f, FDSet *fds) {
        int r;

        assert(m);
        assert(f);

        if (DEBUG_LOGGING) {
                if (fdset_isempty(fds))
                        log_debug("No file descriptors passed");
                else {
                        int fd;

                        FDSET_FOREACH(fd, fds) {
                                _cleanup_free_ char *fn = NULL;

                                r = fd_get_path(fd, &fn);
                                if (r < 0)
                                        log_debug_errno(r, "Received serialized fd %i %s %m",
                                                        fd, glyph(GLYPH_ARROW_RIGHT));
                                else
                                        log_debug("Received serialized fd %i %s %s",
                                                  fd, glyph(GLYPH_ARROW_RIGHT), strna(fn));
                        }
                }
        }

        log_debug("Deserializing state...");

        /* If we are not in reload mode yet, enter it now. Not that this is recursive, a caller might already have
         * increased it to non-zero, which is why we just increase it by one here and down again at the end of this
         * call. */
        _cleanup_(manager_reloading_stopp) _unused_ Manager *reloading = manager_reloading_start(m);

        for (;;) {
                _cleanup_free_ char *l = NULL;
                const char *val;

                r = deserialize_read_line(f, &l);
                if (r < 0)
                        return r;
                if (r == 0) /* eof or end marker */
                        break;

                if ((val = startswith(l, "last-transaction-id="))) {
                        uint64_t id;

                        if (safe_atou64(val, &id) < 0)
                                log_notice("Failed to parse last transaction id value '%s', ignoring.", val);
                        else
                                m->last_transaction_id = MAX(m->last_transaction_id, id);

                } else if ((val = startswith(l, "current-job-id="))) {
                        uint32_t id;

                        if (safe_atou32(val, &id) < 0)
                                log_notice("Failed to parse current job id value '%s', ignoring.", val);
                        else
                                m->current_job_id = MAX(m->current_job_id, id);

                } else if ((val = startswith(l, "n-installed-jobs="))) {
                        uint32_t n;

                        if (safe_atou32(val, &n) < 0)
                                log_notice("Failed to parse installed jobs counter '%s', ignoring.", val);
                        else
                                m->n_installed_jobs += n;

                } else if ((val = startswith(l, "n-failed-jobs="))) {
                        uint32_t n;

                        if (safe_atou32(val, &n) < 0)
                                log_notice("Failed to parse failed jobs counter '%s', ignoring.", val);
                        else
                                m->n_failed_jobs += n;

                } else if ((val = startswith(l, "taint-logged="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                log_notice("Failed to parse taint-logged flag '%s', ignoring.", val);
                        else
                                m->taint_logged = m->taint_logged || r;

                } else if ((val = startswith(l, "service-watchdogs="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                log_notice("Failed to parse service-watchdogs flag '%s', ignoring.", val);
                        else
                                m->service_watchdogs = r;

                } else if ((val = startswith(l, "show-status-overridden="))) {
                        ShowStatus s;

                        s = show_status_from_string(val);
                        if (s < 0)
                                log_notice("Failed to parse show-status-overridden flag '%s', ignoring.", val);
                        else
                                manager_override_show_status(m, s, "deserialize");

                } else if ((val = startswith(l, "log-level-override="))) {
                        int level;

                        level = log_level_from_string(val);
                        if (level < 0)
                                log_notice("Failed to parse log-level-override value '%s', ignoring.", val);
                        else
                                manager_override_log_level(m, level);

                } else if ((val = startswith(l, "log-target-override="))) {
                        LogTarget target;

                        target = log_target_from_string(val);
                        if (target < 0)
                                log_notice("Failed to parse log-target-override value '%s', ignoring.", val);
                        else
                                manager_override_log_target(m, target);

                } else if ((val = startswith(l, "runtime-watchdog-overridden="))) {
                        usec_t t;

                        if (deserialize_usec(val, &t) < 0)
                                log_notice("Failed to parse runtime-watchdog-overridden value '%s', ignoring.", val);
                        else
                                manager_override_watchdog(m, WATCHDOG_RUNTIME, t);

                } else if ((val = startswith(l, "reboot-watchdog-overridden="))) {
                        usec_t t;

                        if (deserialize_usec(val, &t) < 0)
                                log_notice("Failed to parse reboot-watchdog-overridden value '%s', ignoring.", val);
                        else
                                manager_override_watchdog(m, WATCHDOG_REBOOT, t);

                } else if ((val = startswith(l, "kexec-watchdog-overridden="))) {
                        usec_t t;

                        if (deserialize_usec(val, &t) < 0)
                                log_notice("Failed to parse kexec-watchdog-overridden value '%s', ignoring.", val);
                        else
                                manager_override_watchdog(m, WATCHDOG_KEXEC, t);

                } else if ((val = startswith(l, "pretimeout-watchdog-overridden="))) {
                        usec_t t;

                        if (deserialize_usec(val, &t) < 0)
                                log_notice("Failed to parse pretimeout-watchdog-overridden value '%s', ignoring.", val);
                        else
                                manager_override_watchdog(m, WATCHDOG_PRETIMEOUT, t);

                } else if ((val = startswith(l, "pretimeout-watchdog-governor-overridden="))) {
                        r = free_and_strdup(&m->watchdog_pretimeout_governor_overridden, val);
                        if (r < 0)
                                return r;

                } else if ((val = startswith(l, "env="))) {
                        r = deserialize_environment(val, &m->client_environment);
                        if (r < 0)
                                log_notice_errno(r, "Failed to parse environment entry: \"%s\", ignoring: %m", val);

                } else if ((val = startswith(l, "notify-fd="))) {
                        int fd;

                        fd = deserialize_fd(fds, val);
                        if (fd >= 0) {
                                m->notify_event_source = sd_event_source_disable_unref(m->notify_event_source);
                                close_and_replace(m->notify_fd, fd);
                        }

                } else if ((val = startswith(l, "notify-socket="))) {
                        r = free_and_strdup(&m->notify_socket, val);
                        if (r < 0)
                                return r;

                } else if ((val = startswith(l, "user-lookup="))) {

                        m->user_lookup_event_source = sd_event_source_disable_unref(m->user_lookup_event_source);
                        safe_close_pair(m->user_lookup_fds);

                        r = deserialize_fd_many(fds, val, 2, m->user_lookup_fds);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse user-lookup fds: \"%s\", ignoring: %m", val);

                } else if ((val = startswith(l, "handoff-timestamp-fds="))) {

                        m->handoff_timestamp_event_source = sd_event_source_disable_unref(m->handoff_timestamp_event_source);
                        safe_close_pair(m->handoff_timestamp_fds);

                        r = deserialize_fd_many(fds, val, 2, m->handoff_timestamp_fds);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse handoff-timestamp fds: \"%s\", ignoring: %m", val);

                } else if ((val = startswith(l, "dynamic-user=")))
                        dynamic_user_deserialize_one(m, val, fds, NULL);
                else if ((val = startswith(l, "destroy-ipc-uid=")))
                        manager_deserialize_uid_refs_one(m, val);
                else if ((val = startswith(l, "destroy-ipc-gid=")))
                        manager_deserialize_gid_refs_one(m, val);
                else if ((val = startswith(l, "exec-runtime=")))
                        (void) exec_shared_runtime_deserialize_one(m, val, fds);
                else if ((val = startswith(l, "bus-id="))) {

                        r = sd_id128_from_string(val, &m->deserialized_bus_id);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "subscribed="))) {

                        r = strv_extend(&m->subscribed_as_strv, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "varlink-server-metrics-"))) {
                        if (m->objective == MANAGER_RELOAD)
                                /* We don't destroy varlink server on daemon-reload (in contrast to reexec) -> skip! */
                                continue;

                        r = manager_setup_varlink_metrics_server(m);
                        if (r < 0)
                                log_warning_errno(r, "Failed to setup metrics varlink server, ignoring: %m");
                        else
                                (void) varlink_server_deserialize_one(m->metrics_varlink_server, val, fds);

                } else if ((val = startswith(l, "varlink-server-"))) {
                        if (m->objective == MANAGER_RELOAD)
                                /* We don't destroy varlink server on daemon-reload (in contrast to reexec) -> skip! */
                                continue;

                        r = manager_setup_varlink_server(m);
                        if (r < 0)
                                log_warning_errno(r, "Failed to setup varlink server, ignoring: %m");
                        else
                                (void) varlink_server_deserialize_one(m->varlink_server, val, fds);

                } else if ((val = startswith(l, "dump-ratelimit=")))
                        deserialize_ratelimit(&m->dump_ratelimit, "dump-ratelimit", val);
                else if ((val = startswith(l, "reload-reexec-ratelimit=")))
                        deserialize_ratelimit(&m->reload_reexec_ratelimit, "reload-reexec-ratelimit", val);
                else if ((val = startswith(l, "soft-reboots-count="))) {
                        unsigned n;

                        if (safe_atou(val, &n) < 0)
                                log_notice("Failed to parse soft reboots counter '%s', ignoring.", val);
                        else
                                m->soft_reboots_count = n;
                } else if ((val = startswith(l, "previous-objective="))) {
                        ManagerObjective objective;

                        objective = manager_objective_from_string(val);
                        if (objective < 0)
                                log_notice("Failed to parse previous objective '%s', ignoring.", val);
                        else
                                m->previous_objective = objective;

                } else {
                        ManagerTimestamp q;

                        for (q = 0; q < _MANAGER_TIMESTAMP_MAX; q++) {
                                val = startswith(l, manager_timestamp_to_string(q));
                                if (!val)
                                        continue;

                                val = startswith(val, "-timestamp=");
                                if (val)
                                        break;
                        }

                        if (q < _MANAGER_TIMESTAMP_MAX) /* found it */
                                (void) deserialize_dual_timestamp(val, m->timestamps + q);
                        else if (!STARTSWITH_SET(l, "kdbus-fd=", "honor-device-enumeration=", "ready-sent=", "cgroups-agent-fd=")) /* ignore deprecated values */
                                log_notice("Unknown serialization item '%s', ignoring.", l);
                }
        }

        return manager_deserialize_units(m, f, fds);
}
