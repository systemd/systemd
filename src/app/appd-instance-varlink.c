/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "appd-instance.h"
#include "appd-instance-varlink.h"
#include "appd-manager.h"
#include "format-util.h"
#include "json-util.h"
#include "log.h"
#include "path-lookup.h"
#include "pidref.h"
#include "socket-util.h"
#include "string-util.h"
#include "unit-name.h"
#include "varlink-util.h"
#include "varlink-io.systemd.AppInstance.h"

static int start_transient_scope(const char *unit_name, PidRef *peer) {
        int r;

        _cleanup_free_ char *systemd_address = NULL;
        r = xdg_user_runtime_dir("systemd/io.systemd.Manager", &systemd_address);
        if (r < 0)
                return log_debug_errno(r, "Failed to get io.systemd.Manager address: %m");

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, systemd_address);
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to io.systemd.Manager: %m");

        {
                _cleanup_free_ char *link_description = NULL;
                if (asprintf(&link_description, "vl-start-transient-" PID_FMT, peer->pid) < 0)
                        return log_oom_debug();
                (void) sd_varlink_set_description(vl, link_description);
        }

        sd_json_variant *reply;
        const char *error_id;
        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.Unit.StartTransient",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_OBJECT("context",
                                        SD_JSON_BUILD_PAIR_STRING("ID", unit_name),
                                        SD_JSON_BUILD_PAIR_OBJECT("Scope",
                                                        SD_JSON_BUILD_PAIR_ARRAY("PIDs", JSON_BUILD_PIDREF(peer)))),
                        SD_JSON_BUILD_PAIR_STRING("mode", "fail"),
                        SD_JSON_BUILD_PAIR_BOOLEAN("notifyJobChanges", true));
        if (r < 0)
                return log_debug_errno(r, "Failed to issue io.systemd.Unit.StartTransient() call: %m");

        if (error_id)
                return log_debug_errno(sd_varlink_error_to_errno(error_id, reply),
                                       "io.systemd.Unit.StartTransient() failed for PID " PID_FMT ": %s (%m)",
                                       peer->pid, error_id);

        /* The call succeeded, but the job may have failed. Let's check */
        sd_json_variant *job = sd_json_variant_by_key(reply, "job");
        if (!job)
                return -EPROTO;
        const char *job_state = sd_json_variant_string(sd_json_variant_by_key(job, "State"));
        if (!job_state || !streq(job_state, "finished"))
                return -EPROTO;
        const char *job_result = sd_json_variant_string(sd_json_variant_by_key(job, "Result"));
        if (!job_result)
                return -EPROTO;
        if (!streq(job_result, "done")) {
                if (streq(job_result, "canceled"))
                        return -ECANCELED;
                if (streq(job_result, "timeout"))
                        return -ETIMEDOUT;
                return -EPROTO;
        }

        return 0;
}

typedef struct RegisterParams {
        const char *id;
        const char *collection;
        const char *sandbox;
        sd_json_variant *permissions;
        sd_json_variant *entitlements;
} RegisterParams;

static void register_params_done(RegisterParams *params) {
        sd_json_variant_unref(params->permissions);
        sd_json_variant_unref(params->entitlements);
}

static int vl_method_instance_register(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "id",           SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,  offsetof(RegisterParams, id),           SD_JSON_MANDATORY },
                { "collection",   SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,  offsetof(RegisterParams, collection),   SD_JSON_NULLABLE  },
                { "sandbox",      SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,  offsetof(RegisterParams, sandbox),      SD_JSON_NULLABLE  },
                { "permissions",  SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant,       offsetof(RegisterParams, permissions),  SD_JSON_NULLABLE  },
                { "entitlements", SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant,       offsetof(RegisterParams, entitlements), SD_JSON_NULLABLE  },
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_(register_params_done) RegisterParams params = {};
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &params);
        if (r != 0)
                return r;

        if (!xdg_app_id_is_valid(params.id))
                return sd_varlink_error_invalid_parameter_name(link, "id");
        if (params.sandbox && isempty(params.sandbox))
                return sd_varlink_error_invalid_parameter_name(link, "sandbox");

        _cleanup_(pidref_done) PidRef peer = PIDREF_NULL;
        r = varlink_get_peer_pidref(link, &peer);
        if (r < 0)
                return log_debug_errno(r, "Failed to get peer pidref: %m");

        _cleanup_(app_instance_unrefp) AppInstance *instance = NULL;
        r = app_instance_from_pidref(manager, &peer, &instance);
        if (r < 0 && r != -ENOENT)
                return r;

        /* If the caller is already registered under a sandbox engine, that means this request is
         * coming from untrustworthy code and we should discard it. */
        if (instance && instance->sandbox)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, /* parameters= */ NULL);

        /* If the caller is not yet registered, or if it is registered under the wrong app ID (launcher guessed
         * wrong, or an existing app is launching a different app), then move the caller to an appropriate scope. */
        if (!instance || !streq(instance->app_id, params.id)) {
                _cleanup_free_ char *escaped_id = NULL;
                escaped_id = unit_name_escape(params.id);
                if (!escaped_id)
                        return log_oom_debug();

                _cleanup_free_ char *unit_name = NULL;
                (void) pidref_acquire_pidfd_id(&peer);
                uint64_t unique = peer.fd_id ?: (uint64_t) peer.pid;
                if (asprintf(&unit_name, "app-%s-%" PRIu64 ".scope", escaped_id, unique) < 0)
                        return log_oom_debug();

                log_info("Starting transient scope for PID " PID_FMT ": %s", peer.pid, unit_name);

                r = start_transient_scope(unit_name, &peer);
                if (r < 0)
                        return r;

                log_debug("Transient scope started for PID " PID_FMT ", looking up new app instance", peer.pid);

                _cleanup_(app_instance_unrefp) AppInstance *new_instance = NULL;
                r = app_instance_from_pidref(manager, &peer, &new_instance);
                if (r < 0)
                        return r;

                /* Make sure nothing funky happened! E.g. something might have been racing our StartTransient call */
                if (!new_instance || new_instance->sandbox || !streq(new_instance->app_id, params.id))
                        return log_debug_errno(SYNTHETIC_ERRNO(EPROTO),
                                               "Transient scope for PID " PID_FMT " in unexepected state, bailing!",
                                               peer.pid);

                free_and_replace_full(instance, new_instance, app_instance_unref);
        }

        log_debug("Applying registration to instance: %s", instance->unit);

        /* Apps may register themselves repeatedly: by the launcher, and/or the sandbox engine, and/or the
         * app itself. This approach maximizes the likelihood that all apps get registered, but it also means
         * that we have no way of knowing when an app is actually done registering itself. */
        if (instance->ever_queried)
                log_warning("App instance %s is amending its registration, but has already been queried.",
                            instance->unit);

        if (params.sandbox) {
                assert(!instance->sandbox);
                r = strdup_to(&instance->sandbox, params.sandbox);
                if (r < 0)
                        return r;
        }

        if (params.collection) {
                r = free_and_strdup(&instance->collection, empty_to_null(params.collection));
                if (r < 0)
                        return r;
        }

        if (params.permissions)
                json_variant_unref_and_replace(instance->permissions, params.permissions);

        if (params.entitlements)
                json_variant_unref_and_replace(instance->entitlements, params.entitlements);

        r = app_instance_commit(instance);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

typedef struct Target {
        PidRef pid;
        int conn_fd;
        char *cgroup;
} Target;

#define TARGET_NULL (Target) { .pid = PIDREF_NULL, .conn_fd = -1 }

#define TARGET_DISPATCH_FIELDS(offset) \
        { "targetPid",        _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref, (offset) + offsetof(Target, pid),     SD_JSON_NULLABLE|SD_JSON_STRICT }, \
        { "targetConnection", SD_JSON_VARIANT_INTEGER,       sd_json_dispatch_int, (offset) + offsetof(Target, conn_fd), SD_JSON_NULLABLE                }, \
        { "targetCgroup",     SD_JSON_VARIANT_STRING,        json_dispatch_path,   (offset) + offsetof(Target, cgroup),  SD_JSON_NULLABLE|SD_JSON_STRICT }

static void target_done(Target *target) {
        pidref_done(&target->pid);
        target->cgroup = mfree(target->cgroup);
}

static int target_resolve(
                Target *target,
                sd_varlink *link,
                Manager *manager,
                AppInstance **ret_peer,
                AppInstance **ret_target) {
        int r;

        assert(target);
        assert(link);
        assert(manager);
        assert(ret_peer);
        assert(ret_target);

        _cleanup_(pidref_done) PidRef peer_pidref = PIDREF_NULL;
        _cleanup_(app_instance_unrefp) AppInstance *peer_instance = NULL;
        r = varlink_get_peer_pidref(link, &peer_pidref);
        if (r < 0)
                return log_debug_errno(r, "Failed to get peer pidref: %m");
        log_debug("Looking up app instance for peer: PID " PID_FMT, peer_pidref.pid);
        r = app_instance_from_pidref(manager, &peer_pidref, &peer_instance);
        if (r < 0 && r != -ENOENT)
                return r;

        _cleanup_(pidref_done) PidRef conn_pidref = PIDREF_NULL;
        PidRef *target_pidref = NULL;
        bool have_pid = pidref_is_set(&target->pid);
        if (target->conn_fd < 0) {
                if (have_pid)
                        target_pidref = &target->pid;
        } else {
                log_debug("Fetching target pidref from provided connection FD");
                int conn_fd = sd_varlink_peek_fd(link, target->conn_fd);
                if (conn_fd < 0)
                        return log_debug_errno(conn_fd, "Failed to fetch FD from Varlink connection: %m");
                r = getpeerpidref(conn_fd, &conn_pidref);
                if (r < 0)
                        return log_debug_errno(r, "Failed to query pidref from provided connection FD: %m");

                if (have_pid && !pidref_equal(&conn_pidref, &target->pid))
                        return sd_varlink_error(link, "io.systemd.AppInstance.ConflictingTarget", /* parameters= */ NULL);

                target_pidref = &conn_pidref;
        }

        _cleanup_(app_instance_unrefp) AppInstance *target_instance = NULL;
        if (target_pidref) {
                if (!pidref_equal(&peer_pidref, target_pidref)) {
                        log_debug("Looking up app instance for target: PID " PID_FMT, target_pidref->pid);
                        r = app_instance_from_pidref(manager, target_pidref, &target_instance);
                        if (r < 0 && r != -ENOENT)
                                return r;
                } else {
                        log_debug("Peer specified itself as target");
                        target_instance = app_instance_ref(peer_instance);
                }

                if (target->cgroup && (!target_instance || !streq(target->cgroup, target_instance->cg_path)))
                        return sd_varlink_error(link, "io.systemd.AppInstance.ConflictingTarget", /* parameters= */ NULL);
        } else if (target->cgroup) {
                log_debug("Looking up app instance for target: cgroup %s", target->cgroup);
                r = app_instance_from_path(manager, target->cgroup, &target_instance);
                if (r < 0 && r != -ENOENT)
                        return r;
        } else {
                log_debug("No target specified, using peer as target");
                target_instance = app_instance_ref(peer_instance);
        }

        if (!target_instance)
                return sd_varlink_error(link, "io.systemd.AppInstance.NoSuchInstance", /* parameters= */ NULL);

        *ret_peer = TAKE_PTR(peer_instance);
        *ret_target = TAKE_PTR(target_instance);
        return 0;
}

typedef struct QueryParams {
        Target target;
} QueryParams;

static void query_params_done(QueryParams *params) {
        target_done(&params->target);
}

static int vl_method_instance_query(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                TARGET_DISPATCH_FIELDS(offsetof(QueryParams, target)),
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(link);

        _cleanup_(query_params_done) QueryParams p = {
                .target = TARGET_NULL,
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        _cleanup_(app_instance_unrefp) AppInstance *peer_instance = NULL, *target_instance = NULL;
        r = target_resolve(&p.target, link, manager, &peer_instance, &target_instance);
        if (r < 0)
                return r;

        if (peer_instance && peer_instance->sandbox && !app_instance_same_app(peer_instance, target_instance))
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, /* parameters= */ NULL);

        if (!target_instance->ever_queried) {
                target_instance->ever_queried = true;

                r = app_instance_commit(target_instance);
                if (r < 0)
                        return r;
        }

        return sd_varlink_replybo (
                        link,
                        SD_JSON_BUILD_PAIR_UNSIGNED("generation", target_instance->generation),
                        SD_JSON_BUILD_PAIR_STRING("cgroup", target_instance->cg_path),
                        SD_JSON_BUILD_PAIR_STRING("id", target_instance->app_id),
                        SD_JSON_BUILD_PAIR_STRING("collection", target_instance->collection ?: "none"),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("sandbox", target_instance->sandbox),
                        JSON_BUILD_PAIR_VARIANT_NON_EMPTY("permissions", target_instance->permissions),
                        JSON_BUILD_PAIR_VARIANT_NON_EMPTY("entitlements", target_instance->entitlements));
}

typedef struct SetPermissionsParams {
        Target target;
        uint64_t generation;
        sd_json_variant *permissions;
} SetPermissionsParams;

static void set_permissions_params_done(SetPermissionsParams *params) {
        target_done(&params->target);
        sd_json_variant_unref(params->permissions);
}

static int vl_method_instance_set_permissions(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                TARGET_DISPATCH_FIELDS(offsetof(SetPermissionsParams, target)),
                { "generation", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_uint64,  offsetof(SetPermissionsParams, generation),  SD_JSON_MANDATORY },
                { "permissions", SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant, offsetof(SetPermissionsParams, permissions), SD_JSON_MANDATORY },
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(link);

        _cleanup_(set_permissions_params_done) SetPermissionsParams p = {
                .target = TARGET_NULL,
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        _cleanup_(app_instance_unrefp) AppInstance *peer_instance = NULL, *target_instance = NULL;
        r = target_resolve(&p.target, link, manager, &peer_instance, &target_instance);
        if (r < 0)
                return r;

        if (peer_instance && peer_instance->sandbox)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, /* parameters= */ NULL);

        if (!target_instance->ever_queried || p.generation != target_instance->generation)
                return sd_varlink_error(link, "io.systemd.AppInstance.Stale", /* parameters= */ NULL);

        json_variant_unref_and_replace(target_instance->permissions, p.permissions);

        r = app_instance_commit(target_instance);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

int manager_instance_varlink_init(Manager *m) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        int r;

        assert(m);

        if (m->varlink_instance_server)
                return 0;

        r = varlink_server_new(&s, SD_VARLINK_SERVER_INHERIT_USERDATA|SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        (void) sd_varlink_server_set_description(s, "varlink-instance");

        r = sd_varlink_server_add_interface(s, &vl_interface_io_systemd_AppInstance);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = varlink_server_bind_fiber_many(
                        s,
                        "io.systemd.AppInstance.Register", vl_method_instance_register,
                        "io.systemd.AppInstance.Query", vl_method_instance_query,
                        "io.systemd.AppInstance.SetPermissions", vl_method_instance_set_permissions);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        _cleanup_free_ char *socket_path = NULL;
        r = xdg_user_runtime_dir("systemd/io.systemd.AppInstance", &socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine socket path: %m");

        r = sd_varlink_server_listen_address(s, socket_path, 0600 | SD_VARLINK_SERVER_MODE_MKDIR_0755);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to io.systemd.AppInstance varlink socket: %m");

        r = sd_varlink_server_attach_event(s, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach Varlink connection to event loop: %m");

        m->varlink_instance_server = TAKE_PTR(s);
        return 0;
}

void manager_instance_varlink_done(Manager *m) {
        assert(m);

        m->varlink_instance_server = sd_varlink_server_unref(m->varlink_instance_server);
}
