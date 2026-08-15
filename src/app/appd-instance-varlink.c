/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "appd-instance.h"
#include "appd-instance-varlink.h"
#include "appd-manager.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "path-lookup.h"
#include "pidref.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "unit-def.h"
#include "unit-name.h"
#include "varlink-util.h"
#include "varlink-io.systemd.AppInstance.h"

typedef struct RegisterRequest {
        Manager *manager;

        sd_varlink *register_link;
        sd_varlink *start_transient_link;
        PidRef peer;

        const char *id;
        const char *collection;
        const char *sandbox;

        sd_json_variant *permissions;
        sd_json_variant *entitlements;
} RegisterRequest;

static RegisterRequest* register_request_free(RegisterRequest *request) {
        if (!request)
                return NULL;

        sd_varlink_unref(request->register_link);
        sd_varlink_unref(request->start_transient_link);
        pidref_done(&request->peer);

        sd_json_variant_unref(request->permissions);
        sd_json_variant_unref(request->entitlements);

        return mfree(request);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(RegisterRequest*, register_request_free);

static int apply_request(RegisterRequest *request, AppInstance *instance) {
        int r;

        assert(request);
        assert(instance);

        assert(!instance->sandbox);
        assert(streq(request->id, instance->app_id));

        log_debug("Applying registration to instance: %s (cg_path: %s)", instance->app_id, instance->cg_path);

        if (request->sandbox) {
                assert(!isempty(request->sandbox));
                r = strdup_to(&instance->sandbox, request->sandbox);
                if (r < 0)
                        return sd_varlink_error_errno(request->register_link, r);
        }

        if (request->collection) {
                r = free_and_strdup(&instance->collection, empty_to_null(request->collection));
                if (r < 0)
                        return sd_varlink_error_errno(request->register_link, r);
        }

        if (request->permissions)
                json_variant_unref_and_replace(instance->permissions, request->permissions);

        if (request->entitlements) {
                assert(!instance->entitlements);
                json_variant_unref_and_replace(instance->entitlements, request->entitlements);
        }

        r = app_instance_commit(instance);
        if (r < 0)
                return sd_varlink_error_errno(request->register_link, r);

        sd_varlink_reply(request->register_link, NULL);
        return 0;
}

static int handle_start_transient_reply(
                sd_varlink *systemd_link,
                sd_json_variant *reply,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        _cleanup_(register_request_freep) RegisterRequest *request = ASSERT_PTR(userdata);
        int r;

        assert(reply);

        if (error_id)
                return sd_varlink_error(request->register_link, error_id, reply);

        /* Let's check if we're done, or if we should wait to be called again. */
        sd_json_variant *job = sd_json_variant_by_key(reply, "job");
        const char *job_state = sd_json_variant_string(sd_json_variant_by_key(job, "State"));
        assert(job_state); /* systemd always should be returning a job state! */
        if (!streq(job_state, "finished")) {
                TAKE_PTR(request); /* We'll get called back later! */
                return 0;
        }

        /* We're done! Did we succeed? */
        const char *job_result = sd_json_variant_string(sd_json_variant_by_key(job, "Result"));
        assert(job_result); /* finished jobs should always have results */
        if (!streq(job_result, "done")) {
                if (streq(job_result, "canceled"))
                        return sd_varlink_error_errno(request->register_link, -ECANCELED);
                if (streq(job_result, "timeout"))
                        return sd_varlink_error_errno(request->register_link, -ETIMEDOUT);
                return sd_varlink_error_errno(request->register_link, -EPROTO);
        }

        log_debug("Transient scope started for PID " PID_FMT ", looking up new app instance", request->peer.pid);

        _cleanup_(app_instance_unrefp) AppInstance *instance = NULL;
        r = app_instance_get(request->manager, &request->peer, &instance);
        if (r < 0)
                return sd_varlink_error_errno(request->register_link, r);

        return apply_request(request, instance);
}

static int start_transient_scope(RegisterRequest *_request) {
        _cleanup_(register_request_freep) RegisterRequest *request = ASSERT_PTR(_request);
        int r;

        _cleanup_free_ char *unit_name = NULL;
        (void) pidref_acquire_pidfd_id(&request->peer);
        uint64_t unique = request->peer.fd_id ?: (uint64_t) request->peer.pid;
        if (asprintf(&unit_name, "app-%s-%" PRIu64 ".scope", request->id, unique) < 0)
                return log_oom_debug();

        log_debug("Starting transient scope for PID " PID_FMT ": %s", request->peer.pid, unit_name);

        _cleanup_free_ char *systemd_address = NULL;
        r = xdg_user_runtime_dir("systemd/io.systemd.Manager", &systemd_address);
        if (r < 0)
                return log_debug_errno(r, "Failed to get io.systemd.Manager address: %m");

        _cleanup_(sd_varlink_unrefp) sd_varlink *systemd_link = NULL;
        r = sd_varlink_connect_address(&systemd_link, systemd_address);
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to io.systemd.Manager: %m");

        {
                _cleanup_free_ char *link_description = NULL;
                if (asprintf(&link_description, "varlink-start-transient-" PID_FMT, request->peer.pid) < 0)
                        return log_oom_debug();
                (void) sd_varlink_set_description(systemd_link, link_description);
        }

        r = sd_varlink_attach_event(systemd_link, request->manager->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_debug_errno(r, "Failed to attach io.systemd.Manager.StartTransient() to event loop: %m");

        r = sd_varlink_bind_reply(systemd_link, handle_start_transient_reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to bind io.systemd.Manager.StartTransient() reply callback: %m");

        r = sd_varlink_observebo(
                        systemd_link,
                        "io.systemd.Unit.StartTransient",
                        SD_JSON_BUILD_PAIR_OBJECT("context",
                                SD_JSON_BUILD_PAIR_STRING("ID", unit_name),
                                SD_JSON_BUILD_PAIR_OBJECT("Scope",
                                        SD_JSON_BUILD_PAIR_ARRAY("PIDs",
                                                JSON_BUILD_PIDREF(&request->peer)))),
                        SD_JSON_BUILD_PAIR_STRING("mode", "fail"),
                        SD_JSON_BUILD_PAIR_BOOLEAN("notifyJobChanges", true));
        if (r < 0)
                return log_debug_errno(r, "Failed to call io.systemd.Manager.StartTransient(): %m");

        sd_varlink_set_userdata(systemd_link, request);
        request->start_transient_link = TAKE_PTR(systemd_link);
        TAKE_PTR(request); /* Request gets free'd in handle_start_transient_reply */
        return 0;
}

static int vl_method_instance_register(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "id",           SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(RegisterRequest, id),           SD_JSON_MANDATORY },
                { "collection",   SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(RegisterRequest, collection),   0                 },
                { "sandbox",      SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(RegisterRequest, sandbox),      0                 },
                { "permissions",  SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant,      offsetof(RegisterRequest, permissions),  0                 },
                { "entitlements", SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant,      offsetof(RegisterRequest, entitlements), 0                 },
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        _cleanup_(register_request_freep) RegisterRequest *request = NULL;
        int r;

        assert(link);

        request = new(RegisterRequest, 1);
        if (!request)
                return -ENOMEM;

        *request = (RegisterRequest) {
                .manager = manager,
                .register_link = sd_varlink_ref(link),
                .peer = PIDREF_NULL,
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, request);
        if (r != 0)
                return r;

        if (request->sandbox && isempty(request->sandbox))
                return sd_varlink_error_invalid_parameter_name(link, "sandbox");

        r = varlink_get_peer_pidref(link, &request->peer);
        if (r < 0)
                return log_debug_errno(r, "Failed to get peer pidref: %m");

        _cleanup_(app_instance_unrefp) AppInstance *instance = NULL;
        r = app_instance_get(manager, &request->peer, &instance);
        if (r < 0 && r != -ENOENT)
                return r;

        if (instance) {
                /* If the app is already registered under a sandbox engine, that means this request is
                 * coming from untrustworthy code and we should discard it. */
                if (instance->sandbox)
                        return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

                /* Apps need to Register() with appd before they do anything that may lead to a Query().
                 * In practice, this means that apps should register early during their start-up, before
                 * they connect to the IPC services like DBus or Wayland. Once a Query() happens, we
                 * consider the registration "busy" and no longer allow changes. */
                if (instance->ever_queried)
                        return sd_varlink_error(link, "io.systemd.AppInstance.RegistrationBusy", NULL);

                /* If we're already registered under the correct app ID, there's no need to move ourselves
                 * to a different scope. */
                if (streq(instance->app_id, request->id))
                        return apply_request(request, instance);
        }

        return start_transient_scope(TAKE_PTR(request));
}

typedef struct Target {
        PidRef pid;
        int conn_fd_idx;
        char *cgroup;
} Target;

#define TARGET_NULL (Target) { .pid = PIDREF_NULL, .conn_fd_idx = -1 }

static int json_dispatch_target(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Target *target = ASSERT_PTR(userdata);
        if (streq(name, "targetPid"))
                return json_dispatch_pidref(name, variant, flags, &target->pid);
        else if (streq(name, "targetConnection"))
                return sd_json_dispatch_int(name, variant, flags, &target->conn_fd_idx);
        else if (streq(name, "targetCgroup"))
                return sd_json_dispatch_string(name, variant, flags, &target->cgroup);
        else
                return -EINVAL;
}

#define TARGET_DISPATCH_FIELDS(offset) \
        { "targetPid",        _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_target, offset, 0 }, \
        { "targetConnection", SD_JSON_VARIANT_INTEGER,       json_dispatch_target, offset, 0 }, \
        { "targetCgroup",     SD_JSON_VARIANT_STRING,        json_dispatch_target, offset, 0 }

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
        r = app_instance_get(manager, &peer_pidref, &peer_instance);
        if (r < 0 && r != -ENOENT)
                return r;

        _cleanup_(pidref_done) PidRef conn_pidref = PIDREF_NULL;
        PidRef *target_pidref = NULL;
        bool have_pid = pidref_is_set(&target->pid);
        if (target->conn_fd_idx < 0) {
                if (have_pid)
                        target_pidref = &target->pid;
        } else {
                log_debug("Fetching target pidref from provided connection FD");
                int conn_fd = sd_varlink_peek_fd(link, target->conn_fd_idx);
                if (r < 0)
                        return log_debug_errno(r, "Failed to fetch FD from Varlink connection: %m");
                r = getpeerpidref(conn_fd, &conn_pidref);
                if (r < 0)
                        return log_debug_errno(r, "Failed to query pidref from provided connection FD: %m");

                if (have_pid && !pidref_equal(&conn_pidref, &target->pid))
                        return sd_varlink_error(link, "io.systemd.AppInstance.ConflictingTarget", NULL);

                target_pidref = &conn_pidref;
        }

        _cleanup_(app_instance_unrefp) AppInstance *target_instance = NULL;
        if (target_pidref) {
                if (!pidref_equal(&peer_pidref, target_pidref)) {
                        log_debug("Looking up app instance for target: PID " PID_FMT, target_pidref->pid);
                        r = app_instance_get(manager, target_pidref, &target_instance);
                        if (r < 0 && r != -ENOENT)
                                return r;
                } else {
                        log_debug("Peer specified itself as target");
                        target_instance = app_instance_ref(peer_instance);
                }

                if (target->cgroup && !streq(target->cgroup, target_instance->cg_path))
                        return sd_varlink_error(link, "io.systemd.AppInstance.ConflictingTarget", NULL);
        } else if (target->cgroup) {
                log_debug("Looking up app instance for target: cgroup %s", target->cgroup);
                target_instance = app_instance_ref(hashmap_get(manager->instances, target->cgroup));
        } else {
                log_debug("No target specified, using peer as target");
                target_instance = app_instance_ref(peer_instance);
        }

        if (!target_instance)
                return sd_varlink_error(link, "io.systemd.AppInstance.NoSuchInstance", NULL);

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
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        target_instance->ever_queried = true;
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
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        if (p.generation != target_instance->generation)
                return sd_varlink_error(link, "io.systemd.AppInstance.Stale", NULL);

        json_variant_unref_and_replace(target_instance->permissions, p.permissions);
        r = app_instance_commit(target_instance);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
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

        r = sd_varlink_server_bind_method_many(
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
