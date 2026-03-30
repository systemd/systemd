/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "hashmap.h"
#include "log.h"
#include "path-util.h"
#include "qmp-client.h"
#include "string-util.h"
#include "strv.h"
#include "varlink-io.systemd.MachineInstance.h"
#include "varlink-io.systemd.QemuMachineInstance.h"
#include "varlink-io.systemd.VirtualMachineInstance.h"
#include "varlink-util.h"
#include "vmspawn-varlink.h"

DEFINE_PRIVATE_HASH_OPS_FULL(
                varlink_subscriber_hash_ops,
                void, trivial_hash_func, trivial_compare_func, sd_varlink_close_unref,
                char*, strv_free);

struct VmspawnVarlinkContext {
        sd_varlink_server *varlink_server;
        VmspawnQmpBridge *bridge;
        /* Key: sd_varlink* (ref'd), Value: strv filter (NULL = all events).
         * varlink_subscriber_hash_ops handles cleanup of both on removal. */
        Hashmap *subscribed;
};

/* Translate a QMP async completion into a varlink error reply */
static int qmp_error_to_varlink(sd_varlink *link, const char *error_desc, int error) {
        assert(link);

        if (ERRNO_IS_DISCONNECT(error))
                return sd_varlink_error(link, "io.systemd.MachineInstance.NotConnected", NULL);
        if (error == -EIO)
                log_warning("QMP command failed: %s", strna(error_desc));
        return sd_varlink_error_errno(link, error);
}

/* Shared async completion for simple QMP commands that return no data.
 * Errors are translated to varlink replies, not propagated through sd_event. */
static int on_qmp_simple_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        sd_varlink *link = ASSERT_PTR(userdata);

        assert(client);

        if (error == 0)
                (void) sd_varlink_reply(link, NULL);
        else
                (void) qmp_error_to_varlink(link, error_desc, error);

        sd_varlink_unref(link);
        return 0;
}

static int qmp_execute_varlink_async(
                VmspawnVarlinkContext *ctx,
                sd_varlink *link,
                const char *command,
                sd_json_variant *arguments,
                qmp_command_callback_t callback) {

        int r;

        sd_varlink_ref(link);

        r = qmp_client_invoke(ctx->bridge->qmp, command, QMP_CLIENT_ARGS(arguments), callback, link);
        if (r < 0)
                sd_varlink_unref(link);

        return r;
}

static int qmp_execute_simple_async(sd_varlink *link, VmspawnVarlinkContext *ctx, const char *qmp_command) {
        assert(link);
        assert(ctx);
        assert(qmp_command);

        return qmp_execute_varlink_async(ctx, link, qmp_command, /* arguments= */ NULL, on_qmp_simple_complete);
}

static int vl_method_terminate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, ASSERT_PTR(userdata), "quit");
}

static int vl_method_pause(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, ASSERT_PTR(userdata), "stop");
}

static int vl_method_resume(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, ASSERT_PTR(userdata), "cont");
}

static int vl_method_power_off(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, ASSERT_PTR(userdata), "system_powerdown");
}

static int vl_method_reboot(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return qmp_execute_simple_async(link, ASSERT_PTR(userdata), "system_reset");
}

/* Async completion for query-status: extract running/status from QMP result */
static int on_qmp_describe_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = ASSERT_PTR(userdata);

        assert(client);

        if (error != 0) {
                (void) qmp_error_to_varlink(link, error_desc, error);
                return 0;
        }

        sd_json_variant *running = sd_json_variant_by_key(result, "running");
        sd_json_variant *status = sd_json_variant_by_key(result, "status");

        (void) sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_BOOLEAN("running", running ? sd_json_variant_boolean(running) : false),
                        SD_JSON_BUILD_PAIR_STRING("status", status && sd_json_variant_is_string(status) ? sd_json_variant_string(status) : "unknown"));

        return 0;
}

static int vl_method_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);

        return qmp_execute_varlink_async(ctx, link, "query-status", /* arguments= */ NULL, on_qmp_describe_complete);
}

static int vl_method_subscribe_events(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **filter = NULL;
        int r;

        /* SD_VARLINK_REQUIRES_MORE in the IDL rejects non-streaming callers before we get here */

        r = sd_varlink_dispatch(link, parameters, (const sd_json_dispatch_field[]) {
                { "filter", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_strv, 0, SD_JSON_NULLABLE },
                {},
        }, &filter);
        if (r != 0)
                return r;

        sd_varlink_ref(link);

        r = hashmap_ensure_put(&ctx->subscribed, &varlink_subscriber_hash_ops, link, filter);
        if (r < 0) {
                sd_varlink_unref(link);
                return r;
        }

        TAKE_PTR(filter);

        r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_STRING("event", "READY"));
        if (r < 0) {
                strv_free(hashmap_remove(ctx->subscribed, link));
                sd_varlink_close_unref(link);
                return r;
        }

        return 0;
}

static int vl_method_acquire_qmp(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return sd_varlink_error_errno(link, -EOPNOTSUPP);
}

static void vl_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);

        assert(server);
        assert(link);

        /* Only subscribers hold an extra ref on the link (taken in vl_method_subscribe_events).
         * Non-subscriber connections (one-shot commands like Pause, Describe) must not be unref'd
         * here — their extra ref is consumed by the async completion callback. Only unref, never
         * close — the server handles close after this callback returns (matching resolved's
         * vl_on_notification_disconnect pattern).
         *
         * Use hashmap_remove2() so the returned key (non-NULL iff the entry was present)
         * disambiguates "no filter subscriber" (value=NULL) from "not a subscriber". */
        void *removed_key = NULL;
        strv_free(hashmap_remove2(ctx->subscribed, link, &removed_key));
        if (!removed_key)
                return;

        sd_varlink_unref(link);
}

static int on_job_dismiss_complete(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        if (error < 0)
                log_debug_errno(error, "job-dismiss failed: %s", strna(error_desc));

        return 0;
}

static int dispatch_pending_job(VmspawnQmpBridge *bridge, sd_json_variant *data) {
        const char *job_id, *status;
        int r;

        assert(bridge);

        if (!data)
                return 0;

        job_id = sd_json_variant_string(sd_json_variant_by_key(data, "id"));
        status = sd_json_variant_string(sd_json_variant_by_key(data, "status"));

        if (!job_id || !streq_ptr(status, "concluded"))
                return 0;

        _cleanup_free_ char *key = NULL;
        _cleanup_(pending_job_freep) PendingJob *job = hashmap_remove2(bridge->pending_jobs, job_id, (void**) &key);
        if (!job)
                return 0;

        log_debug("QMP job '%s' concluded, firing continuation", job_id);

        /* Dismiss the concluded job before running the continuation */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *dismiss_args = NULL;
        r = sd_json_buildo(&dismiss_args, SD_JSON_BUILD_PAIR_STRING("id", job_id));
        if (r < 0)
                return sd_event_exit(qmp_client_get_event(bridge->qmp), r);

        r = qmp_client_invoke(bridge->qmp, "job-dismiss", QMP_CLIENT_ARGS(dismiss_args),
                              on_job_dismiss_complete, /* userdata= */ NULL);
        if (r < 0)
                return sd_event_exit(qmp_client_get_event(bridge->qmp), r);

        if (!job->on_concluded)
                return 1;

        r = job->on_concluded(bridge->qmp, TAKE_PTR(job->userdata));
        if (r < 0) {
                log_error_errno(r, "Job continuation failed: %m");
                return sd_event_exit(qmp_client_get_event(bridge->qmp), r);
        }

        return 1;
}

static int on_qmp_event(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                void *userdata) {

        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *notification = NULL;
        sd_varlink *link;
        char **filter;
        int r;

        assert(client);
        assert(event);

        /* Dispatch job status changes to pending continuations (e.g. blockdev-create) */
        if (streq(event, "JOB_STATUS_CHANGE"))
                return dispatch_pending_job(ctx->bridge, data);

        if (hashmap_isempty(ctx->subscribed))
                return 0;

        r = sd_json_buildo(
                        &notification,
                        SD_JSON_BUILD_PAIR_STRING("event", event),
                        SD_JSON_BUILD_PAIR_CONDITION(!!data, "data", SD_JSON_BUILD_VARIANT(data)));
        if (r < 0) {
                log_warning_errno(r, "Failed to build event notification, ignoring: %m");
                return 0;
        }

        HASHMAP_FOREACH_KEY(filter, link, ctx->subscribed) {
                if (filter && !strv_contains(filter, event))
                        continue;

                r = sd_varlink_notify(link, notification);
                if (r < 0)
                        log_warning_errno(r, "Failed to notify event subscriber, ignoring: %m");
        }

        return 0;
}

/* Free all subscriber entries — varlink_subscriber_hash_ops handles
 * close + unref for each key and strv_free for each value. */
static void drain_event_subscribers(Hashmap **subscribed) {
        assert(subscribed);
        *subscribed = hashmap_free(*subscribed);
}

static void on_qmp_disconnect(QmpClient *client, void *userdata) {
        VmspawnVarlinkContext *ctx = ASSERT_PTR(userdata);

        assert(client);

        log_debug("Backend connection lost");

        /* Propagate connection loss by closing all subscriber connections */
        drain_event_subscribers(&ctx->subscribed);
}

int vmspawn_varlink_setup(
                VmspawnVarlinkContext **ret,
                VmspawnQmpBridge *bridge,
                const char *runtime_dir,
                char **ret_control_address) {

        _cleanup_(vmspawn_varlink_context_freep) VmspawnVarlinkContext *ctx = NULL;
        _cleanup_free_ char *listen_address = NULL;
        int r;

        assert(ret);
        assert(bridge);
        assert(runtime_dir);

        sd_event *event = qmp_client_get_event(bridge->qmp);
        assert(event);

        ctx = new0(VmspawnVarlinkContext, 1);
        if (!ctx)
                return log_oom();

        /* Create varlink server for VM control */
        r = varlink_server_new(&ctx->varlink_server,
                               SD_VARLINK_SERVER_INHERIT_USERDATA,
                               ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to create varlink server: %m");

        r = sd_varlink_server_add_interface_many(
                        ctx->varlink_server,
                        &vl_interface_io_systemd_MachineInstance,
                        &vl_interface_io_systemd_VirtualMachineInstance,
                        &vl_interface_io_systemd_QemuMachineInstance);
        if (r < 0)
                return log_error_errno(r, "Failed to add varlink interfaces: %m");

        r = sd_varlink_server_bind_method_many(
                        ctx->varlink_server,
                        "io.systemd.MachineInstance.Terminate",         vl_method_terminate,
                        "io.systemd.MachineInstance.PowerOff",          vl_method_power_off,
                        "io.systemd.MachineInstance.Pause",             vl_method_pause,
                        "io.systemd.MachineInstance.Resume",            vl_method_resume,
                        "io.systemd.MachineInstance.Reboot",            vl_method_reboot,
                        "io.systemd.MachineInstance.Describe",          vl_method_describe,
                        "io.systemd.MachineInstance.SubscribeEvents",   vl_method_subscribe_events,
                        "io.systemd.QemuMachineInstance.AcquireQMP",    vl_method_acquire_qmp);
        if (r < 0)
                return log_error_errno(r, "Failed to bind varlink methods: %m");

        r = sd_varlink_server_bind_disconnect(ctx->varlink_server, vl_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to bind disconnect handler: %m");

        listen_address = path_join(runtime_dir, "control");
        if (!listen_address)
                return log_oom();

        r = sd_varlink_server_listen_address(ctx->varlink_server, listen_address, 0600);
        if (r < 0)
                return log_error_errno(r, "Failed to listen on %s: %m", listen_address);

        r = sd_varlink_server_attach_event(ctx->varlink_server, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink server to event loop: %m");

        ctx->bridge = bridge;
        qmp_client_bind_event(ctx->bridge->qmp, on_qmp_event, ctx);
        qmp_client_bind_disconnect(ctx->bridge->qmp, on_qmp_disconnect, ctx);

        log_debug("Varlink control server listening on %s", listen_address);

        if (ret_control_address)
                *ret_control_address = TAKE_PTR(listen_address);

        *ret = TAKE_PTR(ctx);
        return 0;
}

VmspawnVarlinkContext* vmspawn_varlink_context_free(VmspawnVarlinkContext *ctx) {
        if (!ctx)
                return NULL;

        sd_varlink_server_unref(ctx->varlink_server);
        vmspawn_qmp_bridge_free(ctx->bridge);

        drain_event_subscribers(&ctx->subscribed);

        return mfree(ctx);
}
